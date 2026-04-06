package main

import (
	"analizier/src/detector"
	pkt "analizier/src/packet"
	"analizier/src/parser"
	"encoding/csv"
	"fmt"
	"net"
	"os"
	"strconv"
	"time"
)

// ------------------------------------------------------------
// Вспомогательные функции
// ------------------------------------------------------------

func ExportFlowsToCSV(filename string, flows map[string]*pkt.FlowInfo) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("could not create file: %v", err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	header := []string{
		"FlowID", "Packets", "TotalBytes", "AvgSize", "StdDevSize",
		"BPS", "IAT_ms", "Duration_s", "SYN", "ACK", "FIN", "PSH", "RST", "URG",
	}
	if err := writer.Write(header); err != nil {
		return err
	}

	for id, info := range flows {
		s := info.Stats
		record := []string{
			id,
			strconv.Itoa(s.CntPackets),
			strconv.Itoa(s.FlowLength),
			fmt.Sprintf("%.2f", s.AvgPacketSize),
			fmt.Sprintf("%.2f", s.StdDevPacketSize),
			fmt.Sprintf("%.2f", s.BPS),
			fmt.Sprintf("%d", s.IAT.Milliseconds()),
			fmt.Sprintf("%.4f", s.Duration.Seconds()),
			strconv.Itoa(s.CntSYN),
			strconv.Itoa(s.CntACK),
			strconv.Itoa(s.CntFIN),
			strconv.Itoa(s.CntPSH),
			strconv.Itoa(s.CntRST),
			strconv.Itoa(s.CntURG),
		}
		if err := writer.Write(record); err != nil {
			return err
		}
	}
	return nil
}

func DivideByFlow(packets []pkt.PacketInfo) map[string]*pkt.FlowInfo {
	flows := make(map[string]*pkt.FlowInfo)
	for _, packet := range packets {
		flowID := pkt.GetBiFlowID(packet)
		if flows[flowID] == nil {
			flows[flowID] = &pkt.FlowInfo{}
		}
		curFlow := flows[flowID]
		curFlow.FlowID = flowID
		curFlow.Packets = append(curFlow.Packets, packet)
	}
	return flows
}

func ExportWindowsToCSV(filename string, windows []pkt.TimeWindow) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("could not create file: %v", err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	header := []string{
		"StartTime", "EndTime",
		"TotalPackets", "TotalBytes",
		"PPS", "BPS",
		"UniqueSrcIPs", "UniqueDstIPs",
		"UniqueSrcPorts", "UniqueDstPorts",
		"ActiveFlows",
		"CntSYN", "CntACK", "CntFIN", "CntRST", "CntPSH", "CntURG",
	}
	if err := writer.Write(header); err != nil {
		return fmt.Errorf("error writing header: %v", err)
	}

	for _, w := range windows {
		s := w.Stats
		record := []string{
			w.StartTime.Format("2006-01-02 15:04:05.000"),
			w.EndTime.Format("15:04:05.000"),
			strconv.Itoa(s.TotalPackets),
			strconv.Itoa(s.TotalBytes),
			fmt.Sprintf("%.2f", s.PPS),
			fmt.Sprintf("%.2f", s.BPS),
			strconv.Itoa(s.UniqueSrcIPs),
			strconv.Itoa(s.UniqueDstIPs),
			strconv.Itoa(s.UniqueSrcPorts),
			strconv.Itoa(s.UniqueDstPorts),
			strconv.Itoa(s.ActiveFlows),
			strconv.Itoa(s.CntSYN),
			strconv.Itoa(s.CntACK),
			strconv.Itoa(s.CntFIN),
			strconv.Itoa(s.CntRST),
			strconv.Itoa(s.CntPSH),
			strconv.Itoa(s.CntURG),
		}
		if err := writer.Write(record); err != nil {
			return fmt.Errorf("error writing record: %v", err)
		}
	}
	return nil
}

// ------------------------------------------------------------
// Основная функция
// ------------------------------------------------------------
func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run main.go <pcap_file>")
		return
	}
	filename := os.Args[1]

	p := parser.NewParser()
	packets := p.Parse(filename)

	windows := pkt.SplitIntoWindows(packets, 10*time.Second)

	flows := DivideByFlow(packets)
	for _, flow := range flows {
		pkt.AnalyzeFlow(flow)
	}

	// ----- DDoS детекция -----
	ddosDet := &detector.DDoSDetector{}
	anomalousWindows := ddosDet.AnalyzeWindows(windows)

	dosFlowIDs := make(map[string]bool)
	for _, win := range anomalousWindows {
		for flowID, flow := range flows {
			if len(flow.Packets) == 0 {
				continue
			}
			firstPkt := flow.Packets[0].Timestamp
			if (firstPkt.After(win.StartTime) || firstPkt.Equal(win.StartTime)) &&
				(firstPkt.Before(win.EndTime) || firstPkt.Equal(win.EndTime)) {
				dosFlowIDs[flowID] = true
			}
		}
	}
	dosCount := len(dosFlowIDs)

	fmt.Printf("Anomalous windows: %d\n", len(anomalousWindows))
	for _, win := range anomalousWindows {
		s := win.Stats
		ratio := float64(s.CntRST) / float64(s.CntSYN+1)
		fmt.Printf("  %s – %s  BPS=%.0f  PPS=%.0f  SYN=%d  RST=%d  RST/SYN=%.2f  UniqueDstPorts=%d\n",
			win.StartTime.Format("15:04:05"), win.EndTime.Format("15:04:05"),
			s.BPS, s.PPS, s.CntSYN, s.CntRST, ratio, s.UniqueDstPorts)
	}
	fmt.Printf("Total DoS flows (started in anomalous windows): %d\n", dosCount)

	// ----- Детекция червей (смягчённые пороги + отладка) -----
	// Список подозрительных портов (включаем 25 для поиска)
	suspiciousPorts := []int{445, 139, 1433, 6881, 25}
	_, internalNet, _ := net.ParseCIDR("59.166.0.0/16")
	wormDet := detector.NewWormDetector(200, 100_000, internalNet)

	wormCount := 0
	fmt.Println("\n--- Debug: flows on suspicious ports (all, not only anomalies) ---")
	for _, flow := range flows {
		dstPort, _ := strconv.Atoi(flow.Stats.DstPort)
		isSuspicious := false
		for _, p := range suspiciousPorts {
			if dstPort == p {
				isSuspicious = true
				break
			}
		}
		if isSuspicious {
			//fmt.Printf("Suspicious flow: %s  dstPort=%d  packets=%d  BPS=%.0f  duration=%.2fs\n",
			//flow.FlowID, dstPort, flow.Stats.CntPackets, flow.Stats.BPS, flow.Stats.Duration.Seconds())
		}

		res := wormDet.Analyze(flow.Stats)
		if res.IsAnomaly {
			wormCount++
			// выведем и те, что признаны аномальными
			//fmt.Printf("*** WORM DETECTED: %s  dstPort=%d  packets=%d  BPS=%.0f\n",
			//flow.FlowID, dstPort, flow.Stats.CntPackets, flow.Stats.BPS)
		}
	}
	fmt.Printf("Total Worm flows (by detector): %d\n", wormCount)

	// ----- Детектор перегрузки (адаптивный) -----
	overloadDet := detector.NewAdaptiveOverloadDetector(10, 2.7) // 10 окон, 3 сигмы
	overloadWindows := overloadDet.AnalyzeWindows(windows)

	fmt.Printf("Overload windows: %d\n", len(overloadWindows))
	for _, w := range overloadWindows {
		fmt.Printf("  %s – %s  BPS=%.0f  PPS=%.0f\n",
			w.StartTime.Format("15:04:05"), w.EndTime.Format("15:04:05"),
			w.Stats.BPS, w.Stats.PPS)
	}

	// ----- Детектор вирусной активности -----
	// Белый список IP из вашего дампа (легитимные серверы)
	whitelist := []string{
		//"149.171.126.0", "149.171.126.1", "149.171.126.2", "149.171.126.3",
		//"149.171.126.4", "149.171.126.5", "149.171.126.6", "149.171.126.7",
		//"149.171.126.8", "149.171.126.9", "149.171.126.10", "149.171.126.11",
		//"149.171.126.12", "149.171.126.13", "149.171.126.14", "149.171.126.15",
		//"149.171.126.16", "149.171.126.17", "149.171.126.18", "149.171.126.19",
		//"175.45.176.0", "175.45.176.1", "175.45.176.2", "175.45.176.3",
	}
	virusDet := detector.NewVirusDetector(whitelist)

	virusCount := 0
	for _, flow := range flows {
		res := virusDet.Analyze(flow.Stats)
		if res.IsAnomaly {
			virusCount++
			fmt.Printf("*** VIRUS ACTIVITY: %s  dstIP=%s  dstPort=%s  packets=%d  duration=%.2fs BPS=%.0f\n",
				flow.FlowID, flow.Stats.DstIP, flow.Stats.DstPort, flow.Stats.CntPackets, flow.Stats.Duration.Seconds(), flow.Stats.BPS)
		}
	}
	fmt.Printf("Total Virus flows: %d\n", virusCount)
}
