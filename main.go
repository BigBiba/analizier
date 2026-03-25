package main

import (
	pkt "analizier/src/packet"
	"analizier/src/parser"
	"encoding/csv"
	"fmt"
	"os"
	"strconv"
	"time"
)

func printNPackets(packets []pkt.PacketInfo, n int) {
	for i := 0; i < n; i++ {
		pkt.PrintPacketInfo(packets[i])
	}
}

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

	// 2. Итерируемся по данным
	for id, info := range flows {
		s := info.Stats

		record := []string{
			id,                                        // FlowID
			strconv.Itoa(s.CntPackets),                // Количество пакетов
			strconv.Itoa(s.FlowLength),                // Общий объем (FlowLength)
			fmt.Sprintf("%.2f", s.AvgPacketSize),      // Средний размер
			fmt.Sprintf("%.2f", s.StdDevPacketSize),   // Отклонение
			fmt.Sprintf("%.2f", s.BPS),                // BPS
			fmt.Sprintf("%d", s.IAT.Milliseconds()),   // IAT в миллисекундах
			fmt.Sprintf("%.4f", s.Duration.Seconds()), // Длительность в секундах
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

func main() {
	parser := parser.NewParser()
	filename := "files/1.pcap"
	packets := parser.Parse(filename)
	windows := pkt.SplitIntoWindows(packets, 10*time.Second)
	err := ExportWindowsToCSV("files/1_windows.csv", windows)
	if err != nil {
		fmt.Println(err)
	}
	//flows := DivideByFlow(packets)
	//for _, v := range flows {
	//	pkt.AnalyzeFlow(v)
	//}
	//err := ExportFlowsToCSV("files/26_flows.csv", flows)
	//if err != nil {
	//	fmt.Println(err)
	//}
}
