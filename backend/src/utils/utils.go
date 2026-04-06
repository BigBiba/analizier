package utils

import (
	pkt "analizier/backend/src/packet"
	"encoding/csv"
	"fmt"
	"os"
	"strconv"
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
