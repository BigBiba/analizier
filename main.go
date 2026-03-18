package main

import (
	"analizier/src/parser"
	"fmt"
	"strings"
)

func printNPackets(packets []parser.PacketInfo, n int) {
	for i := 0; i < n; i++ {
		printPacketInfo(packets[i])
	}
}

func printPacketInfo(info parser.PacketInfo) {
	const fieldWidth = 20

	formatField := func(name string, value interface{}) {
		fmt.Printf("%-*s %v\n", fieldWidth, name+":", value)
	}

	fmt.Printf("=== Пакет #%d ===\n", info.PacketNumber)

	formatField("Интерфейс", info.Interface)
	formatField("Время", info.Timestamp.Format("2006-01-02 15:04:05.000000"))
	formatField("Объем трафика", fmt.Sprintf("%d байт", info.TrafficVolume))
	formatField("Источник", info.SrcIP)
	formatField("Назначение", info.DstIP)
	formatField("Версия IP", info.IPVersion)

	if info.SrcPort != "" || info.DstPort != "" {
		formatField("Порт источника", ifEmpty(info.SrcPort, "N/A"))
		formatField("Порт назначения", ifEmpty(info.DstPort, "N/A"))
	}

	formatField("Длина пакета", fmt.Sprintf("%d байт", info.Length))
	formatField("Статус (Info)", ifEmpty(info.Info, "—"))

	fmt.Println(strings.Repeat("=", 50))
	fmt.Println()
}

func ifEmpty(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

func main() {
	parser := parser.NewParser()
	filename := "files/1.pcap"
	packets := parser.Parse(filename)
	printNPackets(packets, 5)
}
