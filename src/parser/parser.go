package parser

import (
	"fmt"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
	"log"
	"net"
	"strings"
	"time"
)

type Parser struct {
}

type PacketInfo struct {
	PacketNumber  int       // № пакета
	Interface     string    // Интерфейс
	Timestamp     time.Time // Текущее время и дата пакета
	TrafficVolume int       // Объем трафика
	SrcIP         string    // Источник (IP адрес)
	DstIP         string    // Назначение (IP адрес)
	IPVersion     string    // Internet Протокол version
	SrcPort       string    // Порт источника
	DstPort       string    // Порт назначения
	Length        int       // Длина
	Info          string    // Info
}

func getInterfaceName(index int) string {
	iface, err := net.InterfaceByIndex(index)
	if err != nil {
		return fmt.Sprintf("unknown (index: %d)", index)
	}
	return iface.Name
}

func NewParser() *Parser {
	return &Parser{}
}

func (p *Parser) getInfo(packet gopacket.Packet) string {
	transLayer := packet.TransportLayer()
	if tcpLayer, ok := transLayer.(*layers.TCP); ok {
		var flags []string
		if tcpLayer.SYN {
			flags = append(flags, "SYN")
		}
		if tcpLayer.ACK {
			flags = append(flags, "ACK")
		}
		if tcpLayer.FIN {
			flags = append(flags, "FIN")
		}
		if tcpLayer.RST {
			flags = append(flags, "RST")
		}
		if tcpLayer.PSH {
			flags = append(flags, "PSH")
		}
		if tcpLayer.URG {
			flags = append(flags, "URG")
		}

		if len(flags) > 0 {
			return strings.Join(flags, ", ")
		} else {
			return "No flags"
		}
	}

	if _, ok := transLayer.(*layers.UDP); ok {
		return "UDP datagram"
	}
	return "No info"
}

func (p *Parser) Parse(filename string) []PacketInfo {
	handle, err := pcap.OpenOffline(filename)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	linkType := handle.LinkType()
	packetSource := gopacket.NewPacketSource(handle, linkType)
	packetNum := 0

	result := make([]PacketInfo, 0)

	for packet := range packetSource.Packets() {
		packetNum++

		info := PacketInfo{
			PacketNumber:  packetNum,
			Interface:     getInterfaceName(packet.Metadata().InterfaceIndex),
			Timestamp:     packet.Metadata().Timestamp,
			Length:        int(packet.Metadata().Length),
			TrafficVolume: int(packet.Metadata().CaptureInfo.Length),
		}
		if netLayer := packet.NetworkLayer(); netLayer != nil {
			flow := netLayer.NetworkFlow()
			src, dst := flow.Endpoints()
			info.SrcIP = src.String()
			info.DstIP = dst.String()

			netLayerType := netLayer.LayerType()
			if netLayerType == layers.LayerTypeIPv4 {
				info.IPVersion = "IPv4"
			} else if netLayerType == layers.LayerTypeIPv6 {
				info.IPVersion = "IPv6"
			}
		}
		if transLayer := packet.TransportLayer(); transLayer != nil {
			flow := transLayer.TransportFlow()
			src, dst := flow.Endpoints()
			info.SrcPort = src.String()
			info.DstPort = dst.String()
		}
		info.Info = p.getInfo(packet)
		result = append(result, info)
	}

	return result
}
