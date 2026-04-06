package parser

import (
	"fmt"
	"log"
	"net"

	pkt "analizier/backend/src/packet"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
)

func getInterfaceName(index int) string {
	iface, err := net.InterfaceByIndex(index)
	if err != nil {
		return fmt.Sprintf("unknown (index: %d)", index)
	}
	return iface.Name
}

type Parser struct {
}

func NewParser() *Parser {
	return &Parser{}
}

func (p *Parser) getInfo(packet gopacket.Packet) []string {
	transLayer := packet.TransportLayer()
	var flags []string
	if tcpLayer, ok := transLayer.(*layers.TCP); ok {
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
	}
	return flags
}

func (p *Parser) Parse(filename string) []pkt.PacketInfo {
	handle, err := pcap.OpenOffline(filename)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	linkType := handle.LinkType()
	packetSource := gopacket.NewPacketSource(handle, linkType)
	packetNum := 0

	result := make([]pkt.PacketInfo, 0)

	for packet := range packetSource.Packets() {
		packetNum++
		info := pkt.PacketInfo{
			PacketNumber:  packetNum,
			Interface:     getInterfaceName(packet.Metadata().InterfaceIndex),
			Timestamp:     packet.Metadata().Timestamp,
			Length:        int(packet.Metadata().Length),
			TrafficVolume: int(packet.Metadata().CaptureInfo.Length),
		}
		if netLayer := packet.NetworkLayer(); netLayer != nil {
			flow := netLayer.NetworkFlow()
			info.FlowID = flow
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
			info.FlowID = flow
			src, dst := flow.Endpoints()
			info.SrcPort = src.String()
			info.DstPort = dst.String()
		}
		info.Flags = p.getInfo(packet)
		result = append(result, info)
	}

	return result
}
