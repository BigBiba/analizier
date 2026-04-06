// detector/worm_detector.go
package detector

import (
	"analizier/backend/src/packet"
	"net"
	"strconv"
)

type WormDetector struct {
	MinPackets    int
	MinBPS        float64
	SuspiciousDst map[int]string
	InternalNet   *net.IPNet
}

func (d *WormDetector) Name() string {
	return "WormDetector"
}

func NewWormDetector(minPackets int, minBPS float64, internalNet *net.IPNet) *WormDetector {
	// Оставляем только порты, реально связанные с червями (445 – SMB, 139 – NetBIOS, 1433 – MSSQL)
	// 6881 временно убираем, т.к. в чистом дампе много легитимного BitTorrent
	suspicious := map[int]string{
		445:  "SMB",
		139:  "NetBIOS",
		1433: "MSSQL",
	}
	return &WormDetector{
		MinPackets:    minPackets,
		MinBPS:        minBPS,
		SuspiciousDst: suspicious,
		InternalNet:   internalNet,
	}
}

func (d *WormDetector) Analyze(stats packet.FlowStats) DetectionResult {
	if stats.DstPort == "" {
		return DetectionResult{IsAnomaly: false}
	}
	port, err := strconv.Atoi(stats.DstPort)
	if err != nil {
		return DetectionResult{IsAnomaly: false}
	}
	if _, ok := d.SuspiciousDst[port]; !ok {
		return DetectionResult{IsAnomaly: false}
	}
	if stats.CntPackets < d.MinPackets || stats.BPS < d.MinBPS {
		return DetectionResult{IsAnomaly: false}
	}
	if d.InternalNet != nil {
		dstIP := net.ParseIP(stats.DstIP)
		if dstIP != nil && d.InternalNet.Contains(dstIP) {
			return DetectionResult{IsAnomaly: false}
		}
	}
	return DetectionResult{
		IsAnomaly:  true,
		Confidence: 0.7,
		Type:       AnomalyWorm,
	}
}
