package main

import (
	"fmt"
	"time"

	"analizier/src/detector"
	"analizier/src/packet"
)

func main() {
	p2mp := detector.NewP2MPDetector()
	portScan := detector.NewPortScanDetector()
	flowSwitching := detector.NewFlowSwitchingDetector()

	// 1. Synthetic Flow: Port Scan (Many SYNs, few Packets, small Duration)
	portScanFlow := &packet.FlowInfo{
		FlowID: "192.168.1.1:1234-192.168.1.2:80",
		Packets: []packet.PacketInfo{
			{SrcIP: "192.168.1.1", DstIP: "192.168.1.2", SrcPort: "1234", DstPort: "80", Flags: []string{"SYN"}},
			{SrcIP: "192.168.1.1", DstIP: "192.168.1.2", SrcPort: "1234", DstPort: "81", Flags: []string{"SYN"}},
		},
		Stats: packet.FlowStats{
			CntPackets: 2,
			CntSYN:     2,
			CntACK:     0,
			Duration:   50 * time.Millisecond,
		},
	}

	// 2. Synthetic Flow: Flow Switching (Lots of short flows from same IP)
	fmt.Println("=== Testing Detectors ===")
	
	resScan := portScan.Analyze(portScanFlow.Stats)
	fmt.Printf("[Port Scan Detector] - Anomaly: %v, Confidence: %.2f\n", resScan.IsAnomaly, resScan.Confidence)

	// Feed many short flows from 10.0.0.1 to trigger Flow Switching
	var resSwitch detector.DetectionResult
	for i := 0; i < 60; i++ {
		fakeFlow := &packet.FlowInfo{
			FlowID: fmt.Sprintf("10.0.0.1:%d-10.0.0.2:80", 1000+i),
			Packets: []packet.PacketInfo{
				{SrcIP: "10.0.0.1", DstIP: "10.0.0.2"},
			},
			Stats: packet.FlowStats{CntPackets: 1},
		}
		resSwitch = flowSwitching.AnalyzeFlow(fakeFlow)
	}
	fmt.Printf("[Flow Switching Detector] - Anomaly: %v, Confidence: %.2f\n", resSwitch.IsAnomaly, resSwitch.Confidence)

	// 3. Synthetic Flow: P2MP (One source sending to many destinations)
	var resP2MP detector.DetectionResult
	p2mpFlow := &packet.FlowInfo{FlowID: "p2mp-flow"}
	for i := 0; i < 10; i++ {
		p2mpFlow.Packets = append(p2mpFlow.Packets, packet.PacketInfo{
			SrcIP: "172.16.0.1",
			DstIP: fmt.Sprintf("172.16.0.%d", 100+i),
		})
	}
	resP2MP = p2mp.AnalyzeFlow(p2mpFlow)
	fmt.Printf("[P2MP Detector] - Anomaly: %v, Confidence: %.2f\n", resP2MP.IsAnomaly, resP2MP.Confidence)
}
