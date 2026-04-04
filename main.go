package main

import (
	pkt "analizier/backend/src/packet"
	"fmt"
)

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

func main() {
	fmt.Println("Hello World")
}
