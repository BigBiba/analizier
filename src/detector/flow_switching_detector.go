package detector

import (
	"analizier/src/packet"
	"math"
	"sync"
)

type FlowSwitchingDetector struct {
	mu           sync.Mutex
	srcFlowCount map[string]int

	SwitchThreshold  int
	MaxPacketsInFlow int
}

func NewFlowSwitchingDetector() *FlowSwitchingDetector {
	return &FlowSwitchingDetector{
		srcFlowCount:     make(map[string]int),
		SwitchThreshold:  50, // How many distinct short-lived flows trigger anomaly
		MaxPacketsInFlow: 10, // Max packets to consider it a short-lived hopping flow
	}
}

func (d *FlowSwitchingDetector) Name() string {
	return "Flow Switching Detector"
}

func (d *FlowSwitchingDetector) AnalyzeFlow(flow *packet.FlowInfo) DetectionResult {
	if len(flow.Packets) == 0 {
		return DetectionResult{IsAnomaly: false, Confidence: 0, Type: AnomalyNone}
	}

	// We consider flow hopping if flows are intentionally short-lived
	if flow.Stats.CntPackets > d.MaxPacketsInFlow {
		return DetectionResult{IsAnomaly: false, Confidence: 0, Type: AnomalyNone}
	}

	firstPkt := flow.Packets[0]
	// Normally we want to extract the source. A flow might represent both directions,
	// but let's take the first packet's Source as the initiator.
	initiatorIP := firstPkt.SrcIP
	if initiatorIP == "" {
		return DetectionResult{IsAnomaly: false, Confidence: 0, Type: AnomalyNone}
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	d.srcFlowCount[initiatorIP]++
	count := d.srcFlowCount[initiatorIP]

	if count < d.SwitchThreshold {
		return DetectionResult{IsAnomaly: false, Confidence: 0, Type: AnomalyNone}
	}

	// Cap confidence at 1.0. For 2x the threshold, confidence is 1.0.
	confidence := math.Min(1.0, float64(count)/float64(d.SwitchThreshold*2))

	return DetectionResult{
		IsAnomaly:  true,
		Confidence: confidence,
		Type:       AnomalyFlowSwitching,
	}
}

func (d *FlowSwitchingDetector) Reset() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.srcFlowCount = make(map[string]int)
}
