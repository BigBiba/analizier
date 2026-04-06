package detector

import (
	"analizier/src/packet"
	"math"
	"sync"
)


type P2MPDetector struct {
	mu        sync.Mutex
	srcToDsts map[string]map[string]struct{} 

	Threshold int
}

func NewP2MPDetector() *P2MPDetector {
	return &P2MPDetector{
		srcToDsts: make(map[string]map[string]struct{}),
		Threshold: 5,
	}
}

func (d *P2MPDetector) Name() string {
	return "P2MP Detector"
}

func (d *P2MPDetector) AnalyzeFlow(flow *packet.FlowInfo) DetectionResult {
	localSrcDsts := make(map[string]map[string]struct{})
	for _, pkt := range flow.Packets {
		if pkt.SrcIP == "" || pkt.DstIP == "" {
			continue
		}
		if _, ok := localSrcDsts[pkt.SrcIP]; !ok {
			localSrcDsts[pkt.SrcIP] = make(map[string]struct{})
		}
		localSrcDsts[pkt.SrcIP][pkt.DstIP] = struct{}{}
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	for src, dsts := range localSrcDsts {
		if _, ok := d.srcToDsts[src]; !ok {
			d.srcToDsts[src] = make(map[string]struct{})
		}
		for dst := range dsts {
			d.srcToDsts[src][dst] = struct{}{}
		}
	}

	maxDsts := 0
	for src := range localSrcDsts {
		if cnt := len(d.srcToDsts[src]); cnt > maxDsts {
			maxDsts = cnt
		}
	}

	if maxDsts < d.Threshold {
		return DetectionResult{IsAnomaly: false, Confidence: 0, Type: AnomalyNone}
	}

	confidence := math.Min(1.0, float64(maxDsts)/float64(d.Threshold*2))

	return DetectionResult{
		IsAnomaly:  true,
		Confidence: confidence,
		Type:       AnomalyP2MP,
	}
}

func (d *P2MPDetector) Reset() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.srcToDsts = make(map[string]map[string]struct{})
}
