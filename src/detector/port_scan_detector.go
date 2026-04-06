package detector

import (
	"analizier/src/packet"
	"time"
)


type PortScanDetector struct {
	MinPacketsThreshold int
	MaxDuration time.Duration
	RSTRatioThreshold float64
}

func NewPortScanDetector() *PortScanDetector {
	return &PortScanDetector{
		MinPacketsThreshold: 3,
		MaxDuration:         100 * time.Millisecond,
		RSTRatioThreshold:   0.3,
	}
}

func (d *PortScanDetector) Name() string {
	return "Port Scan Detector"
}

func (d *PortScanDetector) Analyze(stats packet.FlowStats) DetectionResult {
	if stats.CntPackets == 0 {
		return DetectionResult{IsAnomaly: false, Confidence: 0, Type: AnomalyNone}
	}

	score := 0.0

	if stats.CntSYN > 0 && stats.CntACK == 0 {
		score += 0.50
	}
	if stats.CntPackets <= d.MinPacketsThreshold {
		score += 0.25
	}

	rstRatio := float64(stats.CntRST) / float64(stats.CntPackets)
	if rstRatio >= d.RSTRatioThreshold {
		score += 0.15
	}

	if stats.Duration <= d.MaxDuration && stats.CntSYN > 0 {
		score += 0.10
	}

	if score > 1.0 {
		score = 1.0
	}

	return DetectionResult{
		IsAnomaly:  score >= 0.5,
		Confidence: score,
		Type:       AnomalyScanning,
	}
}
