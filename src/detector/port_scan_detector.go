package detector

import (
	"analizier/src/packet"
	"time"
)

// PortScanDetector обнаруживает сканирование портов по признакам отдельного потока.
// Работает как stateless детектор: каждый поток анализируется независимо.
//
// Признаки сканирования портов:
//   - SYN без ACK (SYN-scan): атакующий отправляет SYN, но не завершает handshake
//   - Малое число пакетов (1–3): сканер быстро переходит к следующему порту
//   - Высокая доля RST: целевой хост сбрасывает соединения на закрытых портах
//   - Очень короткая длительность потока: зонды живут доли секунды
type PortScanDetector struct {
	// MinPacketsThreshold — пороговое число пакетов, ниже которого поток считается "зондом"
	MinPacketsThreshold int
	// MaxDuration — максимальная длительность, при которой поток ещё считается коротким
	MaxDuration time.Duration
	// RSTRatioThreshold — доля RST-пакетов, начиная с которой добавляется штраф
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

	// SYN без ACK — классический half-open (SYN) scan
	if stats.CntSYN > 0 && stats.CntACK == 0 {
		score += 0.50
	}

	// Малое число пакетов — признак зонда, а не полноценного соединения
	if stats.CntPackets <= d.MinPacketsThreshold {
		score += 0.25
	}

	// Высокая доля RST — целевой хост отвергает соединение (порт закрыт)
	rstRatio := float64(stats.CntRST) / float64(stats.CntPackets)
	if rstRatio >= d.RSTRatioThreshold {
		score += 0.15
	}

	// Очень короткий поток при наличии SYN — типичный сканер
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
