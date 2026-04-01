package detector

import (
	"analizier/src/packet"
	"math"
	"sync"
)

// P2MPDetector обнаруживает трафик типа "точка–многоточие" (Point-to-Multipoint).
// Паттерн: один источник отправляет данные большому числу уникальных получателей.
//
// Детектор stateful: он накапливает состояние по всем проанализированным потокам
// и возвращает результат на основе накопленной картины.
// Реализует интерфейс FlowDetector, т.к. для корреляции необходимы IP-адреса,
// которых нет в FlowStats.
type P2MPDetector struct {
	mu        sync.Mutex
	srcToDsts map[string]map[string]struct{} // srcIP → множество dstIP

	// Threshold — минимальное число уникальных получателей для признания P2MP
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

// AnalyzeFlow обновляет внутреннее состояние данными потока и возвращает результат.
// Если хотя бы один источник из потока уже достиг порогового числа получателей —
// детектор сообщает об аномалии.
func (d *P2MPDetector) AnalyzeFlow(flow *packet.FlowInfo) DetectionResult {
	// Собираем уникальные пары srcIP→dstIP из пакетов потока
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

	// Обновляем глобальное состояние
	for src, dsts := range localSrcDsts {
		if _, ok := d.srcToDsts[src]; !ok {
			d.srcToDsts[src] = make(map[string]struct{})
		}
		for dst := range dsts {
			d.srcToDsts[src][dst] = struct{}{}
		}
	}

	// Проверяем: есть ли среди источников потока хотя бы один с P2MP-паттерном
	maxDsts := 0
	for src := range localSrcDsts {
		if cnt := len(d.srcToDsts[src]); cnt > maxDsts {
			maxDsts = cnt
		}
	}

	if maxDsts < d.Threshold {
		return DetectionResult{IsAnomaly: false, Confidence: 0, Type: AnomalyNone}
	}

	// Уверенность растёт вместе с числом получателей, насыщаясь к 2×Threshold
	confidence := math.Min(1.0, float64(maxDsts)/float64(d.Threshold*2))

	return DetectionResult{
		IsAnomaly:  true,
		Confidence: confidence,
		Type:       AnomalyP2MP,
	}
}

// Reset сбрасывает накопленное состояние детектора (например, между временными окнами).
func (d *P2MPDetector) Reset() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.srcToDsts = make(map[string]map[string]struct{})
}
