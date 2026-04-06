package detector

import (
	"analizier/src/packet"
	"math"
)

type OverloadDetector struct {
	WindowSize        int     // количество окон для расчёта статистики (скользящее окно)
	Sensitivity       float64 // коэффициент (сколько стандартных отклонений считать аномалией)
	MinBPS            float64 // абсолютный минимальный порог BPS (игнорировать если ниже)
	MinPPS            float64 // абсолютный минимальный порог PPS
	UseAdaptive       bool    // использовать адаптивные пороги или фиксированные
	FixedBPSThreshold float64 // фиксированный порог BPS (если UseAdaptive = false)
	FixedPPSThreshold float64 // фиксированный порог PPS
}

// NewAdaptiveOverloadDetector создаёт адаптивный детектор с настройками по умолчанию
func NewAdaptiveOverloadDetector(windowSize int, sensitivity float64) *OverloadDetector {
	if windowSize <= 0 {
		windowSize = 10
	}
	if sensitivity <= 0 {
		sensitivity = 3.0 // 3 сигмы
	}
	return &OverloadDetector{
		WindowSize:  windowSize,
		Sensitivity: sensitivity,
		MinBPS:      1_000_000, // 0.5 МБ/с – ниже этого не считаем перегрузкой
		MinPPS:      1000,      // 1000 пакетов/с
		UseAdaptive: true,
	}
}

// NewFixedOverloadDetector создаёт детектор с фиксированными порогами (для обратной совместимости)
func NewFixedOverloadDetector(bps, pps float64) *OverloadDetector {
	return &OverloadDetector{
		UseAdaptive:       false,
		FixedBPSThreshold: bps,
		FixedPPSThreshold: pps,
		MinBPS:            0,
		MinPPS:            0,
	}
}

// Name возвращает имя детектора
func (d *OverloadDetector) Name() string {
	return "OverloadDetector"
}

// Analyze требуется интерфейсом Detector, но перегрузка выявляется на окнах
func (d *OverloadDetector) Analyze(stats packet.FlowStats) DetectionResult {
	return DetectionResult{IsAnomaly: false}
}

// AnalyzeWindows анализирует окна и возвращает аномальные (перегруженные)
func (d *OverloadDetector) AnalyzeWindows(windows []packet.TimeWindow) []packet.TimeWindow {
	if len(windows) == 0 {
		return nil
	}

	if !d.UseAdaptive {
		return d.analyzeFixed(windows)
	}
	return d.analyzeAdaptive(windows)
}

// analyzeFixed – старый метод с фиксированными порогами
func (d *OverloadDetector) analyzeFixed(windows []packet.TimeWindow) []packet.TimeWindow {
	var overloaded []packet.TimeWindow
	for _, w := range windows {
		s := w.Stats
		if s.BPS > d.FixedBPSThreshold || s.PPS > d.FixedPPSThreshold {
			overloaded = append(overloaded, w)
		}
	}
	return overloaded
}

// analyzeAdaptive – адаптивный метод на основе скользящего среднего и стандартного отклонения
func (d *OverloadDetector) analyzeAdaptive(windows []packet.TimeWindow) []packet.TimeWindow {
	var overloaded []packet.TimeWindow

	// Для каждого окна, начиная с WindowSize-го, вычисляем порог по предыдущим окнам
	for i := d.WindowSize - 1; i < len(windows); i++ {
		// Берём предыдущие окна: от i-d.WindowSize+1 до i
		start := i - d.WindowSize + 1
		var bpsValues, ppsValues []float64
		for j := start; j <= i; j++ {
			bpsValues = append(bpsValues, windows[j].Stats.BPS)
			ppsValues = append(ppsValues, windows[j].Stats.PPS)
		}

		// Вычисляем среднее и стандартное отклонение для BPS
		avgBPS := average(bpsValues)
		stdBPS := stdDev(bpsValues, avgBPS)

		// То же для PPS
		avgPPS := average(ppsValues)
		stdPPS := stdDev(ppsValues, avgPPS)

		// Порог = среднее + sensitivity * стандартное отклонение
		thresholdBPS := avgBPS + d.Sensitivity*stdBPS
		thresholdPPS := avgPPS + d.Sensitivity*stdPPS

		// Применяем абсолютные минимальные пороги (чтобы не срабатывало на очень низком трафике)
		if thresholdBPS < d.MinBPS {
			thresholdBPS = d.MinBPS
		}
		if thresholdPPS < d.MinPPS {
			thresholdPPS = d.MinPPS
		}

		currentBPS := windows[i].Stats.BPS
		currentPPS := windows[i].Stats.PPS

		if currentBPS > thresholdBPS || currentPPS > thresholdPPS {
			overloaded = append(overloaded, windows[i])
		}
	}

	return overloaded
}

// average вычисляет среднее арифметическое
func average(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	sum := 0.0
	for _, v := range values {
		sum += v
	}
	return sum / float64(len(values))
}

// stdDev вычисляет стандартное отклонение
func stdDev(values []float64, mean float64) float64 {
	if len(values) == 0 {
		return 0
	}
	var sumSqDiff float64
	for _, v := range values {
		diff := v - mean
		sumSqDiff += diff * diff
	}
	variance := sumSqDiff / float64(len(values))
	return math.Sqrt(variance)
}
