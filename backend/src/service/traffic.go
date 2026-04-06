package service

import (
	"analizier/backend/src/detector"
	"analizier/backend/src/models"
	"strings"
	"time"

	pkt "analizier/backend/src/packet"
	prs "analizier/backend/src/parser"
	"analizier/backend/src/repository"
)

func MapFlowToTraffic(flow *pkt.FlowInfo) models.Traffic {
	return models.Traffic{
		FlowID:          flow.FlowID,
		Interface:       flow.Interface,
		Timestamp:       flow.StartTime.Format("2006-01-02 15:04:05"),
		TrafficVolume:   flow.TrafficVolume,
		SourceIP:        flow.SourceIP,
		DestinationIP:   flow.DestinationIP,
		SourcePort:      flow.SourcePort,
		DestinationPort: flow.DestPort,
		IPVersion:       flow.IPVersion,
		Length:          flow.Length,
		Flags:           strings.Join(flow.Statuses, ","),
	}
}

func divideByFlow(packets []pkt.PacketInfo) map[string]*pkt.FlowInfo {
	flows := make(map[string]*pkt.FlowInfo)
	for _, packet := range packets {
		flowID := pkt.GetBiFlowID(packet)
		if flows[flowID] == nil {
			flows[flowID] = &pkt.FlowInfo{
				FlowID:        flowID,
				Interface:     packet.Interface,
				StartTime:     packet.Timestamp,
				SourceIP:      packet.SrcIP,
				DestinationIP: packet.DstIP,
				IPVersion:     packet.IPVersion,
				SourcePort:    packet.SrcPort,
				DestPort:      packet.DstPort,
				Statuses:      make([]string, 0),
			}
		}
		curFlow := flows[flowID]
		curFlow.Packets = append(curFlow.Packets, packet)
		curFlow.EndTime = packet.Timestamp
		curFlow.TrafficVolume += packet.Length
		curFlow.Length += 1
		for _, flag := range packet.Flags {
			if !contains(curFlow.Statuses, flag) {
				curFlow.Statuses = append(curFlow.Statuses, flag)
			}
		}
	}
	return flows
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

type TrafficService struct {
	detectors []detector.Detector
	repo      repository.TrafficRepository
	broadcast chan models.Traffic
}

func NewTrafficService(
	repo repository.TrafficRepository,
	detectors []detector.Detector,
	broadcast chan models.Traffic,
) *TrafficService {
	return &TrafficService{
		repo:      repo,
		detectors: detectors,
		broadcast: broadcast,
	}
}

// приходит файл
// парсим файл на PacketInfo
// Разделяем PacketInfo на FlowInfo
// Тут можно записать FlowInfo в БД
// Собираем FlowStats по FlowInfo
// Пропускаем FlowStats через детекторы и получаем DetectionResult
// Если DetectionResult.IsAnomaly добавляем DetectionResult.Type.String() в список аномалий
// Записываем аномалии для каждого FlowInfo в таблицу единым запросом
func (s *TrafficService) Pipeline(filename string) error {
	parser := prs.NewParser()
	packets := parser.Parse(filename)
	flows := divideByFlow(packets)

	// Разбиваем на временные окна для DDoS и Overload детекторов
	windows := pkt.SplitIntoWindows(packets, 10*time.Second)

	// Синхронный анализ окон (DDoS, Overload)
	anomalousFlows := make(map[string]string) // flowID -> detectorName
	for _, det := range s.detectors {
		if dd, ok := det.(interface {
			AnalyzeWindows([]pkt.TimeWindow) []pkt.TimeWindow
		}); ok {
			anomalousWins := dd.AnalyzeWindows(windows)
			for _, win := range anomalousWins {
				for flowID, flow := range flows {
					if len(flow.Packets) == 0 {
						continue
					}
					firstPkt := flow.Packets[0].Timestamp
					if (firstPkt.After(win.StartTime) || firstPkt.Equal(win.StartTime)) &&
						(firstPkt.Before(win.EndTime) || firstPkt.Equal(win.EndTime)) {
						anomalousFlows[flowID] = det.Name()
					}
				}
			}
		}
	}

	var trafficRecords []*models.Traffic

	for _, flow := range flows {
		pkt.AnalyzeFlow(flow)

		trafficModel := MapFlowToTraffic(flow)

		// Per-flow детекторы (Worm, Virus)
		for _, d := range s.detectors {
			detRes := d.Analyze(flow.Stats)
			if detRes.IsAnomaly {
				trafficModel.Anomalies = append(trafficModel.Anomalies, models.Anomaly{
					AnomalyType: detRes.Type.String(),
				})
			}
		}

		// DDoS/Overload аномалии из анализа окон
		if detName, ok := anomalousFlows[flow.FlowID]; ok {
			if detName == "DDoSDetector" {
				trafficModel.Anomalies = append(trafficModel.Anomalies, models.Anomaly{
					AnomalyType: detector.AnomalyDoS.String(),
				})
			} else if detName == "OverloadDetector" {
				trafficModel.Anomalies = append(trafficModel.Anomalies, models.Anomaly{
					AnomalyType: detector.AnomalyOverload.String(),
				})
			}
		}

		s.broadcast <- trafficModel
		trafficRecords = append(trafficRecords, &trafficModel)
	}

	err := s.repo.CreateBulk(trafficRecords)
	if err != nil {
		return err
	}
	return nil
}
