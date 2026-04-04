package service

import (
	"analizier/backend/src/detector"
	//"analizier/backend/src/models"
	pkt "analizier/backend/src/packet"
	prs "analizier/backend/src/parser"
	"analizier/backend/src/repository"
)

func divideByFlow(packets []pkt.PacketInfo) map[string]*pkt.FlowInfo {
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

type TrafficService struct {
	detectors []detector.Detector
	repo      repository.TrafficRepository
}

func NewTrafficService(
	repo repository.TrafficRepository,
	detectors []detector.Detector,
) *TrafficService {
	return &TrafficService{
		repo:      repo,
		detectors: detectors,
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
	s.repo.CreateBulk()
	for _, flow := range flows {
		var results []string
		pkt.AnalyzeFlow(flow)
		for _, d := range s.detectors {
			detRes := d.Analyze(flow.Stats)
			if detRes.IsAnomaly {
				results = append(results, detRes.Type.String())
			}
		}
		s.repo.WriteFlowAnomaly()
	}
	return nil
}
