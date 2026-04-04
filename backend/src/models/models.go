package models

type Traffic struct {
	ID              uint   `json:"id" gorm:"primaryKey"`
	FlowID          string `json:"flow_id"`
	Timestamp       string `json:"timestamp"`
	Interface       string `json:"interface"`
	SourceIP        string `json:"source_ip"`
	DestinationIP   string `json:"destination_ip"`
	SourcePort      string `json:"source_port"`
	DestinationPort string `json:"destination_port"`
	IPVersion       string `json:"ip_version"`
	Length          int    `json:"length"`
	TrafficVolume   int    `json:"traffic_volume"`
	Flags           string `json:"flags"`
	AnomalyType     string `json:"anomaly_type"`
}

type TrafficDB struct {
}

type TrafficIDAnomalyDB struct {
	ID          uint `json:"id" gorm:"primaryKey"`
	AnomalyType string
}
