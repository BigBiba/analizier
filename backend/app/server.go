package main

import (
	"fmt"
	"strings"

	"analizier/backend/src/models"
	pkt "analizier/backend/src/packet"
	//"analizier/src/parser"

	"github.com/gorilla/websocket"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type Client struct {
	Conn *websocket.Conn
	Send chan models.Traffic
}

func MapPacketToTraffic(p pkt.PacketInfo) models.Traffic {
	return models.Traffic{
		FlowID: fmt.Sprintf("%v", p.FlowID),

		Timestamp: p.Timestamp.Format("2006-01-02 15:04:05"),
		Interface: p.Interface,

		SourceIP:      p.SrcIP,
		DestinationIP: p.DstIP,

		SourcePort:      p.SrcPort,
		DestinationPort: p.DstPort,

		IPVersion: p.IPVersion,

		Length:        p.Length,
		TrafficVolume: p.TrafficVolume,

		Flags: strings.Join(p.Flags, ","),

		AnomalyType: "",
	}
}

func main() {
	db, err := gorm.Open(sqlite.Open("traffic.db"), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}
	db.AutoMigrate(&models.Traffic{}, &models.Anomaly{})

	app := NewApp(db)

	go app.runBroadcast()

	app.SetupRouter()
	app.Router.Run("0.0.0.0:8080")
}
