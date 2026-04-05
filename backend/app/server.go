package main

import (
	"fmt"
	"net/http"
	"strings"

	pkt "analizier/backend/src/packet"
	//"analizier/src/parser"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type Traffic struct {
	ID uint `json:"id" gorm:"primaryKey"`

	FlowID string `json:"flow_id"`

	Timestamp string `json:"timestamp"`
	Interface string `json:"interface"`

	SourceIP      string `json:"source_ip"`
	DestinationIP string `json:"destination_ip"`

	SourcePort      string `json:"source_port"`
	DestinationPort string `json:"destination_port"`

	IPVersion string `json:"ip_version"`

	Length        int `json:"length"`
	TrafficVolume int `json:"traffic_volume"`

	Flags string `json:"flags"`

	AnomalyType string `json:"anomaly_type"`
}

type Client struct {
	Conn *websocket.Conn
	Send chan Traffic
}

var db *gorm.DB

func MapPacketToTraffic(p pkt.PacketInfo) Traffic {
	return Traffic{
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
	var err error
	db, err = gorm.Open(sqlite.Open("traffic.db"), &gorm.Config{})
	if err != nil {
		panic(err)
	}
	db.AutoMigrate(&Traffic{})

	clients := make(map[*Client]bool)
	broadcast := make(chan Traffic)
	upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}

	go func() {
		for traffic := range broadcast {
			for client := range clients {
				select {
				case client.Send <- traffic:
				default:
					close(client.Send)
					delete(clients, client)
				}
			}
		}
	}()

	// go func() {
	// 	parser := parser.NewParser()
	// 	packets := parser.Parse("files/1.pcap")

	// 	for _, p := range packets {
	// 		t := MapPacketToTraffic(p)

	// 		db.Create(&t)
	// 		broadcast <- t
	// 	}
	// }()

	r := gin.Default()

	// CORS
	r.Use(func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE")
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(200)
			return
		}
		c.Next()
	})

	// POST /api/traffic
	r.POST("/api/traffic", func(c *gin.Context) {
		var traffic Traffic
		if err := c.ShouldBindJSON(&traffic); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		db.Create(&traffic)
		broadcast <- traffic
		c.JSON(http.StatusOK, traffic)
	})

	// GET /api/traffic
	r.GET("/api/traffic", func(c *gin.Context) {
		var traffic []Traffic

		sourceIP := c.Query("source_ip")

		query := db

		if sourceIP != "" {
			query = query.Where("source_ip LIKE ?", "%"+sourceIP+"%")
		}

		query.Order("id asc").Find(&traffic)

		c.JSON(http.StatusOK, traffic)
	})

	r.GET("/ws", func(c *gin.Context) {
		conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
		if err != nil {
			fmt.Println("WS upgrade failed:", err)
			return
		}
		client := &Client{Conn: conn, Send: make(chan Traffic, 10)}
		clients[client] = true
		fmt.Println("WS client connected")

		go func(c *Client) {
			for msg := range c.Send {
				if err := c.Conn.WriteJSON(msg); err != nil {
					break
				}
			}
			c.Conn.Close()
		}(client)

		go func(c *Client) {
			defer func() {
				delete(clients, c)
				c.Conn.Close()
				fmt.Println("WS client disconnected")
			}()
			for {
				if _, _, err := c.Conn.NextReader(); err != nil {
					break
				}
			}
		}(client)
	})

	r.Run("0.0.0.0:8080")
}
