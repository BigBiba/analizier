package main

import (
	"fmt"
	"strings"

<<<<<<< HEAD
	pkt "analizier/src/packet"
	"analizier/src/parser"
=======
	"analizier/backend/src/models"
	pkt "analizier/backend/src/packet"
	//"analizier/src/parser"
>>>>>>> 4f723e5 (2 iter)

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
	db.AutoMigrate(&models.Traffic{})

	app := NewApp(db)

	go app.runBroadcast()

<<<<<<< HEAD
	go func() {
		parser := parser.NewParser()
		packets := parser.Parse("files/small.pcap")

		for _, p := range packets {
			t := MapPacketToTraffic(p)

			db.Create(&t)
			broadcast <- t
		}
	}()

	r := gin.Default()

	r.MaxMultipartMemory = 10 << 20

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

	r.POST("/api/upload", func(c *gin.Context) {
		file, err := c.FormFile("file")
		if err != nil {
			c.JSON(400, gin.H{"error": err.Error()})
			return
		}

		// сохраняем файл
		path := "files/" + file.Filename
		if err := c.SaveUploadedFile(file, path); err != nil {
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}

		// парсим
		parser := parser.NewParser()
		packets := parser.Parse(path)

		for _, p := range packets {
			t := MapPacketToTraffic(p)
			db.Create(&t)
			broadcast <- t
		}

		c.JSON(200, gin.H{"status": "uploaded and parsed"})
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

		// пагинация
		page := c.DefaultQuery("page", "1")
		limit := c.DefaultQuery("limit", "20")

		var pageInt, limitInt int
		fmt.Sscanf(page, "%d", &pageInt)
		fmt.Sscanf(limit, "%d", &limitInt)

		offset := (pageInt - 1) * limitInt

		query := db

		if sourceIP != "" {
			query = query.Where("source_ip LIKE ?", "%"+sourceIP+"%")
		}

		query.Order("id asc").
			Limit(limitInt).
			Offset(offset).
			Find(&traffic)

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
=======
	app.SetupRouter()
	app.Router.Run("0.0.0.0:8080")
>>>>>>> 4f723e5 (2 iter)
}
