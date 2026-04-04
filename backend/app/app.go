package main

import (
	"analizier/backend/src/models"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"gorm.io/gorm"
	"net/http"
)

type App struct {
	Router    *gin.Engine
	DB        *gorm.DB
	Clients   map[*Client]bool
	Broadcast chan models.Traffic
	Upgrader  websocket.Upgrader
}

func NewApp(db *gorm.DB) *App {
	return &App{
		Router:    gin.Default(),
		DB:        db,
		Clients:   make(map[*Client]bool),
		Broadcast: make(chan models.Traffic),
		Upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool { return true },
		},
	}
}

func (a *App) SetupRouter() {
	// Настройка CORS
	a.Router.Use(a.corsMiddleware())

	api := a.Router.Group("/api")
	{
		// POST /api/traffic
		api.POST("/traffic", a.handlePostTraffic)
		// GET /api/traffic
		api.GET("/traffic", a.handleGetTraffic)
	}

	a.Router.GET("/ws", a.handleWebSocket)
}

func (a *App) corsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE")
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(200)
			return
		}
		c.Next()
	}
}

func (a *App) handlePostTraffic(c *gin.Context) {
	var traffic models.Traffic
	if err := c.ShouldBindJSON(&traffic); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	a.DB.Create(&traffic)
	a.Broadcast <- traffic
	c.JSON(http.StatusOK, traffic)
}

func (a *App) handleGetTraffic(c *gin.Context) {
	var traffic []models.Traffic
	sourceIP := c.Query("source_ip")

	query := a.DB
	if sourceIP != "" {
		query = query.Where("source_ip LIKE ?", "%"+sourceIP+"%")
	}
	query.Order("id asc").Find(&traffic)
	c.JSON(http.StatusOK, traffic)
}

func (a *App) handleGetTrafficFile(c *gin.Context) {
	file, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No file uploaded"})
		return
	}
	tempPath := "temp_" + file.Filename
	if err := c.SaveUploadedFile(file, tempPath); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save file"})
		return
	}
}

func (a *App) handleWebSocket(c *gin.Context) {
	conn, err := a.Upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		return
	}

	client := &Client{Conn: conn, Send: make(chan models.Traffic, 10)}
	a.Clients[client] = true

	// Логика чтения/записи (можно тоже вынести в отдельные методы Client)
	go a.writePump(client)
	go a.readPump(client)
}

func (a *App) writePump(client *Client) {
	for msg := range client.Send {
		if err := client.Conn.WriteJSON(msg); err != nil {
			break
		}
	}
	client.Conn.Close()
}

func (a *App) readPump(client *Client) {
	defer func() {
		delete(a.Clients, client)
		client.Conn.Close()
		fmt.Println("WS client disconnected")
	}()
	for {
		if _, _, err := client.Conn.NextReader(); err != nil {
			break
		}
	}
}

func (a *App) runBroadcast() {
	for traffic := range a.Broadcast {
		for client := range a.Clients {
			select {
			case client.Send <- traffic:
			default:
				close(client.Send)
				delete(a.Clients, client)
			}
		}
	}
}
