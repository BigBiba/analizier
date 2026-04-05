package main

import (
	"analizier/backend/src/detector"
	"analizier/backend/src/models"
	"analizier/backend/src/repository"
	"analizier/backend/src/service"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"gorm.io/gorm"
	"net/http"
)

type App struct {
	Router         *gin.Engine
	DB             *gorm.DB
	Clients        map[*Client]bool
	Broadcast      chan models.Traffic
	Upgrader       websocket.Upgrader
	TrafficService *service.TrafficService
	TrafficRepo    *repository.TrafficRepository
}

func NewApp(db *gorm.DB) *App {
	router := gin.Default()
	router.MaxMultipartMemory = 10 << 20

	repo := repository.NewSqliteTrafficRepo(db)
	// Добавить детекторы
	detectors := []detector.Detector{}

	trafficService := service.NewTrafficService(repo, detectors)
	return &App{
		Router:    router,
		DB:        db,
		Clients:   make(map[*Client]bool),
		Broadcast: make(chan models.Traffic),
		Upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool { return true },
		},
		TrafficService: trafficService,
		TrafficRepo:    &repo,
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
		// POST /api/upload
		api.POST("/upload", a.handleUpload)
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

func (a *App) handleUpload(c *gin.Context) {
	file, err := c.FormFile("file")
	if err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	path := "files/" + file.Filename
	if err = c.SaveUploadedFile(file, path); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	err = a.TrafficService.Pipeline(path)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	//parser := parser.NewParser()
	//packets := parser.Parse(path)

	//for _, p := range packets {
	//	t := MapPacketToTraffic(p)
	//	db.Create(&t)
	//	broadcast <- t
	//}

	c.JSON(200, gin.H{"status": "uploaded and parsed"})
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

	page := c.DefaultQuery("page", "1")
	limit := c.DefaultQuery("limit", "20")
	var pageInt, limitInt int
	fmt.Sscanf(page, "%d", &pageInt)
	fmt.Sscanf(limit, "%d", &limitInt)
	offset := (pageInt - 1) * limitInt

	traffic, err := (*a.TrafficRepo).GetTraffic(limitInt, offset)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

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
	fmt.Println("WS client connected")

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
