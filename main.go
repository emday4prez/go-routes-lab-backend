package main

import (
	"net/http"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

func main() {
	// Create a Gin router with default middleware (logger and recovery)
	r := gin.Default()
	r.Use(cors.New(cors.Config{
		AllowOrigins: []string{"localhost:5173"},
		AllowMethods: []string{"PUT", "PATCH", "GET", "POST"},
		MaxAge:       12 * time.Hour,
	}))
	// Define a simple GET endpoint
	r.GET("/ping", func(c *gin.Context) {
		// Return JSON response
		c.JSON(http.StatusOK, gin.H{
			"message": "pong",
		})
	})

	// 8080
	r.Run()
}
