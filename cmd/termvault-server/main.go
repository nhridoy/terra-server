package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"github.com/termvault/termvault/internal/api"
	"github.com/termvault/termvault/internal/auth"
	"github.com/termvault/termvault/internal/config"
	"github.com/termvault/termvault/internal/db"
)

func main() {
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found")
	}

	cfg := config.Load()

	if err := db.Init(); err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}

	router := gin.Default()

	router.Use(func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Origin, Content-Type, Authorization")
		c.Header("Access-Control-Allow-Credentials", "true")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	})

	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":  "ok",
			"version": "1.0.0",
		})
	})

	apiGroup := router.Group("/api")
	{
		authGroup := apiGroup.Group("/auth")
		{
			authGroup.POST("/register", api.Register)
			authGroup.POST("/login", api.Login)
			authGroup.POST("/refresh", api.RefreshToken)
			authGroup.GET("/oauth/:provider", api.OAuthRedirect)
			authGroup.POST("/oauth/callback", api.OAuthCallback)
		}

		protected := apiGroup.Group("")
		protected.Use(auth.AuthMiddleware())
		{
			sync := protected.Group("/sync")
			{
				sync.POST("/push", api.SyncPush)
				sync.GET("/pull", api.SyncPull)
				sync.GET("/full", api.SyncFull)
			}
		}
	}

	addr := fmt.Sprintf("%s:%s", cfg.Host, cfg.Port)
	log.Printf("TermVault server starting on %s", addr)
	if err := router.Run(addr); err != nil {
		log.Fatal(err)
	}
}
