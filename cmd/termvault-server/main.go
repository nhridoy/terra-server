package main

import (
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/gin-gonic/gin"
	gormsqlite "github.com/glebarez/sqlite"
	"github.com/termvault/termvault/internal/auth"
	"github.com/termvault/termvault/internal/config"
	"github.com/termvault/termvault/internal/models"
	"gorm.io/gorm"
)

func main() {
	cfg := config.Load()

	var db *gorm.DB
	var err error

	if cfg.DatabaseURL == "" || cfg.DatabaseURL == "sqlite://termvault.db" {
		db, err = gorm.Open(gormsqlite.Open("termvault.db"), &gorm.Config{})
	} else {
		db, err = gorm.Open(gormsqlite.Open(cfg.DatabaseURL), &gorm.Config{})
	}

	if err != nil {
		slog.Error("failed to connect database", "error", err)
		os.Exit(1)
	}

	if err := models.AutoMigrate(db); err != nil {
		slog.Error("failed to run migrations", "error", err)
		os.Exit(1)
	}

	r := gin.Default()

	r.GET("/", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "TermVault API"})
	})

	apiAuth := r.Group("/api/v1/auth")
	apiAuth.POST("/prelogin", auth.HandlePrelogin(db, cfg))
	apiAuth.POST("/register", auth.HandleRegister(db, cfg))

	addr := cfg.Host + ":" + cfg.Port

	go func() {
		slog.Info("server starting", "addr", addr)
		if err := r.Run(addr); err != nil {
			slog.Error("server failed", "error", err)
			os.Exit(1)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
}
