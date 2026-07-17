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
			hosts := protected.Group("/hosts")
			{
				hosts.GET("", api.ListHosts)
				hosts.POST("", api.CreateHost)
				hosts.GET("/:id", api.GetHost)
				hosts.PUT("/:id", api.UpdateHost)
				hosts.DELETE("/:id", api.DeleteHost)
			}

			groups := protected.Group("/groups")
			{
				groups.GET("", api.ListGroups)
				groups.POST("", api.CreateGroup)
				groups.PUT("/:id", api.UpdateGroup)
				groups.DELETE("/:id", api.DeleteGroup)
			}

			vaults := protected.Group("/vaults")
			{
				vaults.GET("", api.ListVaults)
				vaults.POST("", api.CreateVault)
				vaults.PUT("/:id", api.UpdateVault)
				vaults.DELETE("/:id", api.DeleteVault)
				vaults.GET("/:id/data", api.GetVaultData)
				vaults.POST("/:id/unlock", api.UnlockVault)
			}

			keys := protected.Group("/keys")
			{
				keys.GET("", api.ListKeys)
				keys.POST("", api.ImportKey)
				keys.POST("/generate", api.GenerateKey)
				keys.DELETE("/:id", api.DeleteKey)
			}

			snippets := protected.Group("/snippets")
			{
				snippets.GET("", api.ListSnippets)
				snippets.POST("", api.CreateSnippet)
				snippets.PUT("/:id", api.UpdateSnippet)
				snippets.DELETE("/:id", api.DeleteSnippet)
			}

			workspaces := protected.Group("/workspaces")
			{
				workspaces.GET("", api.ListWorkspaces)
				workspaces.POST("", api.CreateWorkspace)
				workspaces.PUT("/:id", api.UpdateWorkspace)
				workspaces.DELETE("/:id", api.DeleteWorkspace)
			}

			tabGroups := protected.Group("/tab-groups")
			{
				tabGroups.GET("", api.ListTabGroups)
				tabGroups.POST("", api.CreateTabGroup)
				tabGroups.PUT("/:id", api.UpdateTabGroup)
				tabGroups.DELETE("/:id", api.DeleteTabGroup)
			}

			sessions := protected.Group("/sessions")
			{
				sessions.GET("", api.ListSessions)
				sessions.GET("/:id", api.GetSession)
			}

			settings := protected.Group("/settings")
			{
				settings.GET("", api.GetSettings)
				settings.PUT("", api.UpdateSettings)
			}

			teams := protected.Group("/teams")
			{
				teams.GET("", api.ListTeams)
				teams.POST("", api.CreateTeam)
				teams.POST("/:id/members", api.AddTeamMember)
			}

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
