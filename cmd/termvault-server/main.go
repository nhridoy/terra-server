package main

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"github.com/termvault/termvault/internal/api"
	"github.com/termvault/termvault/internal/auth"
	"github.com/termvault/termvault/internal/config"
	"github.com/termvault/termvault/internal/db"
	"github.com/termvault/termvault/internal/ssh"
)

func main() {
	// Load environment variables
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found")
	}

	// Load configuration
	cfg := config.Load()

	// Initialize database
	if err := db.Init(); err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}

	// Initialize SSH connection manager
	ssh.DefaultManager.StartCleanup(5 * time.Minute)

	// Initialize Gin router
	router := gin.Default()

	// CORS middleware
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

	// Health check endpoint
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":  "ok",
			"version": "1.0.0",
		})
	})

	// API routes
	apiGroup := router.Group("/api")
	{
		// Auth routes (public)
		authGroup := apiGroup.Group("/auth")
		{
			authGroup.POST("/register", api.Register)
			authGroup.POST("/login", api.Login)
			authGroup.POST("/refresh", api.RefreshToken)
			authGroup.GET("/oauth/:provider", api.OAuthRedirect)
			authGroup.POST("/oauth/callback", api.OAuthCallback)
		}

		// Protected routes
		protected := apiGroup.Group("")
		protected.Use(auth.AuthMiddleware())
		{
			// Host routes
			hosts := protected.Group("/hosts")
			{
				hosts.GET("", api.ListHosts)
				hosts.POST("", api.CreateHost)
				hosts.GET("/:id", api.GetHost)
				hosts.PUT("/:id", api.UpdateHost)
				hosts.DELETE("/:id", api.DeleteHost)
			}

			// Group routes
			groups := protected.Group("/groups")
			{
				groups.GET("", api.ListGroups)
				groups.POST("", api.CreateGroup)
				groups.PUT("/:id", api.UpdateGroup)
				groups.DELETE("/:id", api.DeleteGroup)
			}

			// Vault routes
			vaults := protected.Group("/vaults")
			{
				vaults.GET("", api.ListVaults)
				vaults.POST("", api.CreateVault)
				vaults.PUT("/:id", api.UpdateVault)
				vaults.DELETE("/:id", api.DeleteVault)
				vaults.GET("/:id/data", api.GetVaultData)
				vaults.POST("/:id/unlock", api.UnlockVault)
			}

			// Keychain routes
			keys := protected.Group("/keys")
			{
				keys.GET("", api.ListKeys)
				keys.POST("", api.ImportKey)
				keys.POST("/generate", api.GenerateKey)
				keys.DELETE("/:id", api.DeleteKey)
			}

			// Snippet routes
			snippets := protected.Group("/snippets")
			{
				snippets.GET("", api.ListSnippets)
				snippets.POST("", api.CreateSnippet)
				snippets.PUT("/:id", api.UpdateSnippet)
				snippets.DELETE("/:id", api.DeleteSnippet)
			}

			// Workspace routes
			workspaces := protected.Group("/workspaces")
			{
				workspaces.GET("", api.ListWorkspaces)
				workspaces.POST("", api.CreateWorkspace)
				workspaces.PUT("/:id", api.UpdateWorkspace)
				workspaces.DELETE("/:id", api.DeleteWorkspace)
			}

			// Quick Preset (tab group) routes
			tabGroups := protected.Group("/tab-groups")
			{
				tabGroups.GET("", api.ListTabGroups)
				tabGroups.POST("", api.CreateTabGroup)
				tabGroups.PUT("/:id", api.UpdateTabGroup)
				tabGroups.DELETE("/:id", api.DeleteTabGroup)
			}

			// Session routes
			sessions := protected.Group("/sessions")
			{
				sessions.GET("", api.ListSessions)
				sessions.GET("/:id", api.GetSession)
			}

			// Settings routes
			settings := protected.Group("/settings")
			{
				settings.GET("", api.GetSettings)
				settings.PUT("", api.UpdateSettings)
			}

			// Team routes
			teams := protected.Group("/teams")
			{
				teams.GET("", api.ListTeams)
				teams.POST("", api.CreateTeam)
				teams.POST("/:id/members", api.AddTeamMember)
			}

			// SFTP routes (SSH-based)
			sftp := protected.Group("/sftp/:hostId")
			{
				sftp.GET("/list", api.ListFiles)
				sftp.GET("/read", api.ReadFile)
				sftp.POST("/write", api.WriteFile)
				sftp.POST("/upload", api.UploadFile)
				sftp.DELETE("/delete", api.DeleteFile)
			sftp.POST("/move", api.MoveFile)
			sftp.POST("/mkdir", api.Mkdir)
			sftp.POST("/copy", api.CopyFile)
			}

			// Cross-host SFTP operations
			sftpCross := protected.Group("/sftp")
			{
				sftpCross.POST("/cross-copy", api.CrossCopy)
				sftpCross.POST("/cross-move", api.CrossMove)
			}

			// Port forwarding routes
			portForward := protected.Group("/port-forward")
			{
				portForward.POST("", api.CreatePortForward)
				portForward.GET("", api.ListPortForwards)
				portForward.GET("/:id", api.GetPortForwardStatus)
				portForward.DELETE("/:id", api.DeletePortForward)
			}

			// Local file operations (for development)
			localFiles := protected.Group("/local")
			{
				localFiles.GET("/list", api.LocalListFiles)
				localFiles.GET("/read", api.LocalReadFile)
				localFiles.POST("/write", api.LocalWriteFile)
				localFiles.POST("/upload", api.LocalUploadFile)
				localFiles.DELETE("/delete", api.LocalDeleteFile)
				localFiles.POST("/mkdir", api.LocalMkdir)
			}
		}
	}

	// WebSocket routes
	router.GET("/ws/ssh", api.HandleSSHWebSocket)
	router.GET("/ws/sync", api.WsSyncHandler)

	// Start server
	addr := fmt.Sprintf("%s:%s", cfg.Host, cfg.Port)
	log.Printf("TermVault server starting on %s", addr)
	if err := router.Run(addr); err != nil {
		log.Fatal(err)
	}
}
