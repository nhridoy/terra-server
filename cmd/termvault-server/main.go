package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"github.com/termvault/termvault/internal/api"
	"github.com/termvault/termvault/internal/auth"
	"github.com/termvault/termvault/internal/config"
	"github.com/termvault/termvault/internal/db"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	if err := godotenv.Load(); err != nil {
		slog.Info("No .env file found")
	}

	cfg := config.Load()

	if cfg.JWTSecret == "change-me-in-production" {
		slog.Warn("Using default JWT_SECRET — change it in production!")
	}

	if cfg.Port == "" {
		cfg.Port = "8080"
	}

	if cfg.Host == "" {
		cfg.Host = "0.0.0.0"
	}

	if err := db.Init(); err != nil {
		slog.Error("Failed to initialize database", "error", err)
		os.Exit(1)
	}

	authLimiter := auth.NewRateLimiter(cfg.RateLimitAuth, time.Minute)
	apiLimiter := auth.NewRateLimiter(cfg.RateLimitAPI, time.Minute)

	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(requestLogger())

	// Trusted proxy IP extraction middleware
	trustedCIDRs := auth.ParseCIDRs(cfg.TrustedProxies)
	if len(trustedCIDRs) > 0 {
		router.Use(auth.TrustedClientIPMiddleware(trustedCIDRs))
		slog.Info("Trusted proxies configured", "cidrs", cfg.TrustedProxies)
	}

	router.Use(func(c *gin.Context) {
		origin := c.GetHeader("Origin")
		allowed := false
		for _, o := range cfg.AllowedOrigins {
			if origin == o {
				allowed = true
				break
			}
		}

		if allowed {
			c.Header("Access-Control-Allow-Origin", origin)
			c.Header("Access-Control-Allow-Credentials", "true")
		}

		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Origin, Content-Type, Authorization")
		c.Header("Access-Control-Max-Age", "86400")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("X-XSS-Protection", "1; mode=block")
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")

		c.Next()
	})

	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":  "ok",
			"version": "1.0.0",
		})
	})

	v1 := router.Group("/api/v1")
	{
		authGroup := v1.Group("/auth")
		{
			authGroup.POST("/register", auth.RateLimitMiddleware(authLimiter), api.Register)
			authGroup.POST("/login", auth.RateLimitMiddleware(authLimiter), api.Login)
			authGroup.POST("/refresh", auth.RateLimitByKeyMiddleware(apiLimiter, func(c *gin.Context) string {
				var req struct {
					RefreshToken string `json:"refreshToken"`
				}
				if err := c.ShouldBindJSON(&req); err == nil && req.RefreshToken != "" {
					return req.RefreshToken
				}
				return c.ClientIP()
			}), api.RefreshToken)
			authGroup.GET("/oauth/:provider", api.OAuthRedirect)
			authGroup.POST("/oauth/callback", api.OAuthCallback)
		}

		protected := v1.Group("")
		protected.Use(auth.AuthMiddleware())
		{
			protected.POST("/auth/logout", api.Logout)
			protected.POST("/auth/change-password", api.ChangePassword)
			protected.POST("/auth/master-password", api.SetMasterPassword)
			protected.GET("/auth/me", api.GetCurrentUser)
			protected.PUT("/auth/profile", api.UpdateProfile)
			protected.DELETE("/auth/account", api.DeleteAccount)

			protected.GET("/sync/full", auth.RateLimitByKeyMiddleware(apiLimiter, func(c *gin.Context) string {
				return auth.GetUserID(c)
			}), api.SyncFull)
			protected.POST("/sync/push", auth.RateLimitByKeyMiddleware(apiLimiter, func(c *gin.Context) string {
				return auth.GetUserID(c)
			}), api.SyncPush)

			// REST CRUD endpoints — unused by the Tauri client (client uses sync endpoints).
			// Kept for potential future use (web client, third-party integrations).
			protected.GET("/hosts", api.ListHosts)
			protected.POST("/hosts", api.CreateHost)
			protected.PUT("/hosts/:id", api.UpdateHost)
			protected.DELETE("/hosts/:id", api.DeleteHost)

			protected.GET("/groups", api.ListGroups)
			protected.POST("/groups", api.CreateGroup)
			protected.PUT("/groups/:id", api.UpdateGroup)
			protected.DELETE("/groups/:id", api.DeleteGroup)

			protected.GET("/vaults", api.ListVaults)
			protected.POST("/vaults", api.CreateVault)
			protected.PUT("/vaults/:id", api.UpdateVault)
			protected.DELETE("/vaults/:id", api.DeleteVault)

			protected.GET("/keys", api.ListKeys)
			protected.POST("/keys", api.CreateKey)
			protected.PUT("/keys/:id", api.UpdateKey)
			protected.DELETE("/keys/:id", api.DeleteKey)

			protected.GET("/snippets", api.ListSnippets)
			protected.POST("/snippets", api.CreateSnippet)
			protected.PUT("/snippets/:id", api.UpdateSnippet)
			protected.DELETE("/snippets/:id", api.DeleteSnippet)

			protected.GET("/workspaces", api.ListWorkspaces)
			protected.POST("/workspaces", api.CreateWorkspace)
			protected.PUT("/workspaces/:id", api.UpdateWorkspace)
			protected.DELETE("/workspaces/:id", api.DeleteWorkspace)

			protected.GET("/tab-groups", api.ListTabGroups)
			protected.POST("/tab-groups", api.CreateTabGroup)
			protected.PUT("/tab-groups/:id", api.UpdateTabGroup)
			protected.DELETE("/tab-groups/:id", api.DeleteTabGroup)

			protected.GET("/settings", api.GetSettings)
			protected.PUT("/settings", api.UpdateSettings)

			protected.GET("/teams", api.ListTeams)
			protected.POST("/teams", api.CreateTeam)
			protected.GET("/teams/:id", api.GetTeam)
			protected.PUT("/teams/:id", api.UpdateTeam)
			protected.DELETE("/teams/:id", api.DeleteTeam)
			protected.POST("/teams/:id/members", api.AddMember)
			protected.DELETE("/teams/:id/members/:memberId", api.RemoveMember)
			protected.PUT("/teams/:id/members/:memberId/role", api.UpdateMemberRole)

			protected.GET("/teams/:id/shared-vaults", api.ListSharedVaults)
			protected.POST("/teams/:id/shared-vaults", api.CreateSharedVault)
			protected.DELETE("/teams/:id/shared-vaults/:vaultId", api.DeleteSharedVault)
		}
	}

	addr := cfg.Host + ":" + cfg.Port
	srv := &http.Server{
		Addr:              addr,
		Handler:           router,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	go func() {
		slog.Info("TermVault server starting", "addr", addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("Server failed", "error", err)
			os.Exit(1)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	sig := <-quit
	slog.Info("Shutting down server", "signal", sig.String())

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		slog.Error("Server forced to shutdown", "error", err)
		os.Exit(1)
	}

	slog.Info("Server exited gracefully")
}

func requestLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		raw := c.Request.URL.RawQuery

		c.Next()

		latency := time.Since(start)
		status := c.Writer.Status()
		method := c.Request.Method

		if raw != "" {
			path = path + "?" + raw
		}

		slog.Info("request",
			"method", method,
			"path", path,
			"status", status,
			"latency_ms", latency.Milliseconds(),
			"client_ip", auth.GetClientIP(c),
		)
	}
}
