package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/joho/godotenv"
)

type Config struct {
	Port              string
	Host              string
	DatabaseURL       string
	JWTSecret         string
	JWTExpiry         time.Duration
	RefreshTokenExpiry time.Duration
	BaseURL           string
	OAuthGoogleID     string
	OAuthGoogleSecret string
	OAuthGitHubID     string
	OAuthGitHubSecret string
	OAuthRedirectBase string
	AppScheme         string
	RateLimitAuth     int
	RateLimitAPI      int
	TrustedProxies    []string
}

func Load() *Config {
	godotenv.Load()

	rateLimitAuth := 10
	rateLimitAPI := 30

	cfg := &Config{
		Port:              getEnv("TERMVAULT_PORT", "8080"),
		Host:              getEnv("TERMVAULT_HOST", "0.0.0.0"),
		DatabaseURL:       getEnv("DATABASE_URL", "sqlite://termvault.db"),
		JWTSecret:         os.Getenv("JWT_SECRET"),
		JWTExpiry:         parseDuration(getEnv("JWT_EXPIRY", "15m")),
		RefreshTokenExpiry: parseDuration(getEnv("REFRESH_TOKEN_EXPIRY", "720h")),
		BaseURL:           getEnv("BASE_URL", "http://localhost:8080"),
		OAuthGoogleID:     os.Getenv("OAUTH_GOOGLE_CLIENT_ID"),
		OAuthGoogleSecret: os.Getenv("OAUTH_GOOGLE_CLIENT_SECRET"),
		OAuthGitHubID:     os.Getenv("OAUTH_GITHUB_CLIENT_ID"),
		OAuthGitHubSecret: os.Getenv("OAUTH_GITHUB_CLIENT_SECRET"),
		OAuthRedirectBase: getEnv("OAUTH_REDIRECT_BASE", getEnv("BASE_URL", "http://localhost:8080")),
		AppScheme:         getEnv("APP_SCHEME", "termvault"),
		RateLimitAuth:     rateLimitAuth,
		RateLimitAPI:      rateLimitAPI,
	}

	if v := os.Getenv("RATE_LIMIT_AUTH"); v != "" {
		if n, err := parseIntSafe(v, 10); err == nil {
			cfg.RateLimitAuth = n
		}
	}
	if v := os.Getenv("RATE_LIMIT_API"); v != "" {
		if n, err := parseIntSafe(v, 30); err == nil {
			cfg.RateLimitAPI = n
		}
	}

	if v := os.Getenv("TRUSTED_PROXIES"); v != "" {
		for _, cidr := range strings.Split(v, ",") {
			cidr = strings.TrimSpace(cidr)
			if cidr != "" {
				cfg.TrustedProxies = append(cfg.TrustedProxies, cidr)
			}
		}
	}

	return cfg
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func parseDuration(s string) time.Duration {
	d, _ := time.ParseDuration(s)
	return d
}

func parseIntSafe(s string, fallback int) (int, error) {
	var n int
	_, err := fmt.Sscanf(s, "%d", &n)
	if err != nil {
		return fallback, err
	}
	return n, nil
}
