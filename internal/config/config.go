package config

import (
	"os"
	"strconv"
	"strings"
)

type Config struct {
	Port              string
	Host              string
	DBUrl             string
	JWTSecret         string
	JWTExpiry         string
	RefreshTokenExpiry string
	BaseURL           string
	AllowedOrigins    []string
	TrustedProxies    []string
	RateLimitAuth     int
	RateLimitAPI      int
}

var AppConfig *Config

func Load() *Config {
	allowedOrigins := getEnv("ALLOWED_ORIGINS", "http://localhost:1420,http://localhost:5173,tauri://localhost,https://tauri.localhost")
	trustedProxies := getEnv("TRUSTED_PROXIES", "")
	rateLimitAuth := getEnvInt("RATE_LIMIT_AUTH", 10)
	rateLimitAPI := getEnvInt("RATE_LIMIT_API", 30)

	AppConfig = &Config{
		Port:              getEnv("TERMVAULT_PORT", "8080"),
		Host:              getEnv("TERMVAULT_HOST", "0.0.0.0"),
		DBUrl:             getEnv("DATABASE_URL", "sqlite://termvault.db?cache=shared&_journal_mode=WAL"),
		JWTSecret:         getEnv("JWT_SECRET", "change-me-in-production"),
		JWTExpiry:         getEnv("JWT_EXPIRY", "24h"),
		RefreshTokenExpiry: getEnv("REFRESH_TOKEN_EXPIRY", "720h"),
		BaseURL:           getEnv("BASE_URL", "http://localhost:8080"),
		AllowedOrigins:    strings.Split(allowedOrigins, ","),
		TrustedProxies:    splitNonEmpty(trustedProxies, ","),
		RateLimitAuth:     rateLimitAuth,
		RateLimitAPI:      rateLimitAPI,
	}

	return AppConfig
}

func getEnv(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultValue
}

func getEnvInt(key string, defaultValue int) int {
	if value, exists := os.LookupEnv(key); exists {
		if parsed, err := strconv.Atoi(value); err == nil && parsed > 0 {
			return parsed
		}
	}
	return defaultValue
}

func splitNonEmpty(s, sep string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, sep)
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		trimmed := strings.TrimSpace(p)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	if len(result) == 0 {
		return nil
	}
	return result
}
