package config

import (
	"os"
	"strconv"
)

type Config struct {
	Port    string
	Host    string
	DBUrl   string
	JWTSecret string
	JWTExpiry string

	// OAuth
	OAuthGitHubClientID     string
	OAuthGitHubClientSecret string
	OAuthGoogleClientID     string
	OAuthGoogleClientSecret string
	OAuthGitLabClientID     string
	OAuthGitLabClientSecret string
	OAuthMicrosoftClientID  string
	OAuthMicrosoftClientSecret string
	OAuthBitbucketClientID  string
	OAuthBitbucketClientSecret string

	// OAuth callback URLs
	BaseURL string
}

var AppConfig *Config

func Load() *Config {
	AppConfig = &Config{
		Port:    getEnv("TERMVAULT_PORT", "8080"),
		Host:    getEnv("TERMVAULT_HOST", "0.0.0.0"),
		DBUrl:   getEnv("DATABASE_URL", "sqlite://termvault.db?cache=shared&_journal_mode=WAL"),
		JWTSecret: getEnv("JWT_SECRET", "change-me-in-production"),
		JWTExpiry: getEnv("JWT_EXPIRY", "24h"),

		OAuthGitHubClientID:     getEnv("OAUTH_GITHUB_CLIENT_ID", ""),
		OAuthGitHubClientSecret: getEnv("OAUTH_GITHUB_CLIENT_SECRET", ""),
		OAuthGoogleClientID:     getEnv("OAUTH_GOOGLE_CLIENT_ID", ""),
		OAuthGoogleClientSecret: getEnv("OAUTH_GOOGLE_CLIENT_SECRET", ""),
		OAuthGitLabClientID:     getEnv("OAUTH_GITLAB_CLIENT_ID", ""),
		OAuthGitLabClientSecret: getEnv("OAUTH_GITLAB_CLIENT_SECRET", ""),
		OAuthMicrosoftClientID:  getEnv("OAUTH_MICROSOFT_CLIENT_ID", ""),
		OAuthMicrosoftClientSecret: getEnv("OAUTH_MICROSOFT_CLIENT_SECRET", ""),
		OAuthBitbucketClientID:  getEnv("OAUTH_BITBUCKET_CLIENT_ID", ""),
		OAuthBitbucketClientSecret: getEnv("OAUTH_BITBUCKET_CLIENT_SECRET", ""),

		BaseURL: getEnv("BASE_URL", "http://localhost:8080"),
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
		if intVal, err := strconv.Atoi(value); err == nil {
			return intVal
		}
	}
	return defaultValue
}

func getEnvBool(key string, defaultValue bool) bool {
	if value, exists := os.LookupEnv(key); exists {
		if boolVal, err := strconv.ParseBool(value); err == nil {
			return boolVal
		}
	}
	return defaultValue
}
