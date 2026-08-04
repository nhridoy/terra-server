package config

import (
	"os"
	"testing"
)

func TestLoadDefaults(t *testing.T) {
	cfg := Load()

	if cfg.Port != "8080" {
		t.Errorf("expected default port 8080, got %s", cfg.Port)
	}
	if cfg.Host != "0.0.0.0" {
		t.Errorf("expected default host 0.0.0.0, got %s", cfg.Host)
	}
	if cfg.DatabaseURL != "sqlite://termvault.db" {
		t.Errorf("expected default database URL, got %s", cfg.DatabaseURL)
	}
	if cfg.RateLimitAuth != 10 {
		t.Errorf("expected default rate limit auth 10, got %d", cfg.RateLimitAuth)
	}
	if cfg.RateLimitAPI != 30 {
		t.Errorf("expected default rate limit API 30, got %d", cfg.RateLimitAPI)
	}
}

func TestLoadEnvOverrides(t *testing.T) {
	os.Setenv("TERMVAULT_PORT", "9090")
	os.Setenv("TERMVAULT_HOST", "127.0.0.1")
	os.Setenv("RATE_LIMIT_AUTH", "20")
	os.Setenv("RATE_LIMIT_API", "50")
	os.Setenv("TRUSTED_PROXIES", "10.0.0.0/8, 172.16.0.0/12")
	defer os.Unsetenv("TERMVAULT_PORT")
	defer os.Unsetenv("TERMVAULT_HOST")
	defer os.Unsetenv("RATE_LIMIT_AUTH")
	defer os.Unsetenv("RATE_LIMIT_API")
	defer os.Unsetenv("TRUSTED_PROXIES")

	cfg := Load()

	if cfg.Port != "9090" {
		t.Errorf("expected port 9090, got %s", cfg.Port)
	}
	if cfg.Host != "127.0.0.1" {
		t.Errorf("expected host 127.0.0.1, got %s", cfg.Host)
	}
	if cfg.RateLimitAuth != 20 {
		t.Errorf("expected rate limit auth 20, got %d", cfg.RateLimitAuth)
	}
	if cfg.RateLimitAPI != 50 {
		t.Errorf("expected rate limit API 50, got %d", cfg.RateLimitAPI)
	}
	if len(cfg.TrustedProxies) != 2 {
		t.Errorf("expected 2 trusted proxies, got %d", len(cfg.TrustedProxies))
	}
}
