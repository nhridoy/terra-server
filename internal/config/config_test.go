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
	if cfg.RequireEmailVerification {
		t.Errorf("expected email verification off by default")
	}
	if cfg.SMTPPort != 587 {
		t.Errorf("expected default SMTP port 587, got %d", cfg.SMTPPort)
	}
	if len(cfg.CORSAllowedOrigins) != 4 {
		t.Errorf("expected 4 default CORS origins, got %d: %v", len(cfg.CORSAllowedOrigins), cfg.CORSAllowedOrigins)
	}
}

func TestLoadCORSAllowedOrigins(t *testing.T) {
	os.Setenv("CORS_ALLOWED_ORIGINS", "https://app.example.com, https://admin.example.com")
	defer os.Unsetenv("CORS_ALLOWED_ORIGINS")

	cfg := Load()

	if len(cfg.CORSAllowedOrigins) != 2 {
		t.Fatalf("expected 2 CORS origins, got %d: %v", len(cfg.CORSAllowedOrigins), cfg.CORSAllowedOrigins)
	}
	if cfg.CORSAllowedOrigins[0] != "https://app.example.com" {
		t.Errorf("expected first origin https://app.example.com, got %s", cfg.CORSAllowedOrigins[0])
	}
	if cfg.CORSAllowedOrigins[1] != "https://admin.example.com" {
		t.Errorf("expected second origin https://admin.example.com, got %s", cfg.CORSAllowedOrigins[1])
	}
}

func TestLoadEmailVerificationToggle(t *testing.T) {
	cases := []struct {
		val  string
		want bool
	}{
		{"true", true}, {"TRUE", true}, {"1", true}, {"yes", true},
		{"false", false}, {"0", false}, {"", false}, {"banana", false},
	}
	for _, c := range cases {
		os.Setenv("REQUIRE_EMAIL_VERIFICATION", c.val)
		cfg := Load()
		if cfg.RequireEmailVerification != c.want {
			t.Errorf("REQUIRE_EMAIL_VERIFICATION=%q: got %v want %v", c.val, cfg.RequireEmailVerification, c.want)
		}
	}
	os.Unsetenv("REQUIRE_EMAIL_VERIFICATION")
}

func TestLoadLogOtpFallbackToggle(t *testing.T) {
	cases := []struct {
		val  string
		want bool
	}{
		{"true", true}, {"TRUE", true}, {"1", true}, {"yes", true},
		{"false", false}, {"0", false}, {"", false}, {"banana", false},
	}
	for _, c := range cases {
		os.Setenv("LOG_OTP_FALLBACK", c.val)
		cfg := Load()
		if cfg.LogOtpFallback != c.want {
			t.Errorf("LOG_OTP_FALLBACK=%q: got %v want %v", c.val, cfg.LogOtpFallback, c.want)
		}
	}
	os.Unsetenv("LOG_OTP_FALLBACK")
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
