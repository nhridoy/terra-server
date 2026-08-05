package auth

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/termvault/termvault/internal/config"
	"github.com/termvault/termvault/internal/models"
	"gorm.io/gorm"
)

func oauthTestConfig() *config.Config {
	return &config.Config{
		JWTSecret:         "test-secret-key",
		JWTExpiry:         15 * 60e9,
		RefreshTokenExpiry: 30 * 24 * 60e9,
		OAuthGoogleID:     "google-client-id",
		OAuthGoogleSecret: "google-client-secret",
		OAuthGitHubID:     "github-client-id",
		OAuthGitHubSecret: "github-client-secret",
		OAuthRedirectBase: "http://localhost:8080",
		AppScheme:         "termvault",
	}
}

func oauthRouter(db *gorm.DB, cfg *config.Config) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(gin.Recovery())

	apiAuth := r.Group("/api/v1/auth")
	apiAuth.GET("/oauth/start/:provider", HandleOAuthStart(db, cfg))
	apiAuth.GET("/oauth/callback/:provider", HandleOAuthCallback(db, cfg))
	apiAuth.POST("/oauth/exchange", HandleOAuthExchange(db, cfg))
	apiAuth.POST("/oauth/setup", HandleOAuthSetup(db, cfg))
	return r
}

func seedOAuthState(t *testing.T, db *gorm.DB, state, provider, codeVerifier, deviceID string, expiresAt time.Time, usedAt *time.Time) {
	t.Helper()
	os := models.OAuthState{
		State:        state,
		Provider:     provider,
		CodeVerifier: codeVerifier,
		DeviceID:     deviceID,
		ExpiresAt:    expiresAt,
		UsedAt:       usedAt,
	}
	if err := db.Create(&os).Error; err != nil {
		t.Fatalf("seed OAuth state: %v", err)
	}
}

func seedAuthCode(t *testing.T, db *gorm.DB, code, purpose string, userID uuid.UUID, deviceID string, expiresAt time.Time, usedAt *time.Time) {
	t.Helper()
	codeHash := hashToken(code)
	ac := models.AuthCode{
		CodeHash:  codeHash,
		Purpose:   purpose,
		UserID:    userID,
		DeviceID:  deviceID,
		ExpiresAt: expiresAt,
		UsedAt:    usedAt,
	}
	if err := db.Create(&ac).Error; err != nil {
		t.Fatalf("seed auth code: %v", err)
	}
}

func seedOAuthUser(t *testing.T, db *gorm.DB, provider, providerSub, email string, initialized bool) uuid.UUID {
	t.Helper()
	userID := uuid.New()
	user := models.User{
		ID:           userID,
		Email:        email,
		FullName:     email,
		AuthProvider: provider,
		ProviderSub:  &providerSub,
		Initialized:  initialized,
	}
	if err := db.Create(&user).Error; err != nil {
		t.Fatalf("seed OAuth user: %v", err)
	}
	return userID
}

func TestOAuthStart_ValidGoogle(t *testing.T) {
	db := setupTestDB(t)
	cfg := oauthTestConfig()
	r := oauthRouter(db, cfg)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/oauth/start/google", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d: %s", w.Code, w.Body.String())
	}

	location := w.Header().Get("Location")
	if location == "" {
		t.Fatal("expected Location header")
	}
	if !contains(location, "accounts.google.com") {
		t.Errorf("expected Google auth URL, got: %s", location)
	}
	if !contains(location, "code_challenge=") {
		t.Errorf("expected code_challenge in URL, got: %s", location)
	}
	if !contains(location, "code_challenge_method=S256") {
		t.Errorf("expected code_challenge_method=S256 in URL, got: %s", location)
	}

	var count int64
	db.Model(&models.OAuthState{}).Count(&count)
	if count != 1 {
		t.Errorf("expected 1 OAuth state, got %d", count)
	}
}

func TestOAuthStart_ValidGitHub(t *testing.T) {
	db := setupTestDB(t)
	cfg := oauthTestConfig()
	r := oauthRouter(db, cfg)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/oauth/start/github", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d: %s", w.Code, w.Body.String())
	}

	location := w.Header().Get("Location")
	if !contains(location, "github.com") {
		t.Errorf("expected GitHub auth URL, got: %s", location)
	}
}

func TestOAuthStart_UnknownProvider(t *testing.T) {
	db := setupTestDB(t)
	cfg := oauthTestConfig()
	r := oauthRouter(db, cfg)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/oauth/start/facebook", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestOAuthStart_StoresDeviceID(t *testing.T) {
	db := setupTestDB(t)
	cfg := oauthTestConfig()
	r := oauthRouter(db, cfg)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/oauth/start/google?device_id=my-device", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d: %s", w.Code, w.Body.String())
	}

	var os models.OAuthState
	db.Where("provider = ?", "google").First(&os)
	if os.DeviceID != "my-device" {
		t.Errorf("expected device_id 'my-device', got '%s'", os.DeviceID)
	}
}

func TestOAuthCallback_InvalidState(t *testing.T) {
	db := setupTestDB(t)
	cfg := oauthTestConfig()
	r := oauthRouter(db, cfg)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/oauth/callback/google?code=abc&state=nonexistent", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d: %s", w.Code, w.Body.String())
	}

	location := w.Header().Get("Location")
	if !contains(location, "auth/error") {
		t.Errorf("expected error redirect, got: %s", location)
	}
	if !contains(location, "invalid_state") {
		t.Errorf("expected invalid_state in redirect, got: %s", location)
	}
}

func TestOAuthCallback_UsedState(t *testing.T) {
	db := setupTestDB(t)
	cfg := oauthTestConfig()
	r := oauthRouter(db, cfg)

	usedAt := time.Now()
	seedOAuthState(t, db, "used-state", "google", "verifier", "dev1", time.Now().Add(10*time.Minute), &usedAt)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/oauth/callback/google?code=abc&state=used-state", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", w.Code)
	}

	location := w.Header().Get("Location")
	if !contains(location, "state_already_used") {
		t.Errorf("expected state_already_used, got: %s", location)
	}
}

func TestOAuthCallback_ExpiredState(t *testing.T) {
	db := setupTestDB(t)
	cfg := oauthTestConfig()
	r := oauthRouter(db, cfg)

	seedOAuthState(t, db, "expired-state", "google", "verifier", "dev1", time.Now().Add(-1*time.Hour), nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/oauth/callback/google?code=abc&state=expired-state", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", w.Code)
	}

	location := w.Header().Get("Location")
	if !contains(location, "state_expired") {
		t.Errorf("expected state_expired, got: %s", location)
	}
}

func TestOAuthCallback_MissingCode(t *testing.T) {
	db := setupTestDB(t)
	cfg := oauthTestConfig()
	r := oauthRouter(db, cfg)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/oauth/callback/google?state=abc", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", w.Code)
	}

	location := w.Header().Get("Location")
	if !contains(location, "missing_code_or_state") {
		t.Errorf("expected missing_code_or_state, got: %s", location)
	}
}

func TestOAuthCallback_MissingState(t *testing.T) {
	db := setupTestDB(t)
	cfg := oauthTestConfig()
	r := oauthRouter(db, cfg)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/oauth/callback/google?code=abc", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", w.Code)
	}

	location := w.Header().Get("Location")
	if !contains(location, "missing_code_or_state") {
		t.Errorf("expected missing_code_or_state, got: %s", location)
	}
}

func TestOAuthExchange_ValidCode(t *testing.T) {
	db := setupTestDB(t)
	cfg := oauthTestConfig()
	r := oauthRouter(db, cfg)

	uid := seedOAuthUser(t, db, "google", "12345", "exchange@example.com", false)
	seedAuthCode(t, db, "valid-exchange-code", "oauth_setup", uid, "dev1", time.Now().Add(15*time.Minute), nil)

	body, _ := json.Marshal(gin.H{
		"setup_code": "valid-exchange-code",
		"user_id":    uid.String(),
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/oauth/exchange", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	data := resp["data"].(map[string]interface{})
	if data["access_token"] == nil || data["access_token"] == "" {
		t.Error("access_token should not be empty")
	}
	if data["refresh_token"] == nil || data["refresh_token"] == "" {
		t.Error("refresh_token should not be empty")
	}
	if data["initialized"] != false {
		t.Error("expected initialized=false for new OAuth user")
	}

	var ac models.AuthCode
	codeHash := hashToken("valid-exchange-code")
	db.Where("code_hash = ?", codeHash).First(&ac)
	if ac.UsedAt == nil {
		t.Error("setup code should be marked as used")
	}
}

func TestOAuthExchange_ExpiredCode(t *testing.T) {
	db := setupTestDB(t)
	cfg := oauthTestConfig()
	r := oauthRouter(db, cfg)

	uid := seedOAuthUser(t, db, "google", "12345", "expired-exchange@example.com", false)
	seedAuthCode(t, db, "expired-exchange-code", "oauth_setup", uid, "dev1", time.Now().Add(-1*time.Hour), nil)

	body, _ := json.Marshal(gin.H{
		"setup_code": "expired-exchange-code",
		"user_id":    uid.String(),
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/oauth/exchange", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", w.Code, w.Body.String())
	}
}

func TestOAuthExchange_UsedCode(t *testing.T) {
	db := setupTestDB(t)
	cfg := oauthTestConfig()
	r := oauthRouter(db, cfg)

	uid := seedOAuthUser(t, db, "google", "12345", "used-exchange@example.com", false)
	usedAt := time.Now()
	seedAuthCode(t, db, "used-exchange-code", "oauth_setup", uid, "dev1", time.Now().Add(15*time.Minute), &usedAt)

	body, _ := json.Marshal(gin.H{
		"setup_code": "used-exchange-code",
		"user_id":    uid.String(),
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/oauth/exchange", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", w.Code, w.Body.String())
	}
}

func TestOAuthExchange_InvalidCode(t *testing.T) {
	db := setupTestDB(t)
	cfg := oauthTestConfig()
	r := oauthRouter(db, cfg)

	body, _ := json.Marshal(gin.H{
		"setup_code": "nonexistent-code",
		"user_id":    uuid.New().String(),
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/oauth/exchange", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", w.Code, w.Body.String())
	}
}

func TestOAuthSetup_ValidSetupToken(t *testing.T) {
	db := setupTestDB(t)
	cfg := oauthTestConfig()
	r := oauthRouter(db, cfg)

	uid := seedOAuthUser(t, db, "google", "12345", "setup@example.com", false)
	seedAuthCode(t, db, "valid-setup-token", "oauth_setup", uid, "dev1", time.Now().Add(15*time.Minute), nil)

	body, _ := json.Marshal(gin.H{
		"setup_token":       "valid-setup-token",
		"encrypted_dek":     "base64-dek",
		"encrypted_privkey": "base64-privkey",
		"auth_verifier":     "new-verifier",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/oauth/setup", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	data := resp["data"].(map[string]interface{})
	if data["access_token"] == nil || data["access_token"] == "" {
		t.Error("access_token should not be empty")
	}
	if data["refresh_token"] == nil || data["refresh_token"] == "" {
		t.Error("refresh_token should not be empty")
	}

	var user models.User
	db.Where("id = ?", uid).First(&user)
	if !user.Initialized {
		t.Error("user should be initialized after setup")
	}
	if user.AuthVerifier == nil || *user.AuthVerifier != "new-verifier" {
		t.Error("auth_verifier should be set")
	}

	var dek models.UserKey
	if db.Where("user_id = ? AND key_type = ?", uid, "dek").First(&dek).Error != nil {
		t.Error("DEK key should be created")
	} else if dek.Payload != "base64-dek" {
		t.Errorf("DEK payload: want base64-dek, got %s", dek.Payload)
	}

	var pk models.UserKey
	if db.Where("user_id = ? AND key_type = ?", uid, "privkey").First(&pk).Error != nil {
		t.Error("privkey should be created")
	} else if pk.Payload != "base64-privkey" {
		t.Errorf("privkey payload: want base64-privkey, got %s", pk.Payload)
	}
}

func TestOAuthSetup_ExpiredToken(t *testing.T) {
	db := setupTestDB(t)
	cfg := oauthTestConfig()
	r := oauthRouter(db, cfg)

	uid := seedOAuthUser(t, db, "google", "12345", "expired-setup@example.com", false)
	seedAuthCode(t, db, "expired-setup-token", "oauth_setup", uid, "dev1", time.Now().Add(-1*time.Hour), nil)

	body, _ := json.Marshal(gin.H{
		"setup_token":   "expired-setup-token",
		"encrypted_dek": "base64-dek",
		"auth_verifier": "new-verifier",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/oauth/setup", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", w.Code, w.Body.String())
	}
}

func TestOAuthSetup_AlreadyInitialized(t *testing.T) {
	db := setupTestDB(t)
	cfg := oauthTestConfig()
	r := oauthRouter(db, cfg)

	uid := seedOAuthUser(t, db, "google", "12345", "init-setup@example.com", true)
	seedAuthCode(t, db, "init-setup-token", "oauth_setup", uid, "dev1", time.Now().Add(15*time.Minute), nil)

	body, _ := json.Marshal(gin.H{
		"setup_token":   "init-setup-token",
		"encrypted_dek": "base64-dek",
		"auth_verifier": "new-verifier",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/oauth/setup", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d: %s", w.Code, w.Body.String())
	}
}

func TestOAuthSetup_UsedToken(t *testing.T) {
	db := setupTestDB(t)
	cfg := oauthTestConfig()
	r := oauthRouter(db, cfg)

	uid := seedOAuthUser(t, db, "google", "12345", "used-setup@example.com", false)
	usedAt := time.Now()
	seedAuthCode(t, db, "used-setup-token", "oauth_setup", uid, "dev1", time.Now().Add(15*time.Minute), &usedAt)

	body, _ := json.Marshal(gin.H{
		"setup_token":   "used-setup-token",
		"encrypted_dek": "base64-dek",
		"auth_verifier": "new-verifier",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/oauth/setup", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", w.Code, w.Body.String())
	}
}

func TestOAuthSetup_NoPrivkey(t *testing.T) {
	db := setupTestDB(t)
	cfg := oauthTestConfig()
	r := oauthRouter(db, cfg)

	uid := seedOAuthUser(t, db, "google", "12345", "no-privkey-setup@example.com", false)
	seedAuthCode(t, db, "no-privkey-token", "oauth_setup", uid, "dev1", time.Now().Add(15*time.Minute), nil)

	body, _ := json.Marshal(gin.H{
		"setup_token":   "no-privkey-token",
		"encrypted_dek": "base64-dek",
		"auth_verifier": "new-verifier",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/oauth/setup", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var count int64
	db.Model(&models.UserKey{}).Where("user_id = ? AND key_type = ?", uid, "privkey").Count(&count)
	if count != 0 {
		t.Error("no privkey should be created when not provided")
	}
}

func TestOAuthSetup_InvalidToken(t *testing.T) {
	db := setupTestDB(t)
	cfg := oauthTestConfig()
	r := oauthRouter(db, cfg)

	body, _ := json.Marshal(gin.H{
		"setup_token":   "nonexistent-token",
		"encrypted_dek": "base64-dek",
		"auth_verifier": "new-verifier",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/oauth/setup", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", w.Code, w.Body.String())
	}
}

func TestOAuthSetup_EmptyBody(t *testing.T) {
	db := setupTestDB(t)
	cfg := oauthTestConfig()
	r := oauthRouter(db, cfg)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/oauth/setup", bytes.NewReader([]byte("{}")))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestOAuthExchange_EmptyBody(t *testing.T) {
	db := setupTestDB(t)
	cfg := oauthTestConfig()
	r := oauthRouter(db, cfg)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/oauth/exchange", bytes.NewReader([]byte("{}")))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func contains(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
