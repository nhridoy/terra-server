package auth

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/termvault/termvault/internal/config"
	"github.com/termvault/termvault/internal/models"
	gormsqlite "github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func setupTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(gormsqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to open test db: %v", err)
	}
	if err := models.AutoMigrate(db); err != nil {
		t.Fatalf("failed to migrate: %v", err)
	}
	return db
}

func setupHandlerRouter(db *gorm.DB, cfg *config.Config) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(gin.Recovery())
	auth := r.Group("/api/v1/auth")
	auth.POST("/prelogin", HandlePrelogin(db, cfg))
	auth.POST("/register", HandleRegister(db, cfg))
	auth.POST("/login", HandleLogin(db, cfg))
	auth.POST("/refresh", HandleRefresh(db, cfg))
	auth.POST("/logout", HandleLogout(db))
	auth.POST("/recovery", HandleRecovery(db, cfg))

	protected := r.Group("/api/v1")
	protected.Use(JWTMiddleware(cfg))
	protected.GET("/me", HandleMe(db))
	protected.POST("/auth/password-change", HandlePasswordChange(db, cfg))
	return r
}

func testConfig() *config.Config {
	return &config.Config{
		JWTSecret:         "test-secret-key",
		JWTExpiry:         15 * 60e9,
		RefreshTokenExpiry: 30 * 24 * 60e9,
	}
}

func seedUserWithVerifier(t *testing.T, db *gorm.DB, email string) (uuid.UUID, []byte) {
	t.Helper()
	userID := uuid.New()
	verifier := []byte("test-secret-verifier-bytes")
	verifierB64 := base64.RawStdEncoding.EncodeToString(verifier)
	salt := "test-salt"
	saltCL := "test-salt-cl"
	user := models.User{
		ID:           userID,
		Email:        email,
		Name:         email,
		AuthProvider: "password",
		AuthVerifier: &verifierB64,
		AuthSalt:     &salt,
		SaltCL:       &saltCL,
		KDFM:         67108864,
		KDFT:         3,
		KDFP:         1,
		Initialized:  true,
	}
	if err := db.Create(&user).Error; err != nil {
		t.Fatalf("seed user: %v", err)
	}
	return userID, verifier
}

func makeAccessToken(userID uuid.UUID, cfg *config.Config) string {
	at, _, err := GenerateTokenPair(userID, "", cfg)
	if err != nil {
		panic("makeAccessToken: " + err.Error())
	}
	return at
}

func TestPrelogin_KnownEmail(t *testing.T) {
	db := setupTestDB(t)
	cfg := testConfig()

	salt := "stored-salt"
	saltCL := "stored-salt-cl"
	verifier := "stored-verifier"
	user := models.User{
		ID:           uuid.New(),
		Email:        "alice@example.com",
		Name:         "Alice",
		AuthProvider: "password",
		AuthSalt:     &salt,
		SaltCL:       &saltCL,
		AuthVerifier: &verifier,
		KDFM:         67108864,
		KDFT:         3,
		KDFP:         1,
	}
	if err := db.Create(&user).Error; err != nil {
		t.Fatalf("seed user: %v", err)
	}

	r := setupHandlerRouter(db, cfg)

	body, _ := json.Marshal(gin.H{"email": "alice@example.com"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/prelogin", bytes.NewReader(body))
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

	data, ok := resp["data"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected data object, got %v", resp["data"])
	}

	if data["server_salt"] != salt {
		t.Errorf("server_salt: want %q, got %v", salt, data["server_salt"])
	}
	if data["salt_cl"] != saltCL {
		t.Errorf("salt_cl: want %q, got %v", saltCL, data["salt_cl"])
	}
	if data["nonce"] == nil || data["nonce"] == "" {
		t.Error("nonce should not be empty")
	}

	kdf, ok := data["kdf"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected kdf object, got %v", data["kdf"])
	}
	if int(kdf["m"].(float64)) != 67108864 {
		t.Errorf("kdf.m: want 67108864, got %v", kdf["m"])
	}
	if int(kdf["t"].(float64)) != 3 {
		t.Errorf("kdf.t: want 3, got %v", kdf["t"])
	}
	if int(kdf["p"].(float64)) != 1 {
		t.Errorf("kdf.p: want 1, got %v", kdf["p"])
	}
}

func TestPrelogin_UnknownEmail(t *testing.T) {
	db := setupTestDB(t)
	cfg := testConfig()
	r := setupHandlerRouter(db, cfg)

	body, _ := json.Marshal(gin.H{"email": "nobody@example.com"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/prelogin", bytes.NewReader(body))
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
	if data["nonce"] == nil || data["nonce"] == "" {
		t.Error("nonce should not be empty (random fallback)")
	}
	if data["server_salt"] == nil || data["server_salt"] == "" {
		t.Error("server_salt should not be empty (random fallback)")
	}
	if data["salt_cl"] == nil || data["salt_cl"] == "" {
		t.Error("salt_cl should not be empty (random fallback)")
	}
	if data["kdf"] == nil {
		t.Error("kdf should not be nil (random fallback)")
	}
}

func TestPrelogin_EmptyBody(t *testing.T) {
	db := setupTestDB(t)
	cfg := testConfig()
	r := setupHandlerRouter(db, cfg)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/prelogin", nil)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestRegister_NewUser(t *testing.T) {
	db := setupTestDB(t)
	cfg := testConfig()
	r := setupHandlerRouter(db, cfg)

	userID := uuid.New()
	body, _ := json.Marshal(gin.H{
		"user_id":          userID.String(),
		"email":            "bob@example.com",
		"password_hash":    "base64-verifier",
		"encrypted_dek":    "base64-dek",
		"encrypted_privkey": "base64-privkey",
		"kdf_m":            67108864,
		"kdf_t":            3,
		"kdf_p":            1,
		"server_salt":      "server-salt",
		"salt_cl":          "client-salt",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
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

	userObj, ok := data["user"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected user object, got %v", data["user"])
	}
	if userObj["email"] != "bob@example.com" {
		t.Errorf("user.email: want bob@example.com, got %v", userObj["email"])
	}
	if userObj["id"] != userID.String() {
		t.Errorf("user.id: want %s, got %v", userID, userObj["id"])
	}

	var vault models.Vault
	if err := db.Where("owner_id = ? AND kind = ?", userID, "personal").First(&vault).Error; err != nil {
		t.Errorf("personal vault not created: %v", err)
	}
}

func TestRegister_ExistingEmail(t *testing.T) {
	db := setupTestDB(t)
	cfg := testConfig()

	salt := "existing-salt"
	saltCL := "existing-salt-cl"
	existing := models.User{
		ID:           uuid.New(),
		Email:        "taken@example.com",
		Name:         "Existing",
		AuthProvider: "password",
		AuthSalt:     &salt,
		SaltCL:       &saltCL,
	}
	if err := db.Create(&existing).Error; err != nil {
		t.Fatalf("seed user: %v", err)
	}

	r := setupHandlerRouter(db, cfg)

	body, _ := json.Marshal(gin.H{
		"user_id":       uuid.New().String(),
		"email":         "taken@example.com",
		"password_hash": "base64-verifier",
		"kdf_m":         67108864,
		"kdf_t":         3,
		"kdf_p":         1,
		"server_salt":   "server-salt",
		"salt_cl":       "client-salt",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d: %s", w.Code, w.Body.String())
	}
}

func TestRegister_Idempotent(t *testing.T) {
	db := setupTestDB(t)
	cfg := testConfig()

	userID := uuid.New()
	salt := "server-salt"
	saltCL := "client-salt"
	existing := models.User{
		ID:           userID,
		Email:        "idempotent@example.com",
		Name:         "Existing",
		AuthProvider: "password",
		AuthSalt:     &salt,
		SaltCL:       &saltCL,
	}
	if err := db.Create(&existing).Error; err != nil {
		t.Fatalf("seed user: %v", err)
	}

	r := setupHandlerRouter(db, cfg)

	body, _ := json.Marshal(gin.H{
		"user_id":       userID.String(),
		"email":         "idempotent@example.com",
		"password_hash": "base64-verifier",
		"kdf_m":         67108864,
		"kdf_t":         3,
		"kdf_p":         1,
		"server_salt":   "new-server-salt",
		"salt_cl":       "new-client-salt",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for idempotent register, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	data := resp["data"].(map[string]interface{})
	if data["access_token"] == nil || data["access_token"] == "" {
		t.Error("access_token should not be empty")
	}
}

func TestRegister_InvalidBody(t *testing.T) {
	db := setupTestDB(t)
	cfg := testConfig()
	r := setupHandlerRouter(db, cfg)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", bytes.NewReader([]byte("not json")))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestLogin_CorrectProof(t *testing.T) {
	db := setupTestDB(t)
	cfg := testConfig()
	r := setupHandlerRouter(db, cfg)

	_, verifier := seedUserWithVerifier(t, db, "alice@example.com")
	nonce := []byte("test-nonce-for-login")
	proof := GenerateProof(verifier, nonce)

	body, _ := json.Marshal(gin.H{
		"email":    "alice@example.com",
		"proof":    base64.RawStdEncoding.EncodeToString(proof),
		"nonce":    base64.RawStdEncoding.EncodeToString(nonce),
		"device_id": "device-1",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(body))
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
	userObj, ok := data["user"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected user object, got %v", data["user"])
	}
	if userObj["email"] != "alice@example.com" {
		t.Errorf("user.email: want alice@example.com, got %v", userObj["email"])
	}
}

func TestLogin_WrongProof(t *testing.T) {
	db := setupTestDB(t)
	cfg := testConfig()
	r := setupHandlerRouter(db, cfg)

	seedUserWithVerifier(t, db, "alice@example.com")
	wrongProof := []byte("wrong-proof-data")
	nonce := []byte("test-nonce")

	body, _ := json.Marshal(gin.H{
		"email": "alice@example.com",
		"proof": base64.RawStdEncoding.EncodeToString(wrongProof),
		"nonce": base64.RawStdEncoding.EncodeToString(nonce),
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", w.Code, w.Body.String())
	}
}

func TestLogin_NonExistentEmail(t *testing.T) {
	db := setupTestDB(t)
	cfg := testConfig()
	r := setupHandlerRouter(db, cfg)

	body, _ := json.Marshal(gin.H{
		"email": "nobody@example.com",
		"proof": "dGVzdA",
		"nonce": "dGVzdA",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", w.Code, w.Body.String())
	}
}

func TestRefresh_ValidToken(t *testing.T) {
	db := setupTestDB(t)
	cfg := testConfig()
	r := setupHandlerRouter(db, cfg)

	uid, _ := seedUserWithVerifier(t, db, "refresh@example.com")
	rtToken, err := createRefreshToken(db, uid, "device-1", cfg)
	if err != nil {
		t.Fatalf("create refresh token: %v", err)
	}

	body, _ := json.Marshal(gin.H{"refresh_token": rtToken})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", bytes.NewReader(body))
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
	if data["refresh_token"] == rtToken {
		t.Error("refresh_token should be rotated (different from old)")
	}
}

func TestRefresh_ExpiredToken(t *testing.T) {
	db := setupTestDB(t)
	cfg := testConfig()
	r := setupHandlerRouter(db, cfg)

	uid, _ := seedUserWithVerifier(t, db, "expired@example.com")
	rawToken := "expired-token-value"
	tokenHash := hashToken(rawToken)
	now := time.Now()
	rt := models.RefreshToken{
		UserID:    uid,
		TokenHash: tokenHash,
		DeviceID:  "device-1",
		ExpiresAt: now.Add(-1 * time.Hour),
	}
	db.Create(&rt)

	body, _ := json.Marshal(gin.H{"refresh_token": rawToken})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", w.Code, w.Body.String())
	}
}

func TestRefresh_ReuseDetection(t *testing.T) {
	db := setupTestDB(t)
	cfg := testConfig()
	r := setupHandlerRouter(db, cfg)

	uid, _ := seedUserWithVerifier(t, db, "reuse@example.com")

	rawToken1 := "token-for-rotation"
	tokenHash1 := hashToken(rawToken1)
	now := time.Now()
	rt1 := models.RefreshToken{
		UserID:    uid,
		TokenHash: tokenHash1,
		DeviceID:  "device-1",
		ExpiresAt: now.Add(24 * time.Hour),
	}
	db.Create(&rt1)

	body, _ := json.Marshal(gin.H{"refresh_token": rawToken1})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("first refresh should succeed: %d: %s", w.Code, w.Body.String())
	}

	body2, _ := json.Marshal(gin.H{"refresh_token": rawToken1})
	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", bytes.NewReader(body2))
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, req2)

	if w2.Code != http.StatusUnauthorized {
		t.Fatalf("reuse should return 401, got %d: %s", w2.Code, w2.Body.String())
	}

	var count int64
	db.Model(&models.RefreshToken{}).Where("user_id = ? AND revoked_at IS NOT NULL", uid).Count(&count)
	if count < 2 {
		t.Errorf("expected at least 2 revoked tokens after reuse, got %d", count)
	}
}

func TestLogout_ValidToken(t *testing.T) {
	db := setupTestDB(t)
	cfg := testConfig()
	r := setupHandlerRouter(db, cfg)

	uid, _ := seedUserWithVerifier(t, db, "logout@example.com")
	rtToken, err := createRefreshToken(db, uid, "device-1", cfg)
	if err != nil {
		t.Fatalf("create refresh token: %v", err)
	}

	body, _ := json.Marshal(gin.H{"refresh_token": rtToken})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", w.Code, w.Body.String())
	}

	tokenHash := hashToken(rtToken)
	var rt models.RefreshToken
	db.Where("token_hash = ?", tokenHash).First(&rt)
	if rt.RevokedAt == nil {
		t.Error("refresh token should be revoked after logout")
	}
}

func TestLogout_InvalidToken(t *testing.T) {
	db := setupTestDB(t)
	cfg := testConfig()
	r := setupHandlerRouter(db, cfg)

	body, _ := json.Marshal(gin.H{"refresh_token": "nonexistent-token"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", w.Code, w.Body.String())
	}
}

func TestMe_ValidToken(t *testing.T) {
	db := setupTestDB(t)
	cfg := testConfig()
	r := setupHandlerRouter(db, cfg)

	uid, _ := seedUserWithVerifier(t, db, "me@example.com")
	token := makeAccessToken(uid, cfg)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
	req.Header.Set("Authorization", "Bearer "+token)
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
	if data["email"] != "me@example.com" {
		t.Errorf("email: want me@example.com, got %v", data["email"])
	}
	if data["id"] != uid.String() {
		t.Errorf("id: want %s, got %v", uid, data["id"])
	}
}

func TestMe_NoToken(t *testing.T) {
	db := setupTestDB(t)
	cfg := testConfig()
	r := setupHandlerRouter(db, cfg)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", w.Code, w.Body.String())
	}
}

func TestPasswordChange_ValidOldProof(t *testing.T) {
	db := setupTestDB(t)
	cfg := testConfig()
	r := setupHandlerRouter(db, cfg)

	uid, verifier := seedUserWithVerifier(t, db, "pwchange@example.com")
	token := makeAccessToken(uid, cfg)

	nonce := []byte("old-nonce-for-pwchange")
	proof := GenerateProof(verifier, nonce)

	body, _ := json.Marshal(gin.H{
		"old_proof":     base64.RawStdEncoding.EncodeToString(proof),
		"old_nonce":     base64.RawStdEncoding.EncodeToString(nonce),
		"new_verifier":  "new-verifier-value",
		"new_server_salt": "new-server-salt",
		"new_salt_cl":   "new-salt-cl",
		"new_kdf_m":     134217728,
		"new_kdf_t":     4,
		"new_kdf_p":     2,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/password-change", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", w.Code, w.Body.String())
	}

	var user models.User
	db.Where("id = ?", uid).First(&user)
	if user.AuthVerifier == nil || *user.AuthVerifier != "new-verifier-value" {
		t.Errorf("verifier not updated: got %v", user.AuthVerifier)
	}
	if user.AuthSalt == nil || *user.AuthSalt != "new-server-salt" {
		t.Errorf("auth_salt not updated: got %v", user.AuthSalt)
	}
	if user.SaltCL == nil || *user.SaltCL != "new-salt-cl" {
		t.Errorf("salt_cl not updated: got %v", user.SaltCL)
	}
	if user.KDFM != 134217728 {
		t.Errorf("kdf_m: want 134217728, got %d", user.KDFM)
	}
	if user.KDFT != 4 {
		t.Errorf("kdf_t: want 4, got %d", user.KDFT)
	}
	if user.KDFP != 2 {
		t.Errorf("kdf_p: want 2, got %d", user.KDFP)
	}
}

func TestPasswordChange_WrongOldProof(t *testing.T) {
	db := setupTestDB(t)
	cfg := testConfig()
	r := setupHandlerRouter(db, cfg)

	uid, _ := seedUserWithVerifier(t, db, "pwchange-wrong@example.com")
	token := makeAccessToken(uid, cfg)

	wrongProof := []byte("completely-wrong-proof")
	nonce := []byte("some-nonce")

	body, _ := json.Marshal(gin.H{
		"old_proof":    base64.RawStdEncoding.EncodeToString(wrongProof),
		"old_nonce":    base64.RawStdEncoding.EncodeToString(nonce),
		"new_verifier": "new-verifier-value",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/password-change", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", w.Code, w.Body.String())
	}
}

func TestPasswordChange_RevokesOtherSessions(t *testing.T) {
	db := setupTestDB(t)
	cfg := testConfig()
	r := setupHandlerRouter(db, cfg)

	uid, verifier := seedUserWithVerifier(t, db, "pwchange-revoke@example.com")

	rt1, _ := createRefreshToken(db, uid, "device-1", cfg)
	rt2, _ := createRefreshToken(db, uid, "device-2", cfg)

	token := makeAccessToken(uid, cfg)
	nonce := []byte("revoke-nonce")
	proof := GenerateProof(verifier, nonce)

	body, _ := json.Marshal(gin.H{
		"old_proof":    base64.RawStdEncoding.EncodeToString(proof),
		"old_nonce":    base64.RawStdEncoding.EncodeToString(nonce),
		"new_verifier": "updated-verifier",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/password-change", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", w.Code, w.Body.String())
	}

	var revokedCount int64
	db.Model(&models.RefreshToken{}).Where("user_id = ? AND revoked_at IS NOT NULL", uid).Count(&revokedCount)
	if revokedCount < 2 {
		t.Errorf("expected at least 2 revoked tokens after password change, got %d", revokedCount)
	}

	for _, rtRaw := range []string{rt1, rt2} {
		h := hashToken(rtRaw)
		var rt models.RefreshToken
		db.Where("token_hash = ?", h).First(&rt)
		if rt.RevokedAt == nil {
			t.Errorf("token %s should be revoked", rtRaw[:8])
		}
	}
}

func TestPasswordChange_NoToken(t *testing.T) {
	db := setupTestDB(t)
	cfg := testConfig()
	r := setupHandlerRouter(db, cfg)

	body, _ := json.Marshal(gin.H{
		"old_proof":    "dGVzdA",
		"old_nonce":    "dGVzdA",
		"new_verifier": "new-v",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/password-change", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", w.Code, w.Body.String())
	}
}

func TestRecovery_ValidSignature(t *testing.T) {
	db := setupTestDB(t)
	cfg := testConfig()
	r := setupHandlerRouter(db, cfg)

	uid, _ := seedUserWithVerifier(t, db, "recovery@example.com")
	recoveryCode := "my-secret-recovery-code"
	codeHash := sha256.Sum256([]byte(recoveryCode))
	codeHashB64 := base64.RawStdEncoding.EncodeToString(codeHash[:])
	db.Model(&models.User{}).Where("id = ?", uid).Update("recovery_hash", codeHashB64)

	body, _ := json.Marshal(gin.H{
		"recovery_code": base64.RawStdEncoding.EncodeToString([]byte(recoveryCode)),
		"signature":     base64.RawStdEncoding.EncodeToString([]byte("valid-sig")),
		"new_verifier":  "recovered-verifier",
		"new_server_salt": "recovered-salt",
		"new_salt_cl":   "recovered-salt-cl",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/recovery", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", w.Code, w.Body.String())
	}

	var user models.User
	db.Where("id = ?", uid).First(&user)
	if user.AuthVerifier == nil || *user.AuthVerifier != "recovered-verifier" {
		t.Errorf("verifier not updated: got %v", user.AuthVerifier)
	}
	if user.RecoveryHash != nil {
		t.Errorf("recovery_hash should be cleared after use, got %v", user.RecoveryHash)
	}
}

func TestRecovery_InvalidCode(t *testing.T) {
	db := setupTestDB(t)
	cfg := testConfig()
	r := setupHandlerRouter(db, cfg)

	uid, _ := seedUserWithVerifier(t, db, "recovery-invalid@example.com")
	realCode := "real-recovery-code"
	codeHash := sha256.Sum256([]byte(realCode))
	codeHashB64 := base64.RawStdEncoding.EncodeToString(codeHash[:])
	db.Model(&models.User{}).Where("id = ?", uid).Update("recovery_hash", codeHashB64)

	wrongCode := base64.RawStdEncoding.EncodeToString([]byte("wrong-recovery-code"))
	body, _ := json.Marshal(gin.H{
		"recovery_code": wrongCode,
		"signature":     base64.RawStdEncoding.EncodeToString([]byte("some-sig")),
		"new_verifier":  "new-v",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/recovery", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", w.Code, w.Body.String())
	}
}

func TestRecovery_InvalidSignature(t *testing.T) {
	db := setupTestDB(t)
	cfg := testConfig()
	r := setupHandlerRouter(db, cfg)

	uid, _ := seedUserWithVerifier(t, db, "recovery-sig@example.com")
	recoveryCode := "valid-code"
	codeHash := sha256.Sum256([]byte(recoveryCode))
	codeHashB64 := base64.RawStdEncoding.EncodeToString(codeHash[:])
	db.Model(&models.User{}).Where("id = ?", uid).Update("recovery_hash", codeHashB64)

	body, _ := json.Marshal(gin.H{
		"recovery_code": base64.RawStdEncoding.EncodeToString([]byte(recoveryCode)),
		"signature":     base64.RawStdEncoding.EncodeToString([]byte("x")),
		"new_verifier":  "new-v",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/recovery", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", w.Code, w.Body.String())
	}
}

func TestRecovery_ReplacesKeyring(t *testing.T) {
	db := setupTestDB(t)
	cfg := testConfig()
	r := setupHandlerRouter(db, cfg)

	uid, _ := seedUserWithVerifier(t, db, "recovery-keyring@example.com")
	recoveryCode := "keyring-recovery"
	codeHash := sha256.Sum256([]byte(recoveryCode))
	codeHashB64 := base64.RawStdEncoding.EncodeToString(codeHash[:])
	db.Model(&models.User{}).Where("id = ?", uid).Update("recovery_hash", codeHashB64)

	db.Create(&models.UserKey{
		UserID:  uid,
		KeyType: "dek",
		Payload: "old-dek-payload",
	})

	body, _ := json.Marshal(gin.H{
		"recovery_code":    base64.RawStdEncoding.EncodeToString([]byte(recoveryCode)),
		"signature":        base64.RawStdEncoding.EncodeToString([]byte("sig")),
		"new_verifier":     "recovered-v",
		"new_encrypted_dek": "new-dek-payload",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/recovery", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", w.Code, w.Body.String())
	}

	var uk models.UserKey
	if db.Where("user_id = ? AND key_type = ?", uid, "dek").First(&uk).Error != nil {
		t.Fatal("dek key should exist after recovery")
	}
	if uk.Payload != "new-dek-payload" {
		t.Errorf("dek payload: want new-dek-payload, got %s", uk.Payload)
	}
}

func TestRecovery_RevokesAllSessions(t *testing.T) {
	db := setupTestDB(t)
	cfg := testConfig()
	r := setupHandlerRouter(db, cfg)

	uid, _ := seedUserWithVerifier(t, db, "recovery-revoke@example.com")
	recoveryCode := "revoke-all-code"
	codeHash := sha256.Sum256([]byte(recoveryCode))
	codeHashB64 := base64.RawStdEncoding.EncodeToString(codeHash[:])
	db.Model(&models.User{}).Where("id = ?", uid).Update("recovery_hash", codeHashB64)

	createRefreshToken(db, uid, "device-1", cfg)
	createRefreshToken(db, uid, "device-2", cfg)

	body, _ := json.Marshal(gin.H{
		"recovery_code": base64.RawStdEncoding.EncodeToString([]byte(recoveryCode)),
		"signature":     base64.RawStdEncoding.EncodeToString([]byte("sig")),
		"new_verifier":  "recovered-v",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/recovery", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", w.Code, w.Body.String())
	}

	var activeCount int64
	db.Model(&models.RefreshToken{}).Where("user_id = ? AND revoked_at IS NULL", uid).Count(&activeCount)
	if activeCount != 0 {
		t.Errorf("expected 0 active tokens after recovery, got %d", activeCount)
	}
}
