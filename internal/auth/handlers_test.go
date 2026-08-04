package auth

import (
	"bytes"
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

	protected := r.Group("/api/v1")
	protected.Use(JWTMiddleware(cfg))
	protected.GET("/me", HandleMe(db))
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
