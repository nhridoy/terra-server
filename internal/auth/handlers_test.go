package auth

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

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
	return r
}

func testConfig() *config.Config {
	return &config.Config{
		JWTSecret:         "test-secret-key",
		JWTExpiry:         15 * 60e9,
		RefreshTokenExpiry: 30 * 24 * 60e9,
	}
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
		"user_id":         userID.String(),
		"email":           "bob@example.com",
		"password_hash":   "base64-verifier",
		"encrypted_dek":   "base64-dek",
		"encrypted_privkey": "base64-privkey",
		"kdf_m":           67108864,
		"kdf_t":           3,
		"kdf_p":           1,
		"server_salt":     "server-salt",
		"salt_cl":         "client-salt",
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
		"user_id":         uuid.New().String(),
		"email":           "taken@example.com",
		"password_hash":   "base64-verifier",
		"kdf_m":           67108864,
		"kdf_t":           3,
		"kdf_p":           1,
		"server_salt":     "server-salt",
		"salt_cl":         "client-salt",
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
		"user_id":         userID.String(),
		"email":           "idempotent@example.com",
		"password_hash":   "base64-verifier",
		"kdf_m":           67108864,
		"kdf_t":           3,
		"kdf_p":           1,
		"server_salt":     "new-server-salt",
		"salt_cl":         "new-client-salt",
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
