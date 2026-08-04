package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/termvault/termvault/internal/config"
	"github.com/termvault/termvault/internal/models"
	"gorm.io/gorm"
)

type preloginRequest struct {
	Email string `json:"email" binding:"required"`
}

type registerRequest struct {
	UserID           string `json:"user_id" binding:"required"`
	Email            string `json:"email" binding:"required"`
	PasswordHash     string `json:"password_hash" binding:"required"`
	EncryptedDEK     string `json:"encrypted_dek"`
	EncryptedPrivkey string `json:"encrypted_privkey"`
	KDFM             int    `json:"kdf_m"`
	KDFT             int    `json:"kdf_t"`
	KDFP             int    `json:"kdf_p"`
	ServerSalt       string `json:"server_salt" binding:"required"`
	SaltCL           string `json:"salt_cl" binding:"required"`
}

func HandlePrelogin(db *gorm.DB, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req preloginRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			Error(c, http.StatusBadRequest, "VALIDATION_ERROR", "email is required")
			return
		}

		var user models.User
		found := db.Where("email = ?", req.Email).First(&user).Error == nil

		if found {
			kdf := map[string]interface{}{
				"m": user.KDFM,
				"t": user.KDFT,
				"p": user.KDFP,
			}
			nonce := randBytes(32)
			Success(c, http.StatusOK, gin.H{
				"nonce":       nonce,
				"kdf":         kdf,
				"server_salt": deref(user.AuthSalt),
				"salt_cl":     deref(user.SaltCL),
			})
			return
		}

		kdf := map[string]interface{}{
			"m": randInt(32, 268435456),
			"t": randInt(1, 16),
			"p": randInt(1, 8),
		}
		nonce := randBytes(32)
		Success(c, http.StatusOK, gin.H{
			"nonce":       nonce,
			"kdf":         kdf,
			"server_salt": randHex(32),
			"salt_cl":     randHex(32),
		})
	}
}

func HandleRegister(db *gorm.DB, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req registerRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			Error(c, http.StatusBadRequest, "VALIDATION_ERROR", "invalid request body")
			return
		}

		userID, err := uuid.Parse(req.UserID)
		if err != nil {
			Error(c, http.StatusBadRequest, "VALIDATION_ERROR", "invalid user_id")
			return
		}

		var existing models.User
		if db.Where("id = ?", userID).First(&existing).Error == nil {
			at, rt, err := GenerateTokenPair(userID, "", cfg)
			if err != nil {
				Error(c, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to generate tokens")
				return
			}
			Success(c, http.StatusOK, gin.H{
				"access_token":  at,
				"refresh_token": rt,
				"user":          existing,
			})
			return
		}

		if db.Where("email = ?", req.Email).First(&existing).Error == nil {
			Error(c, http.StatusConflict, "CONFLICT", "email already registered")
			return
		}

		user := models.User{
			ID:           userID,
			Email:        req.Email,
			Name:         req.Email,
			AuthProvider: "password",
			AuthVerifier: &req.PasswordHash,
			AuthSalt:     &req.ServerSalt,
			SaltCL:       &req.SaltCL,
			KDFM:         req.KDFM,
			KDFT:         req.KDFT,
			KDFP:         req.KDFP,
			Initialized:  true,
		}
		if err := db.Create(&user).Error; err != nil {
			Error(c, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to create user")
			return
		}

		if err := models.SeedPersonalVault(db, userID); err != nil {
			Error(c, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to seed vault")
			return
		}

		at, rt, err := GenerateTokenPair(userID, "", cfg)
		if err != nil {
			Error(c, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to generate tokens")
			return
		}

		Success(c, http.StatusCreated, gin.H{
			"access_token":  at,
			"refresh_token": rt,
			"user":          user,
		})
	}
}

type loginRequest struct {
	Email         string `json:"email" binding:"required"`
	Proof         string `json:"proof" binding:"required"`
	Nonce         string `json:"nonce" binding:"required"`
	DeviceID      string `json:"device_id"`
	ClientPubkey  string `json:"client_pubkey"`
}

func HandleLogin(db *gorm.DB, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req loginRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			Error(c, http.StatusBadRequest, "VALIDATION_ERROR", "invalid request body")
			return
		}

		var user models.User
		if db.Where("email = ?", req.Email).First(&user).Error != nil {
			Error(c, http.StatusUnauthorized, "UNAUTHORIZED", "invalid credentials")
			return
		}

		if user.AuthVerifier == nil {
			Error(c, http.StatusUnauthorized, "UNAUTHORIZED", "invalid credentials")
			return
		}

		proofBytes, err := base64.RawStdEncoding.DecodeString(req.Proof)
		if err != nil {
			Error(c, http.StatusUnauthorized, "UNAUTHORIZED", "invalid credentials")
			return
		}
		nonceBytes, err := base64.RawStdEncoding.DecodeString(req.Nonce)
		if err != nil {
			Error(c, http.StatusUnauthorized, "UNAUTHORIZED", "invalid credentials")
			return
		}
		verifierBytes, err := base64.RawStdEncoding.DecodeString(*user.AuthVerifier)
		if err != nil {
			Error(c, http.StatusUnauthorized, "UNAUTHORIZED", "invalid credentials")
			return
		}

		expectedProof := GenerateProof(verifierBytes, nonceBytes)
		if !ConstantTimeCompare(proofBytes, expectedProof) {
			Error(c, http.StatusUnauthorized, "UNAUTHORIZED", "invalid credentials")
			return
		}

		now := time.Now()
		db.Model(&user).Update("last_login_at", &now)

		rtToken, err := createRefreshToken(db, user.ID, req.DeviceID, cfg)
		if err != nil {
			Error(c, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to create refresh token")
			return
		}

		at, _, err := GenerateTokenPair(user.ID, req.DeviceID, cfg)
		if err != nil {
			Error(c, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to generate tokens")
			return
		}

		var keyringBlob *string
		var uk models.UserKey
		if db.Where("user_id = ? AND key_type = ?", user.ID, "keyring").First(&uk).Error == nil {
			keyringBlob = &uk.Payload
		}

		Success(c, http.StatusOK, gin.H{
			"access_token":  at,
			"refresh_token": rtToken,
			"user":          user,
			"keyring":       keyringBlob,
		})
	}
}

type refreshRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

func HandleRefresh(db *gorm.DB, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req refreshRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			Error(c, http.StatusBadRequest, "VALIDATION_ERROR", "refresh_token is required")
			return
		}

		tokenHash := hashToken(req.RefreshToken)

		var rt models.RefreshToken
		if db.Where("token_hash = ?", tokenHash).First(&rt).Error != nil {
			Error(c, http.StatusUnauthorized, "UNAUTHORIZED", "invalid refresh token")
			return
		}

		if rt.RevokedAt != nil {
			db.Model(&models.RefreshToken{}).Where("user_id = ? AND revoked_at IS NULL", rt.UserID).
				Update("revoked_at", time.Now())
			Error(c, http.StatusUnauthorized, "UNAUTHORIZED", "refresh token revoked (reuse detected)")
			return
		}

		if time.Now().After(rt.ExpiresAt) {
			Error(c, http.StatusUnauthorized, "UNAUTHORIZED", "refresh token expired")
			return
		}

		now := time.Now()
		db.Model(&rt).Updates(map[string]interface{}{
			"revoked_at":  &now,
			"rotated_at":  &now,
		})

		newRT, err := createRefreshToken(db, rt.UserID, rt.DeviceID, cfg)
		if err != nil {
			Error(c, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to create refresh token")
			return
		}

		at, _, err := GenerateTokenPair(rt.UserID, rt.DeviceID, cfg)
		if err != nil {
			Error(c, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to generate tokens")
			return
		}

		Success(c, http.StatusOK, gin.H{
			"access_token":  at,
			"refresh_token": newRT,
		})
	}
}

func HandleLogout(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req refreshRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			Error(c, http.StatusBadRequest, "VALIDATION_ERROR", "refresh_token is required")
			return
		}

		tokenHash := hashToken(req.RefreshToken)

		var rt models.RefreshToken
		if db.Where("token_hash = ?", tokenHash).First(&rt).Error != nil {
			Error(c, http.StatusUnauthorized, "UNAUTHORIZED", "invalid refresh token")
			return
		}

		now := time.Now()
		db.Model(&rt).Update("revoked_at", &now)

		c.Status(http.StatusNoContent)
	}
}

func HandleMe(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, exists := c.Get("user_id")
		if !exists {
			Error(c, http.StatusUnauthorized, "UNAUTHORIZED", "missing user context")
			return
		}

		var user models.User
		if db.Where("id = ?", userID).First(&user).Error != nil {
			Error(c, http.StatusNotFound, "NOT_FOUND", "user not found")
			return
		}

		Success(c, http.StatusOK, user)
	}
}

func createRefreshToken(db *gorm.DB, userID uuid.UUID, deviceID string, cfg *config.Config) (string, error) {
	rawToken := randBytes(48)
	tokenHash := hashToken(rawToken)

	now := time.Now()
	rt := models.RefreshToken{
		UserID:    userID,
		TokenHash: tokenHash,
		DeviceID:  deviceID,
		ExpiresAt: now.Add(cfg.RefreshTokenExpiry),
	}
	if err := db.Create(&rt).Error; err != nil {
		return "", err
	}
	return rawToken, nil
}

func hashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return base64.RawStdEncoding.EncodeToString(h[:])
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func randBytes(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return base64.RawStdEncoding.EncodeToString(b)
}

func randHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return base64.RawStdEncoding.EncodeToString(b)
}

func randInt(min, max int) int {
	b := make([]byte, 4)
	rand.Read(b)
	v := int(b[0])<<24 | int(b[1])<<16 | int(b[2])<<8 | int(b[3])
	if v < 0 {
		v = -v
	}
	return min + (v % (max - min + 1))
}
