package auth

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"

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
