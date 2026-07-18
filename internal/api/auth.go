package api

import (
	"crypto/rand"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/termvault/termvault/internal/auth"
	"github.com/termvault/termvault/internal/db"
)

type RegisterRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Username string `json:"username" binding:"required,min=3,max=50"`
	Password string `json:"password" binding:"required,min=8"`
}

type LoginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

type RefreshRequest struct {
	RefreshToken string `json:"refreshToken" binding:"required"`
}

func generateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	return b, err
}

func bytesToHex(b []byte) string {
	return auth.BytesToHex(b)
}

// ensureDefaultVaults creates the Personal and Team system vaults for a user
// if they do not already exist. It is idempotent and safe to call on every
// request; the unique (user_id, name) constraint handles concurrent races.
func ensureDefaultVaults(userID string) {
	defaults := []db.Vault{
		{
			UserID:        userID,
			Name:          "Personal",
			Description:   "Personal vault for individual use",
			IsDefault:     true,
			IsSystem:      true,
			EncryptedData: "",
			IV:            "",
			Salt:          "",
		},
		{
			UserID:        userID,
			Name:          "Team",
			Description:   "Team vault for shared resources",
			IsDefault:     false,
			IsSystem:      true,
			EncryptedData: "",
			IV:            "",
			Salt:          "",
		},
	}

	for _, v := range defaults {
		var count int64
		db.GetDB().Model(&db.Vault{}).
			Where("user_id = ? AND name = ?", userID, v.Name).
			Count(&count)
		if count > 0 {
			continue
		}
		if err := db.GetDB().Create(&v).Error; err != nil {
			log.Printf("Failed to create default vault '%s' for user %s: %v", v.Name, userID, err)
		}
	}
}

// Register handles user registration
func Register(c *gin.Context) {
	var req RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Check if user already exists
	var existingUser db.User
	if result := db.GetDB().Where("email = ?", req.Email).First(&existingUser); result.Error == nil {
		c.JSON(http.StatusConflict, gin.H{"error": "email already registered"})
		return
	}

	// Generate SRP values
	salt, err := generateRandomBytes(32)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate salt"})
		return
	}

	verifier, err := auth.GenerateVerifier(req.Email, req.Password, salt)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate verifier"})
		return
	}

	// Generate encryption keys
	encSalt, err := generateRandomBytes(32)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate encryption salt"})
		return
	}

	nonce, err := generateRandomBytes(24)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate nonce"})
		return
	}

	// Create user
	user := db.User{
		Email:       req.Email,
		Username:    req.Username,
		SrpSalt:     bytesToHex(salt),
		SrpVerifier: auth.BigIntToHex(verifier),
		KeyNonce:    bytesToHex(nonce),
		KeySalt:     bytesToHex(encSalt),
	}

	if result := db.GetDB().Create(&user); result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create user"})
		return
	}

	// Create default settings
	settings := db.Settings{
		UserID:      user.ID,
		Theme:       "dark",
		FontFamily:  "JetBrains Mono",
		FontSize:    14,
		CursorStyle: "block",
	}
	db.GetDB().Create(&settings)

	// Create default system vaults (Personal, Team) for the new user.
	// ensureDefaultVaults is idempotent and also runs on every ListVaults call.
	ensureDefaultVaults(user.ID)

	// Generate tokens
	tokens, err := auth.GenerateTokenPair(user.ID, user.Email)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate tokens"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"userId":    user.ID,
		"token":     tokens.AccessToken,
		"refreshToken": tokens.RefreshToken,
		"expiresAt": tokens.ExpiresAt,
	})
}

// Login handles SRP6a authentication
func Login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Find user
	var user db.User
	if result := db.GetDB().Where("email = ?", req.Email).First(&user); result.Error != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	// Verify password
	saltBytes, err := auth.HexToBytes(user.SrpSalt)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "invalid server state"})
		return
	}

	verifierBytes, err := auth.HexToBytes(user.SrpVerifier)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "invalid server state"})
		return
	}

	// Verify the password matches
	if !auth.VerifyPassword(req.Email, req.Password, saltBytes, verifierBytes) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	// Generate tokens
	tokens, err := auth.GenerateTokenPair(user.ID, user.Email)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate tokens"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"token":              tokens.AccessToken,
		"refreshToken":       tokens.RefreshToken,
		"expiresAt":          tokens.ExpiresAt,
		"encryptedPrivateKey": user.EncryptedPriv,
		"encryptedPersonalKey": user.EncryptedPK,
		"publicKey":          user.PublicKey,
		"nonce":              user.KeyNonce,
		"salt":               user.KeySalt,
		"userId":             user.ID,
	})
}

// RefreshToken handles token refresh
func RefreshToken(c *gin.Context) {
	var req RefreshRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validate refresh token
	claims, err := auth.ValidateToken(req.RefreshToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid refresh token"})
		return
	}

	// Generate new token pair
	tokens, err := auth.GenerateTokenPair(claims.UserID, claims.Email)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate tokens"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"token":        tokens.AccessToken,
		"refreshToken": tokens.RefreshToken,
		"expiresAt":    tokens.ExpiresAt,
	})
}

// OAuthRedirect handles OAuth provider redirect
func OAuthRedirect(c *gin.Context) {
	provider := c.Param("provider")
	c.JSON(http.StatusNotImplemented, gin.H{"error": "oauth not yet implemented", "provider": provider})
}

// OAuthCallback handles OAuth callback
func OAuthCallback(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "oauth callback not yet implemented"})
}
