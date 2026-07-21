package api

import (
	"crypto/rand"
	"log/slog"
	"net/http"
	"regexp"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/termvault/termvault/internal/auth"
	"github.com/termvault/termvault/internal/config"
	"github.com/termvault/termvault/internal/db"
	"gorm.io/gorm"
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

type ChangePasswordRequest struct {
	CurrentPassword string `json:"currentPassword" binding:"required"`
	NewPassword     string `json:"newPassword" binding:"required,min=8"`
}

type UpdateProfileRequest struct {
	Username string `json:"username" binding:"required,min=3,max=50"`
	Email    string `json:"email" binding:"required,email"`
}

var (
	errPasswordTooShort = &passwordError{"password must be at least 8 characters with uppercase, lowercase, and a digit"}
	errPasswordNoUpper  = &passwordError{"password must contain at least one uppercase letter"}
	errPasswordNoLower  = &passwordError{"password must contain at least one lowercase letter"}
	errPasswordNoDigit  = &passwordError{"password must contain at least one digit"}
)

type passwordError struct{ msg string }

func (e *passwordError) Error() string { return e.msg }

func generateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	return b, err
}

func bytesToHex(b []byte) string {
	return auth.BytesToHex(b)
}

var (
	hasUpper = regexp.MustCompile(`[A-Z]`)
	hasLower = regexp.MustCompile(`[a-z]`)
	hasDigit = regexp.MustCompile(`[0-9]`)
)

func validatePassword(password string) error {
	if len(password) < 8 {
		return errPasswordTooShort
	}
	if !hasUpper.MatchString(password) {
		return errPasswordNoUpper
	}
	if !hasLower.MatchString(password) {
		return errPasswordNoLower
	}
	if !hasDigit.MatchString(password) {
		return errPasswordNoDigit
	}
	return nil
}

func ensureDefaultVaults(userID string) {
	defaults := []db.Vault{
		{
			UserID:    userID,
			Name:      "Personal",
			IsDefault: true,
			IsSystem:  true,
		},
		{
			UserID:    userID,
			Name:      "Team",
			IsDefault: false,
			IsSystem:  true,
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
		v.ID = uuid.New().String()
		if err := db.GetDB().Create(&v).Error; err != nil {
			slog.Error("Failed to create default vault", "name", v.Name, "userId", userID, "error", err)
		}
	}
}

func createRefreshToken(userID string) (string, time.Time, error) {
	tokenBytes := make([]byte, 64)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", time.Time{}, err
	}
	token := bytesToHex(tokenBytes)

	expiryDuration, err := time.ParseDuration(config.AppConfig.RefreshTokenExpiry)
	if err != nil {
		expiryDuration = 720 * time.Hour // 30 days default
	}
	expiresAt := time.Now().Add(expiryDuration)

	refreshToken := db.RefreshToken{
		ID:        uuid.New().String(),
		UserID:    userID,
		Token:     token,
		ExpiresAt: expiresAt,
	}

	if err := db.GetDB().Create(&refreshToken).Error; err != nil {
		return "", time.Time{}, err
	}

	return token, expiresAt, nil
}

func Register(c *gin.Context) {
	var req RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := validatePassword(req.Password); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var existingUser db.User
	if result := db.GetDB().Where("email = ?", req.Email).First(&existingUser); result.Error == nil {
		c.JSON(http.StatusConflict, gin.H{"error": "email already registered"})
		return
	}

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

	user := db.User{
		ID:           uuid.New().String(),
		Email:        req.Email,
		Username:     req.Username,
		SrpSalt:      bytesToHex(salt),
		SrpVerifier:  auth.BigIntToHex(verifier),
		KeyNonce:     bytesToHex(nonce),
		KeySalt:      bytesToHex(encSalt),
	}

	if result := db.GetDB().Create(&user); result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create user"})
		return
	}

	settings := db.Settings{
		ID:          uuid.New().String(),
		UserID:      user.ID,
		Theme:       "dark",
		FontFamily:  "JetBrains Mono",
		FontSize:    14,
		CursorStyle: "block",
	}
	if err := db.GetDB().Create(&settings).Error; err != nil {
		slog.Error("Failed to create default settings", "userId", user.ID, "error", err)
	}

	ensureDefaultVaults(user.ID)

	tokens, err := auth.GenerateTokenPair(user.ID, user.Email)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate tokens"})
		return
	}

	refreshToken, refreshExpiry, err := createRefreshToken(user.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create refresh token"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"userId":              user.ID,
		"token":               tokens.AccessToken,
		"refreshToken":        refreshToken,
		"expiresAt":           tokens.ExpiresAt,
		"refreshExpiry":       refreshExpiry.Unix(),
		"hasMasterPassword":   user.HasMasterPassword,
	})
}

func Login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var user db.User
	if result := db.GetDB().Where("email = ?", req.Email).First(&user); result.Error != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

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

	if !auth.VerifyPassword(req.Email, req.Password, saltBytes, verifierBytes) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	tokens, err := auth.GenerateTokenPair(user.ID, user.Email)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate tokens"})
		return
	}

	refreshToken, refreshExpiry, err := createRefreshToken(user.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create refresh token"})
		return
	}

	ensureDefaultVaults(user.ID)

	c.JSON(http.StatusOK, gin.H{
		"token":               tokens.AccessToken,
		"refreshToken":        refreshToken,
		"expiresAt":           tokens.ExpiresAt,
		"refreshExpiry":       refreshExpiry.Unix(),
		"encryptedPrivateKey": user.EncryptedPriv,
		"encryptedPersonalKey": user.EncryptedPK,
		"publicKey":           user.PublicKey,
		"nonce":               user.KeyNonce,
		"salt":                user.KeySalt,
		"userId":              user.ID,
		"username":            user.Username,
		"hasMasterPassword":   user.HasMasterPassword,
	})
}

func RefreshToken(c *gin.Context) {
	var req RefreshRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var storedToken db.RefreshToken
	if result := db.GetDB().Where("token = ? AND expires_at > ?", req.RefreshToken, time.Now()).First(&storedToken); result.Error != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired refresh token"})
		return
	}

	db.GetDB().Delete(&storedToken)

	var user db.User
	if result := db.GetDB().Where("id = ?", storedToken.UserID).First(&user); result.Error != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "user not found"})
		return
	}

	tokens, err := auth.GenerateTokenPair(user.ID, user.Email)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate tokens"})
		return
	}

	refreshToken, refreshExpiry, err := createRefreshToken(user.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create refresh token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"token":        tokens.AccessToken,
		"refreshToken": refreshToken,
		"expiresAt":    tokens.ExpiresAt,
		"refreshExpiry": refreshExpiry.Unix(),
	})
}

func Logout(c *gin.Context) {
	userID := auth.GetUserID(c)
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	// Revoke all refresh tokens for this user
	db.GetDB().Where("user_id = ?", userID).Delete(&db.RefreshToken{})

	// Revoke all access tokens for this user (prevents use of token until expiry)
	auth.RevokeAllTokensForUser(userID)

	c.JSON(http.StatusOK, gin.H{"message": "logged out"})
}

func ChangePassword(c *gin.Context) {
	userID := auth.GetUserID(c)
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	var req ChangePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := validatePassword(req.NewPassword); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var user db.User
	if result := db.GetDB().Where("id = ?", userID).First(&user); result.Error != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}

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

	if !auth.VerifyPassword(user.Email, req.CurrentPassword, saltBytes, verifierBytes) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "current password is incorrect"})
		return
	}

	newSalt, err := generateRandomBytes(32)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate salt"})
		return
	}

	newVerifier, err := auth.GenerateVerifier(user.Email, req.NewPassword, newSalt)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate verifier"})
		return
	}

	user.SrpSalt = bytesToHex(newSalt)
	user.SrpVerifier = auth.BigIntToHex(newVerifier)

	if result := db.GetDB().Save(&user); result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update password"})
		return
	}

	db.GetDB().Where("user_id = ?", userID).Delete(&db.RefreshToken{})

	c.JSON(http.StatusOK, gin.H{"message": "password changed"})
}

func UpdateProfile(c *gin.Context) {
	userID := auth.GetUserID(c)
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	var req UpdateProfileRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var user db.User
	if result := db.GetDB().Where("id = ?", userID).First(&user); result.Error != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}

	if req.Email != user.Email {
		var existing db.User
		if result := db.GetDB().Where("email = ? AND id != ?", req.Email, userID).First(&existing); result.Error == nil {
			c.JSON(http.StatusConflict, gin.H{"error": "email already in use"})
			return
		}
	}

	user.Username = req.Username
	user.Email = req.Email

	if result := db.GetDB().Save(&user); result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update profile"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"userId":   user.ID,
		"username": user.Username,
		"email":    user.Email,
	})
}

func DeleteAccount(c *gin.Context) {
	userID := auth.GetUserID(c)
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	var req struct {
		Password string `json:"password" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var user db.User
	if result := db.GetDB().Where("id = ?", userID).First(&user); result.Error != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}

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

	if !auth.VerifyPassword(user.Email, req.Password, saltBytes, verifierBytes) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "incorrect password"})
		return
	}

	// Delete all user data in a transaction
	if err := db.InTransaction(func(tx *gorm.DB) error {
		tx.Where("user_id = ?", userID).Delete(&db.Host{})
		tx.Where("user_id = ?", userID).Delete(&db.Group{})
		tx.Where("user_id = ?", userID).Delete(&db.Keychain{})
		tx.Where("user_id = ?", userID).Delete(&db.Snippet{})
		tx.Where("user_id = ?", userID).Delete(&db.Workspace{})
		tx.Where("user_id = ?", userID).Delete(&db.TabGroup{})
		tx.Where("user_id = ?", userID).Delete(&db.Vault{})
		tx.Where("user_id = ?", userID).Delete(&db.Settings{})
		tx.Where("user_id = ?", userID).Delete(&db.RefreshToken{})
		return tx.Delete(&user).Error
	}); err != nil {
		slog.Error("Failed to delete account", "userId", userID, "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete account"})
		return
	}

	// Revoke all tokens
	auth.RevokeAllTokensForUser(userID)

	c.JSON(http.StatusOK, gin.H{"message": "account deleted"})
}

func OAuthRedirect(c *gin.Context) {
	provider := c.Param("provider")
	c.JSON(http.StatusNotImplemented, gin.H{"error": "oauth not yet implemented", "provider": provider})
}

func OAuthCallback(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{"error": "oauth callback not yet implemented"})
}

func SetMasterPassword(c *gin.Context) {
	userID := auth.GetUserID(c)
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	var user db.User
	if result := db.GetDB().Where("id = ?", userID).First(&user); result.Error != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}

	user.HasMasterPassword = true
	if result := db.GetDB().Save(&user); result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update user"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "master password set"})
}

func GetCurrentUser(c *gin.Context) {
	userID := auth.GetUserID(c)
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	var user db.User
	if result := db.GetDB().Where("id = ?", userID).First(&user); result.Error != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"userId":             user.ID,
		"email":              user.Email,
		"username":           user.Username,
		"hasMasterPassword":  user.HasMasterPassword,
	})
}
