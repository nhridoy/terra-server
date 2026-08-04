package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/termvault/termvault/internal/config"
	"github.com/termvault/termvault/internal/models"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"gorm.io/gorm"
)

func generatePKCE() (verifier string, challenge string, err error) {
	b := make([]byte, 32)
	if _, err = rand.Read(b); err != nil {
		return
	}
	verifier = base64.RawURLEncoding.EncodeToString(b)
	h := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(h[:])
	return
}

func getOAuthConfig(provider string, cfg *config.Config) (*oauth2.Config, error) {
	switch provider {
	case "google":
		return &oauth2.Config{
			ClientID:     cfg.OAuthGoogleID,
			ClientSecret: cfg.OAuthGoogleSecret,
			Endpoint:     google.Endpoint,
			RedirectURL:  cfg.OAuthRedirectBase + "/api/v1/auth/oauth/callback/" + provider,
			Scopes:       []string{"openid", "email", "profile"},
		}, nil
	case "github":
		return &oauth2.Config{
			ClientID:     cfg.OAuthGitHubID,
			ClientSecret: cfg.OAuthGitHubSecret,
			Endpoint: oauth2.Endpoint{
				AuthURL:  "https://github.com/login/oauth/authorize",
				TokenURL: "https://github.com/login/oauth/access_token",
			},
			RedirectURL: cfg.OAuthRedirectBase + "/api/v1/auth/oauth/callback/" + provider,
			Scopes:      []string{"user:email"},
		}, nil
	default:
		return nil, fmt.Errorf("unknown provider: %s", provider)
	}
}

type userInfo struct {
	Email       string
	Name        string
	AvatarURL   string
	ProviderSub string
}

func fetchGoogleUserInfo(token *oauth2.Token) (*userInfo, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("GET", "https://www.googleapis.com/oauth2/v2/userinfo", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("google userinfo returned %d", resp.StatusCode)
	}

	var raw struct {
		Email   string `json:"email"`
		Name    string `json:"name"`
		Picture string `json:"picture"`
		ID      string `json:"id"`
	}
	body, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, err
	}
	return &userInfo{
		Email:       raw.Email,
		Name:        raw.Name,
		AvatarURL:   raw.Picture,
		ProviderSub: raw.ID,
	}, nil
}

func fetchGitHubUserInfo(token *oauth2.Token) (*userInfo, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("GET", "https://api.github.com/user", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("github user returned %d", resp.StatusCode)
	}

	var raw struct {
		Name      string `json:"name"`
		Email     string `json:"email"`
		AvatarURL string `json:"avatar_url"`
		ID        int64  `json:"id"`
	}
	body, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, err
	}
	return &userInfo{
		Email:       raw.Email,
		Name:        raw.Name,
		AvatarURL:   raw.AvatarURL,
		ProviderSub: fmt.Sprintf("%d", raw.ID),
	}, nil
}

func HandleOAuthStart(db *gorm.DB, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		provider := c.Param("provider")
		oauthCfg, err := getOAuthConfig(provider, cfg)
		if err != nil {
			Error(c, http.StatusBadRequest, "INVALID_PROVIDER", "unsupported OAuth provider")
			return
		}

		verifier, challenge, err := generatePKCE()
		if err != nil {
			Error(c, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to generate PKCE")
			return
		}

		state := randBytes(32)
		deviceID := c.Query("device_id")
		if deviceID == "" {
			deviceID = "default"
		}

		oauthState := models.OAuthState{
			State:        state,
			Provider:     provider,
			CodeVerifier: verifier,
			DeviceID:     deviceID,
			ExpiresAt:    time.Now().Add(10 * time.Minute),
		}
		if err := db.Create(&oauthState).Error; err != nil {
			Error(c, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to store OAuth state")
			return
		}

		authURL := oauthCfg.AuthCodeURL(state,
			oauth2.SetAuthURLParam("code_challenge", challenge),
			oauth2.SetAuthURLParam("code_challenge_method", "S256"),
		)

		c.Redirect(http.StatusFound, authURL)
	}
}

func HandleOAuthCallback(db *gorm.DB, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		provider := c.Param("provider")
		code := c.Query("code")
		state := c.Query("state")

		if code == "" || state == "" {
			c.Redirect(http.StatusFound, cfg.AppScheme+"://auth/error?message=missing_code_or_state")
			return
		}

		var oauthState models.OAuthState
		if db.Where("state = ?", state).First(&oauthState).Error != nil {
			c.Redirect(http.StatusFound, cfg.AppScheme+"://auth/error?message=invalid_state")
			return
		}

		if oauthState.UsedAt != nil {
			c.Redirect(http.StatusFound, cfg.AppScheme+"://auth/error?message=state_already_used")
			return
		}

		if time.Now().After(oauthState.ExpiresAt) {
			c.Redirect(http.StatusFound, cfg.AppScheme+"://auth/error?message=state_expired")
			return
		}

		now := time.Now()
		db.Model(&oauthState).Update("used_at", &now)

		oauthCfg, err := getOAuthConfig(provider, cfg)
		if err != nil {
			c.Redirect(http.StatusFound, cfg.AppScheme+"://auth/error?message=invalid_provider")
			return
		}

		token, err := oauthCfg.Exchange(c.Request.Context(), code,
			oauth2.SetAuthURLParam("code_verifier", oauthState.CodeVerifier),
		)
		if err != nil {
			c.Redirect(http.StatusFound, cfg.AppScheme+"://auth/error?message=token_exchange_failed")
			return
		}

		var ui *userInfo
		switch provider {
		case "google":
			ui, err = fetchGoogleUserInfo(token)
		case "github":
			ui, err = fetchGitHubUserInfo(token)
		default:
			c.Redirect(http.StatusFound, cfg.AppScheme+"://auth/error?message=unsupported_provider")
			return
		}
		if err != nil {
			c.Redirect(http.StatusFound, cfg.AppScheme+"://auth/error?message=userinfo_failed")
			return
		}

		var user models.User
		providerSub := ui.ProviderSub
		found := db.Where("auth_provider = ? AND provider_sub = ?", provider, providerSub).First(&user).Error == nil

		if !found {
			if db.Where("email = ?", ui.Email).First(&user).Error == nil {
				user.AuthProvider = provider
				user.ProviderSub = &providerSub
				if err := db.Save(&user).Error; err != nil {
					c.Redirect(http.StatusFound, cfg.AppScheme+"://auth/error?message=link_failed")
					return
				}
			} else {
				user = models.User{
					ID:           uuid.New(),
					Email:        ui.Email,
					Name:         ui.Name,
					AuthProvider: provider,
					ProviderSub:  &providerSub,
					Initialized:  false,
					CreatedAt:    time.Now(),
					UpdatedAt:    time.Now(),
				}
				if err := db.Create(&user).Error; err != nil {
					c.Redirect(http.StatusFound, cfg.AppScheme+"://auth/error?message=create_user_failed")
					return
				}
				if err := models.SeedPersonalVault(db, user.ID); err != nil {
					c.Redirect(http.StatusFound, cfg.AppScheme+"://auth/error?message=vault_seed_failed")
					return
				}
			}
		}

		if !user.Initialized {
			setupCode := randBytes(32)
			setupCodeHash := hashToken(setupCode)
			ac := models.AuthCode{
				CodeHash:  setupCodeHash,
				Purpose:   "oauth_setup",
				UserID:    user.ID,
				DeviceID:  oauthState.DeviceID,
				ExpiresAt: time.Now().Add(15 * time.Minute),
			}
			if err := db.Create(&ac).Error; err != nil {
				c.Redirect(http.StatusFound, cfg.AppScheme+"://auth/error?message=setup_code_failed")
				return
			}
			setupURL := fmt.Sprintf("%s://auth/setup?setup_code=%s&user_id=%s", cfg.AppScheme, setupCode, user.ID.String())
			c.Redirect(http.StatusFound, setupURL)
			return
		}

		at, rt, err := GenerateTokenPair(user.ID, oauthState.DeviceID, cfg)
		if err != nil {
			c.Redirect(http.StatusFound, cfg.AppScheme+"://auth/error?message=token_generation_failed")
			return
		}

		successURL := fmt.Sprintf("%s://auth/success?access_token=%s&refresh_token=%s&user_id=%s",
			cfg.AppScheme,
			url.QueryEscape(at),
			url.QueryEscape(rt),
			user.ID.String(),
		)
		c.Redirect(http.StatusFound, successURL)
	}
}

type oauthExchangeRequest struct {
	SetupCode string `json:"setup_code" binding:"required"`
	UserID    string `json:"user_id" binding:"required"`
}

func HandleOAuthExchange(db *gorm.DB, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req oauthExchangeRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			Error(c, http.StatusBadRequest, "VALIDATION_ERROR", "setup_code and user_id are required")
			return
		}

		userID, err := uuid.Parse(req.UserID)
		if err != nil {
			Error(c, http.StatusBadRequest, "VALIDATION_ERROR", "invalid user_id")
			return
		}

		codeHash := hashToken(req.SetupCode)

		var ac models.AuthCode
		if db.Where("code_hash = ? AND purpose = ?", codeHash, "oauth_setup").First(&ac).Error != nil {
			Error(c, http.StatusUnauthorized, "UNAUTHORIZED", "invalid or expired setup code")
			return
		}

		if ac.UsedAt != nil {
			Error(c, http.StatusUnauthorized, "UNAUTHORIZED", "setup code already used")
			return
		}

		if time.Now().After(ac.ExpiresAt) {
			Error(c, http.StatusUnauthorized, "UNAUTHORIZED", "setup code expired")
			return
		}

		if ac.UserID != userID {
			Error(c, http.StatusUnauthorized, "UNAUTHORIZED", "setup code does not match user")
			return
		}

		now := time.Now()
		db.Model(&ac).Update("used_at", &now)

		var user models.User
		if db.Where("id = ?", userID).First(&user).Error != nil {
			Error(c, http.StatusNotFound, "NOT_FOUND", "user not found")
			return
		}

		at, rt, err := GenerateTokenPair(userID, ac.DeviceID, cfg)
		if err != nil {
			Error(c, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to generate tokens")
			return
		}

		Success(c, http.StatusOK, gin.H{
			"access_token":  at,
			"refresh_token": rt,
			"user":          user,
			"initialized":   user.Initialized,
		})
	}
}

type oauthSetupRequest struct {
	SetupToken       string `json:"setup_token" binding:"required"`
	EncryptedDEK     string `json:"encrypted_dek" binding:"required"`
	EncryptedPrivkey string `json:"encrypted_privkey"`
	AuthVerifier     string `json:"auth_verifier" binding:"required"`
}

func HandleOAuthSetup(db *gorm.DB, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req oauthSetupRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			Error(c, http.StatusBadRequest, "VALIDATION_ERROR", "setup_token, encrypted_dek, and auth_verifier are required")
			return
		}

		codeHash := hashToken(req.SetupToken)

		var ac models.AuthCode
		if db.Where("code_hash = ? AND purpose = ?", codeHash, "oauth_setup").First(&ac).Error != nil {
			Error(c, http.StatusUnauthorized, "UNAUTHORIZED", "invalid or expired setup token")
			return
		}

		if ac.UsedAt != nil {
			Error(c, http.StatusUnauthorized, "UNAUTHORIZED", "setup token already used")
			return
		}

		if time.Now().After(ac.ExpiresAt) {
			Error(c, http.StatusUnauthorized, "UNAUTHORIZED", "setup token expired")
			return
		}

		var user models.User
		if db.Where("id = ?", ac.UserID).First(&user).Error != nil {
			Error(c, http.StatusNotFound, "NOT_FOUND", "user not found")
			return
		}

		if user.Initialized {
			Error(c, http.StatusConflict, "ALREADY_INITIALIZED", "user already initialized")
			return
		}

		now := time.Now()
		db.Model(&ac).Update("used_at", &now)

		user.AuthVerifier = &req.AuthVerifier
		user.Initialized = true
		user.UpdatedAt = now
		if err := db.Save(&user).Error; err != nil {
			Error(c, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to update user")
			return
		}

		uk := models.UserKey{
			UserID:  user.ID,
			KeyType: "dek",
			Payload: req.EncryptedDEK,
		}
		if err := db.Create(&uk).Error; err != nil {
			Error(c, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to store DEK")
			return
		}

		if req.EncryptedPrivkey != "" {
			pk := models.UserKey{
				UserID:  user.ID,
				KeyType: "privkey",
				Payload: req.EncryptedPrivkey,
			}
			db.Create(&pk)
		}

		at, rt, err := GenerateTokenPair(user.ID, ac.DeviceID, cfg)
		if err != nil {
			Error(c, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to generate tokens")
			return
		}

		Success(c, http.StatusOK, gin.H{
			"access_token":  at,
			"refresh_token": rt,
			"user":          user,
		})
	}
}
