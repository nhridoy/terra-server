package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/termvault/termvault/internal/auth"
	"github.com/termvault/termvault/internal/db"
)

type UpdateSettingsRequest struct {
	Theme       *string `json:"theme"`
	FontFamily  *string `json:"fontFamily"`
	FontSize    *int    `json:"fontSize"`
	CursorStyle *string `json:"cursorStyle"`
	Keybindings *string `json:"keybindings"`
}

func GetSettings(c *gin.Context) {
	userID := auth.GetUserID(c)
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	var settings db.Settings
	if result := db.GetDB().Where("user_id = ?", userID).First(&settings); result.Error != nil {
		// Create default settings if not found
		settings = db.Settings{
			UserID:      userID,
			Theme:       "dark",
			FontFamily:  "JetBrains Mono",
			FontSize:    14,
			CursorStyle: "block",
		}
		db.GetDB().Create(&settings)
	}

	c.JSON(http.StatusOK, gin.H{"settings": settings})
}

func UpdateSettings(c *gin.Context) {
	userID := auth.GetUserID(c)
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	var settings db.Settings
	if result := db.GetDB().Where("user_id = ?", userID).First(&settings); result.Error != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "settings not found"})
		return
	}

	var req UpdateSettingsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.Theme != nil {
		settings.Theme = *req.Theme
	}
	if req.FontFamily != nil {
		settings.FontFamily = *req.FontFamily
	}
	if req.FontSize != nil {
		settings.FontSize = *req.FontSize
	}
	if req.CursorStyle != nil {
		settings.CursorStyle = *req.CursorStyle
	}
	if req.Keybindings != nil {
		settings.Keybindings = *req.Keybindings
	}

	if result := db.GetDB().Save(&settings); result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update settings"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"settings": settings})
}
