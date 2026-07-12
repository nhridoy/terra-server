package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/termvault/termvault/internal/auth"
	"github.com/termvault/termvault/internal/db"
)

func ListSessions(c *gin.Context) {
	userID := auth.GetUserID(c)
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	vaultID := c.Query("vaultId")
	if vaultID != "" && !vaultBelongsToUser(userID, vaultID) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid vault"})
		return
	}

	q := db.GetDB().Where("user_id = ?", userID)
	if vaultID != "" {
		q = q.Where("vault_id = ?", vaultID)
	}

	var sessions []db.SessionLog
	if result := q.Order("started_at DESC").Limit(100).Find(&sessions); result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch sessions"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"sessions": sessions})
}

func GetSession(c *gin.Context) {
	userID := auth.GetUserID(c)
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	sessionID := c.Param("id")

	var session db.SessionLog
	if result := db.GetDB().Where("id = ? AND user_id = ?", sessionID, userID).First(&session); result.Error != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "session not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"session": session})
}
