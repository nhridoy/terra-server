package api

import (
	"encoding/json"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/termvault/termvault/internal/auth"
	"github.com/termvault/termvault/internal/db"
)

type CreateSnippetRequest struct {
	Name        string   `json:"name" binding:"required"`
	Command     string   `json:"command" binding:"required"`
	Description string   `json:"description"`
	Tags        []string `json:"tags"`
	VaultID     *string  `json:"vaultId"`
}

type UpdateSnippetRequest struct {
	Name        *string  `json:"name"`
	Command     *string  `json:"command"`
	Description *string  `json:"description"`
	Tags        []string `json:"tags"`
}

func marshalTags(tags []string) string {
	if tags == nil {
		return "[]"
	}
	b, _ := json.Marshal(tags)
	return string(b)
}

func ListSnippets(c *gin.Context) {
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

	var snippets []db.Snippet
	if result := q.Order("created_at DESC").Find(&snippets); result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch snippets"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"snippets": snippets})
}

func CreateSnippet(c *gin.Context) {
	userID := auth.GetUserID(c)
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	var req CreateSnippetRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	vaultID, ok := resolveVaultID(userID, strPtrValue(req.VaultID))
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "a valid vault is required"})
		return
	}

	snippet := db.Snippet{
		UserID:      userID,
		VaultID:     &vaultID,
		Name:        req.Name,
		Command:     req.Command,
		Description: req.Description,
		Tags:        marshalTags(req.Tags),
	}

	if result := db.GetDB().Create(&snippet); result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create snippet"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"snippet": snippet})
}

func UpdateSnippet(c *gin.Context) {
	userID := auth.GetUserID(c)
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	snippetID := c.Param("id")

	var snippet db.Snippet
	if result := db.GetDB().Where("id = ? AND user_id = ?", snippetID, userID).First(&snippet); result.Error != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "snippet not found"})
		return
	}

	var req UpdateSnippetRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.Name != nil {
		snippet.Name = *req.Name
	}
	if req.Command != nil {
		snippet.Command = *req.Command
	}
	if req.Description != nil {
		snippet.Description = *req.Description
	}
	if req.Tags != nil {
		snippet.Tags = marshalTags(req.Tags)
	}

	if result := db.GetDB().Save(&snippet); result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update snippet"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"snippet": snippet})
}

func DeleteSnippet(c *gin.Context) {
	userID := auth.GetUserID(c)
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	snippetID := c.Param("id")

	var snippet db.Snippet
	if result := db.GetDB().Where("id = ? AND user_id = ?", snippetID, userID).First(&snippet); result.Error != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "snippet not found"})
		return
	}

	if result := db.GetDB().Delete(&snippet); result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete snippet"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "snippet deleted"})
}
