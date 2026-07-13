package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/termvault/termvault/internal/auth"
	"github.com/termvault/termvault/internal/db"
)

type CreateTabGroupRequest struct {
	Name    string `json:"name" binding:"required"`
	Layout  string `json:"layout" binding:"required"`
	VaultID string `json:"vaultId"`
}

type UpdateTabGroupRequest struct {
	Name   *string `json:"name"`
	Layout *string `json:"layout"`
}

func ListTabGroups(c *gin.Context) {
	userID := auth.GetUserID(c)
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	vaultID := c.Query("vaultId")

	query := db.GetDB().Where("user_id = ?", userID)
	if vaultID != "" {
		query = query.Where("vault_id = ?", vaultID)
	}

	var tabGroups []db.TabGroup
	if result := query.Order("created_at DESC").Find(&tabGroups); result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch tab groups"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"tabGroups": tabGroups})
}

func CreateTabGroup(c *gin.Context) {
	userID := auth.GetUserID(c)
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	var req CreateTabGroupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var vaultIDPtr *string
	if req.VaultID != "" {
		vaultIDPtr = &req.VaultID
	}

	tabGroup := db.TabGroup{
		UserID:  userID,
		VaultID: vaultIDPtr,
		Name:    req.Name,
		Layout:  req.Layout,
	}

	if result := db.GetDB().Create(&tabGroup); result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create tab group"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"tabGroup": tabGroup})
}

func UpdateTabGroup(c *gin.Context) {
	userID := auth.GetUserID(c)
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	tabGroupID := c.Param("id")

	var tabGroup db.TabGroup
	if result := db.GetDB().Where("id = ? AND user_id = ?", tabGroupID, userID).First(&tabGroup); result.Error != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "tab group not found"})
		return
	}

	var req UpdateTabGroupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.Name != nil {
		tabGroup.Name = *req.Name
	}
	if req.Layout != nil {
		tabGroup.Layout = *req.Layout
	}

	if result := db.GetDB().Save(&tabGroup); result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update tab group"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"tabGroup": tabGroup})
}

func DeleteTabGroup(c *gin.Context) {
	userID := auth.GetUserID(c)
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	tabGroupID := c.Param("id")

	var tabGroup db.TabGroup
	if result := db.GetDB().Where("id = ? AND user_id = ?", tabGroupID, userID).First(&tabGroup); result.Error != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "tab group not found"})
		return
	}

	if result := db.GetDB().Delete(&tabGroup); result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete tab group"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "tab group deleted"})
}
