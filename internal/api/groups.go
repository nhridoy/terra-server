package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/termvault/termvault/internal/auth"
	"github.com/termvault/termvault/internal/db"
)

type CreateGroupRequest struct {
	Name     string  `json:"name" binding:"required"`
	ParentID *string `json:"parentId"`
	VaultID  *string `json:"vaultId"`
}

type UpdateGroupRequest struct {
	Name     *string `json:"name"`
	ParentID *string `json:"parentId"`
}

func ListGroups(c *gin.Context) {
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

	var groups []db.Group
	if result := q.Order("sort_order ASC").Find(&groups); result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch groups"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"groups": groups})
}

func CreateGroup(c *gin.Context) {
	userID := auth.GetUserID(c)
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	var req CreateGroupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	vaultID, ok := resolveVaultID(userID, strPtrValue(req.VaultID))
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "a valid vault is required"})
		return
	}

	group := db.Group{
		UserID:   userID,
		VaultID:  &vaultID,
		Name:     req.Name,
		ParentID: req.ParentID,
	}

	if result := db.GetDB().Create(&group); result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create group"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"group": group})
}

func UpdateGroup(c *gin.Context) {
	userID := auth.GetUserID(c)
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	groupID := c.Param("id")

	var group db.Group
	if result := db.GetDB().Where("id = ? AND user_id = ?", groupID, userID).First(&group); result.Error != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "group not found"})
		return
	}

	var req UpdateGroupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.Name != nil {
		group.Name = *req.Name
	}
	if req.ParentID != nil {
		group.ParentID = req.ParentID
	}

	if result := db.GetDB().Save(&group); result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update group"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"group": group})
}

func DeleteGroup(c *gin.Context) {
	userID := auth.GetUserID(c)
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	groupID := c.Param("id")

	var group db.Group
	if result := db.GetDB().Where("id = ? AND user_id = ?", groupID, userID).First(&group); result.Error != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "group not found"})
		return
	}

	if result := db.GetDB().Delete(&group); result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete group"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "group deleted"})
}
