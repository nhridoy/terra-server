package api

import (
	"encoding/json"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/termvault/termvault/internal/auth"
	"github.com/termvault/termvault/internal/db"
)

type CreateWorkspaceRequest struct {
	Name    string   `json:"name" binding:"required"`
	Layout  string   `json:"layout" binding:"required"`
	HostIDs []string `json:"hostIds"`
}

type UpdateWorkspaceRequest struct {
	Name    *string `json:"name"`
	Layout  *string `json:"layout"`
	HostIDs []string `json:"hostIds"`
}

func ListWorkspaces(c *gin.Context) {
	userID := auth.GetUserID(c)
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	var workspaces []db.Workspace
	if result := db.GetDB().Where("user_id = ?", userID).Order("created_at DESC").Find(&workspaces); result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch workspaces"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"workspaces": workspaces})
}

func CreateWorkspace(c *gin.Context) {
	userID := auth.GetUserID(c)
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	var req CreateWorkspaceRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	hostIDsJSON := "[]"
	if len(req.HostIDs) > 0 {
		b, _ := json.Marshal(req.HostIDs)
		hostIDsJSON = string(b)
	}

	workspace := db.Workspace{
		UserID:  userID,
		Name:    req.Name,
		Layout:  req.Layout,
		HostIDs: hostIDsJSON,
	}

	if result := db.GetDB().Create(&workspace); result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create workspace"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"workspace": workspace})
}

func UpdateWorkspace(c *gin.Context) {
	userID := auth.GetUserID(c)
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	workspaceID := c.Param("id")

	var workspace db.Workspace
	if result := db.GetDB().Where("id = ? AND user_id = ?", workspaceID, userID).First(&workspace); result.Error != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "workspace not found"})
		return
	}

	var req UpdateWorkspaceRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.Name != nil {
		workspace.Name = *req.Name
	}
	if req.Layout != nil {
		workspace.Layout = *req.Layout
	}
	if req.HostIDs != nil {
		b, _ := json.Marshal(req.HostIDs)
		workspace.HostIDs = string(b)
	}

	if result := db.GetDB().Save(&workspace); result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update workspace"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"workspace": workspace})
}

func DeleteWorkspace(c *gin.Context) {
	userID := auth.GetUserID(c)
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	workspaceID := c.Param("id")

	var workspace db.Workspace
	if result := db.GetDB().Where("id = ? AND user_id = ?", workspaceID, userID).First(&workspace); result.Error != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "workspace not found"})
		return
	}

	if result := db.GetDB().Delete(&workspace); result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete workspace"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "workspace deleted"})
}
