package api

import (
	"encoding/json"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/termvault/termvault/internal/auth"
	"github.com/termvault/termvault/internal/db"
)

type CreateHostRequest struct {
	Name      string   `json:"name" binding:"required"`
	Address   string   `json:"address" binding:"required"`
	Port      int      `json:"port"`
	Username  string   `json:"username"`
	AuthType  string   `json:"authType"`
	Password  string   `json:"password"`
	KeyID     string   `json:"keyId"`
	GroupID   *string  `json:"groupId"`
	Tags      []string `json:"tags"`
	Color     string   `json:"color"`
	Icon      string   `json:"icon"`
	SortOrder int      `json:"sortOrder"`
	VaultID   *string  `json:"vaultId"`
}

type UpdateHostRequest struct {
	Name      *string  `json:"name"`
	Address   *string  `json:"address"`
	Port      *int     `json:"port"`
	Username  *string  `json:"username"`
	AuthType  *string  `json:"authType"`
	Password  *string  `json:"password"`
	KeyID     *string  `json:"keyId"`
	GroupID   *string  `json:"groupId"`
	Tags      []string `json:"tags"`
	Color     *string  `json:"color"`
	Icon      *string  `json:"icon"`
	SortOrder *int     `json:"sortOrder"`
}

// ListHosts returns all hosts for the authenticated user
func ListHosts(c *gin.Context) {
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

	var hosts []db.Host
	if result := q.Order("sort_order ASC").Find(&hosts); result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch hosts"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"hosts": hosts})
}

// CreateHost creates a new host
func CreateHost(c *gin.Context) {
	userID := auth.GetUserID(c)
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	var req CreateHostRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Default port
	if req.Port == 0 {
		req.Port = 22
	}

	vaultID, ok := resolveVaultID(userID, strPtrValue(req.VaultID))
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "a valid vault is required"})
		return
	}

	// Convert tags to JSON string
	tagsJSON := "[]"
	if len(req.Tags) > 0 {
		tagsBytes, _ := json.Marshal(req.Tags)
		tagsJSON = string(tagsBytes)
	}

	host := db.Host{
		UserID:    userID,
		VaultID:   &vaultID,
		Name:      req.Name,
		Address:   req.Address,
		Hostname:  req.Address,
		Port:      req.Port,
		Username:  req.Username,
		GroupID:   req.GroupID,
		Tags:      tagsJSON,
		Color:     req.Color,
		Icon:      req.Icon,
		SortOrder: req.SortOrder,
	}

	if req.Password != "" {
		host.Password = req.Password
	}

	if req.KeyID != "" {
		var key db.Keychain
		if err := db.GetDB().Where("id = ? AND user_id = ?", req.KeyID, userID).First(&key).Error; err == nil {
			host.PrivateKey = key.EncryptedPrivKey
		}
	}

	if result := db.GetDB().Create(&host); result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create host"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"host": host})
}

// GetHost returns a specific host
func GetHost(c *gin.Context) {
	userID := auth.GetUserID(c)
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	hostID := c.Param("id")

	var host db.Host
	if result := db.GetDB().Where("id = ? AND user_id = ?", hostID, userID).First(&host); result.Error != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "host not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"host": host})
}

// UpdateHost updates an existing host
func UpdateHost(c *gin.Context) {
	userID := auth.GetUserID(c)
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	hostID := c.Param("id")

	var host db.Host
	if result := db.GetDB().Where("id = ? AND user_id = ?", hostID, userID).First(&host); result.Error != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "host not found"})
		return
	}

	var req UpdateHostRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Update fields
	if req.Name != nil {
		host.Name = *req.Name
	}
	if req.Address != nil {
		host.Address = *req.Address
		host.Hostname = *req.Address
	}
	if req.Port != nil {
		host.Port = *req.Port
	}
	if req.Username != nil {
		host.Username = *req.Username
	}
	if req.GroupID != nil {
		host.GroupID = req.GroupID
	}
	if req.Tags != nil {
		tagsBytes, _ := json.Marshal(req.Tags)
		host.Tags = string(tagsBytes)
	}
	if req.Color != nil {
		host.Color = *req.Color
	}
	if req.Icon != nil {
		host.Icon = *req.Icon
	}
	if req.SortOrder != nil {
		host.SortOrder = *req.SortOrder
	}
	if req.Password != nil {
		host.Password = *req.Password
	}
	if req.KeyID != nil && *req.KeyID != "" {
		var key db.Keychain
		if err := db.GetDB().Where("id = ? AND user_id = ?", *req.KeyID, userID).First(&key).Error; err == nil {
			host.PrivateKey = key.EncryptedPrivKey
		}
	}

	if result := db.GetDB().Save(&host); result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update host"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"host": host})
}

// DeleteHost deletes a host
func DeleteHost(c *gin.Context) {
	userID := auth.GetUserID(c)
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	hostID := c.Param("id")

	var host db.Host
	if result := db.GetDB().Where("id = ? AND user_id = ?", hostID, userID).First(&host); result.Error != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "host not found"})
		return
	}

	if result := db.GetDB().Delete(&host); result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete host"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "host deleted"})
}
