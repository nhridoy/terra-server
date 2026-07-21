package api

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/termvault/termvault/internal/auth"
	"github.com/termvault/termvault/internal/db"
	"gorm.io/gorm"
)

func getPagination(c *gin.Context) (int, int) {
	limit := 100
	offset := 0
	if l := c.Query("limit"); l != "" {
		if v, err := strconv.Atoi(l); err == nil && v > 0 && v <= 500 {
			limit = v
		}
	}
	if o := c.Query("offset"); o != "" {
		if v, err := strconv.Atoi(o); err == nil && v >= 0 {
			offset = v
		}
	}
	return limit, offset
}

// ---- Hosts ----
// NOTE: These REST CRUD endpoints are not used by the Tauri client.
// The client uses local SQLite + sync (sync_push/sync_pull) for all core data.
// These endpoints exist for potential future use (web client, third-party integrations).
// Update endpoints are currently no-ops (parse request but don't apply changes).

type CreateHostRequest struct {
	VaultID    string `json:"vaultId" binding:"required"`
	GroupID    string `json:"groupId"`
	Name       string `json:"name" binding:"required,max=255"`
	Address    string `json:"address" binding:"required,max=255"`
	Port       int    `json:"port"`
	Username   string `json:"username" binding:"max=255"`
	Password   string `json:"password" binding:"max=4096"`
	PrivateKey string `json:"privateKey" binding:"max=65536"`
	Passphrase string `json:"passphrase" binding:"max=4096"`
	Color      string `json:"color" binding:"max=32"`
}

func ListHosts(c *gin.Context) {
	userID := auth.GetUserID(c)
	vaultID := c.Query("vaultId")
	limit, offset := getPagination(c)

	var hosts []db.Host
	query := db.GetDB().Where("user_id = ?", userID)
	if vaultID != "" {
		query = query.Where("vault_id = ?", vaultID)
	}
	query.Offset(offset).Limit(limit).Find(&hosts)
	c.JSON(http.StatusOK, hosts)
}

func CreateHost(c *gin.Context) {
	userID := auth.GetUserID(c)
	var req CreateHostRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	host := db.Host{
		ID:         uuid.New().String(),
		UserID:     userID,
		VaultID:    req.VaultID,
		GroupID:    req.GroupID,
		Name:       req.Name,
		Address:    req.Address,
		Port:       req.Port,
		Username:   req.Username,
		Password:   req.Password,
		PrivateKey: req.PrivateKey,
		Passphrase: req.Passphrase,
		Color:      req.Color,
	}
	if host.Port == 0 {
		host.Port = 22
	}

	if err := db.GetDB().Create(&host).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create host"})
		return
	}
	c.JSON(http.StatusCreated, host)
}

func UpdateHost(c *gin.Context) {
	userID := auth.GetUserID(c)
	id := c.Param("id")

	var host db.Host
	if result := db.GetDB().Where("id = ? AND user_id = ?", id, userID).First(&host); result.Error != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "host not found"})
		return
	}

	var req CreateHostRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	db.GetDB().Save(&host)
	c.JSON(http.StatusOK, host)
}

func DeleteHost(c *gin.Context) {
	userID := auth.GetUserID(c)
	id := c.Param("id")

	result := db.GetDB().Where("id = ? AND user_id = ?", id, userID).Delete(&db.Host{})
	if result.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "host not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "host deleted"})
}

// ---- Groups ----

type CreateGroupRequest struct {
	VaultID  string `json:"vaultId" binding:"required"`
	ParentID string `json:"parentId"`
	Name     string `json:"name" binding:"required"`
}

func ListGroups(c *gin.Context) {
	userID := auth.GetUserID(c)
	vaultID := c.Query("vaultId")
	limit, offset := getPagination(c)

	var groups []db.Group
	query := db.GetDB().Where("user_id = ?", userID)
	if vaultID != "" {
		query = query.Where("vault_id = ?", vaultID)
	}
	query.Offset(offset).Limit(limit).Find(&groups)
	c.JSON(http.StatusOK, groups)
}

func CreateGroup(c *gin.Context) {
	userID := auth.GetUserID(c)
	var req CreateGroupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	group := db.Group{
		ID:       uuid.New().String(),
		UserID:   userID,
		VaultID:  req.VaultID,
		ParentID: req.ParentID,
		Name:     req.Name,
	}

	if err := db.GetDB().Create(&group).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create group"})
		return
	}
	c.JSON(http.StatusCreated, group)
}

func UpdateGroup(c *gin.Context) {
	userID := auth.GetUserID(c)
	id := c.Param("id")

	var group db.Group
	if result := db.GetDB().Where("id = ? AND user_id = ?", id, userID).First(&group); result.Error != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "group not found"})
		return
	}

	var req CreateGroupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	db.GetDB().Save(&group)
	c.JSON(http.StatusOK, group)
}

func DeleteGroup(c *gin.Context) {
	userID := auth.GetUserID(c)
	id := c.Param("id")

	result := db.GetDB().Where("id = ? AND user_id = ?", id, userID).Delete(&db.Group{})
	if result.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "group not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "group deleted"})
}

// ---- Vaults ----

func ListVaults(c *gin.Context) {
	userID := auth.GetUserID(c)
	limit, offset := getPagination(c)

	var vaults []db.Vault
	db.GetDB().Where("user_id = ?", userID).Offset(offset).Limit(limit).Find(&vaults)
	c.JSON(http.StatusOK, vaults)
}

func CreateVault(c *gin.Context) {
	userID := auth.GetUserID(c)
	var req struct {
		Name        string `json:"name" binding:"required"`
		Description string `json:"description"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var count int64
	db.GetDB().Model(&db.Vault{}).Where("user_id = ? AND name = ?", userID, req.Name).Count(&count)
	if count > 0 {
		c.JSON(http.StatusConflict, gin.H{"error": "vault name already exists"})
		return
	}

	vault := db.Vault{
		ID:          uuid.New().String(),
		UserID:      userID,
		Name:        req.Name,
		Description: req.Description,
	}

	if err := db.GetDB().Create(&vault).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create vault"})
		return
	}
	c.JSON(http.StatusCreated, vault)
}

func UpdateVault(c *gin.Context) {
	userID := auth.GetUserID(c)
	id := c.Param("id")

	var vault db.Vault
	if result := db.GetDB().Where("id = ? AND user_id = ?", id, userID).First(&vault); result.Error != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "vault not found"})
		return
	}

	if vault.IsSystem {
		c.JSON(http.StatusForbidden, gin.H{"error": "cannot modify system vault"})
		return
	}

	var req struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.Name != "" {
		var count int64
		db.GetDB().Model(&db.Vault{}).Where("user_id = ? AND name = ? AND id != ?", userID, req.Name, id).Count(&count)
		if count > 0 {
			c.JSON(http.StatusConflict, gin.H{"error": "vault name already exists"})
			return
		}
	}

	db.GetDB().Save(&vault)
	c.JSON(http.StatusOK, vault)
}

func DeleteVault(c *gin.Context) {
	userID := auth.GetUserID(c)
	id := c.Param("id")

	var vault db.Vault
	if result := db.GetDB().Where("id = ? AND user_id = ?", id, userID).First(&vault); result.Error != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "vault not found"})
		return
	}

	if vault.IsSystem {
		c.JSON(http.StatusForbidden, gin.H{"error": "cannot delete system vault"})
		return
	}

	if err := db.InTransaction(func(tx *gorm.DB) error {
		tx.Where("vault_id = ?", id).Delete(&db.Host{})
		tx.Where("vault_id = ?", id).Delete(&db.Group{})
		tx.Where("vault_id = ?", id).Delete(&db.Keychain{})
		tx.Where("vault_id = ?", id).Delete(&db.Snippet{})
		tx.Where("vault_id = ?", id).Delete(&db.Workspace{})
		tx.Where("vault_id = ?", id).Delete(&db.TabGroup{})
		return tx.Delete(&vault).Error
	}); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete vault"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "vault deleted"})
}

// ---- Keychain ----

type CreateKeyRequest struct {
	VaultID string `json:"vaultId" binding:"required"`
	Name    string `json:"name" binding:"required,max=255"`
	Type    string `json:"type" binding:"required,max=50"`
	Data    string `json:"data" binding:"max=65536"`
}

func ListKeys(c *gin.Context) {
	userID := auth.GetUserID(c)
	vaultID := c.Query("vaultId")
	limit, offset := getPagination(c)

	var keys []db.Keychain
	query := db.GetDB().Where("user_id = ?", userID)
	if vaultID != "" {
		query = query.Where("vault_id = ?", vaultID)
	}
	query.Offset(offset).Limit(limit).Find(&keys)
	c.JSON(http.StatusOK, keys)
}

func CreateKey(c *gin.Context) {
	userID := auth.GetUserID(c)
	var req CreateKeyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	key := db.Keychain{
		ID:      uuid.New().String(),
		UserID:  userID,
		VaultID: req.VaultID,
		Name:    req.Name,
		Type:    req.Type,
		Data:    req.Data,
	}

	if err := db.GetDB().Create(&key).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create key"})
		return
	}
	c.JSON(http.StatusCreated, key)
}

func UpdateKey(c *gin.Context) {
	userID := auth.GetUserID(c)
	id := c.Param("id")

	var key db.Keychain
	if result := db.GetDB().Where("id = ? AND user_id = ?", id, userID).First(&key); result.Error != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "key not found"})
		return
	}

	var req CreateKeyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	db.GetDB().Save(&key)
	c.JSON(http.StatusOK, key)
}

func DeleteKey(c *gin.Context) {
	userID := auth.GetUserID(c)
	id := c.Param("id")

	result := db.GetDB().Where("id = ? AND user_id = ?", id, userID).Delete(&db.Keychain{})
	if result.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "key not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "key deleted"})
}

// ---- Snippets ----

type CreateSnippetRequest struct {
	VaultID string `json:"vaultId" binding:"required"`
	Name    string `json:"name" binding:"required"`
	Command string `json:"command" binding:"required"`
}

func ListSnippets(c *gin.Context) {
	userID := auth.GetUserID(c)
	vaultID := c.Query("vaultId")
	limit, offset := getPagination(c)

	var snippets []db.Snippet
	query := db.GetDB().Where("user_id = ?", userID)
	if vaultID != "" {
		query = query.Where("vault_id = ?", vaultID)
	}
	query.Offset(offset).Limit(limit).Find(&snippets)
	c.JSON(http.StatusOK, snippets)
}

func CreateSnippet(c *gin.Context) {
	userID := auth.GetUserID(c)
	var req CreateSnippetRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	snippet := db.Snippet{
		ID:      uuid.New().String(),
		UserID:  userID,
		VaultID: req.VaultID,
		Name:    req.Name,
		Command: req.Command,
	}

	if err := db.GetDB().Create(&snippet).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create snippet"})
		return
	}
	c.JSON(http.StatusCreated, snippet)
}

func UpdateSnippet(c *gin.Context) {
	userID := auth.GetUserID(c)
	id := c.Param("id")

	var snippet db.Snippet
	if result := db.GetDB().Where("id = ? AND user_id = ?", id, userID).First(&snippet); result.Error != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "snippet not found"})
		return
	}

	var req CreateSnippetRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	db.GetDB().Save(&snippet)
	c.JSON(http.StatusOK, snippet)
}

func DeleteSnippet(c *gin.Context) {
	userID := auth.GetUserID(c)
	id := c.Param("id")

	result := db.GetDB().Where("id = ? AND user_id = ?", id, userID).Delete(&db.Snippet{})
	if result.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "snippet not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "snippet deleted"})
}

// ---- Workspaces ----

type CreateWorkspaceRequest struct {
	VaultID string `json:"vaultId" binding:"required"`
	Name    string `json:"name" binding:"required"`
	Layout  string `json:"layout"`
}

func ListWorkspaces(c *gin.Context) {
	userID := auth.GetUserID(c)
	vaultID := c.Query("vaultId")
	limit, offset := getPagination(c)

	var workspaces []db.Workspace
	query := db.GetDB().Where("user_id = ?", userID)
	if vaultID != "" {
		query = query.Where("vault_id = ?", vaultID)
	}
	query.Offset(offset).Limit(limit).Find(&workspaces)
	c.JSON(http.StatusOK, workspaces)
}

func CreateWorkspace(c *gin.Context) {
	userID := auth.GetUserID(c)
	var req CreateWorkspaceRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	workspace := db.Workspace{
		ID:      uuid.New().String(),
		UserID:  userID,
		VaultID: req.VaultID,
		Name:    req.Name,
		Layout:  req.Layout,
	}

	if err := db.GetDB().Create(&workspace).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create workspace"})
		return
	}
	c.JSON(http.StatusCreated, workspace)
}

func UpdateWorkspace(c *gin.Context) {
	userID := auth.GetUserID(c)
	id := c.Param("id")

	var workspace db.Workspace
	if result := db.GetDB().Where("id = ? AND user_id = ?", id, userID).First(&workspace); result.Error != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "workspace not found"})
		return
	}

	var req CreateWorkspaceRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	db.GetDB().Save(&workspace)
	c.JSON(http.StatusOK, workspace)
}

func DeleteWorkspace(c *gin.Context) {
	userID := auth.GetUserID(c)
	id := c.Param("id")

	result := db.GetDB().Where("id = ? AND user_id = ?", id, userID).Delete(&db.Workspace{})
	if result.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "workspace not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "workspace deleted"})
}

// ---- Tab Groups ----

type CreateTabGroupRequest struct {
	VaultID string `json:"vaultId" binding:"required"`
	Name    string `json:"name" binding:"required"`
	Tabs    string `json:"tabs"`
}

func ListTabGroups(c *gin.Context) {
	userID := auth.GetUserID(c)
	vaultID := c.Query("vaultId")
	limit, offset := getPagination(c)

	var tabGroups []db.TabGroup
	query := db.GetDB().Where("user_id = ?", userID)
	if vaultID != "" {
		query = query.Where("vault_id = ?", vaultID)
	}
	query.Offset(offset).Limit(limit).Find(&tabGroups)
	c.JSON(http.StatusOK, tabGroups)
}

func CreateTabGroup(c *gin.Context) {
	userID := auth.GetUserID(c)
	var req CreateTabGroupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	tabGroup := db.TabGroup{
		ID:      uuid.New().String(),
		UserID:  userID,
		VaultID: req.VaultID,
		Name:    req.Name,
		Tabs:    req.Tabs,
	}

	if err := db.GetDB().Create(&tabGroup).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create tab group"})
		return
	}
	c.JSON(http.StatusCreated, tabGroup)
}

func UpdateTabGroup(c *gin.Context) {
	userID := auth.GetUserID(c)
	id := c.Param("id")

	var tabGroup db.TabGroup
	if result := db.GetDB().Where("id = ? AND user_id = ?", id, userID).First(&tabGroup); result.Error != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "tab group not found"})
		return
	}

	var req CreateTabGroupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	db.GetDB().Save(&tabGroup)
	c.JSON(http.StatusOK, tabGroup)
}

func DeleteTabGroup(c *gin.Context) {
	userID := auth.GetUserID(c)
	id := c.Param("id")

	result := db.GetDB().Where("id = ? AND user_id = ?", id, userID).Delete(&db.TabGroup{})
	if result.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "tab group not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "tab group deleted"})
}

// ---- Settings ----

func GetSettings(c *gin.Context) {
	userID := auth.GetUserID(c)

	var settings db.Settings
	if result := db.GetDB().Where("user_id = ?", userID).First(&settings); result.Error != nil {
		settings = db.Settings{
			ID:          uuid.New().String(),
			UserID:      userID,
			Theme:       "dark",
			FontFamily:  "JetBrains Mono",
			FontSize:    14,
			CursorStyle: "block",
		}
		db.GetDB().Create(&settings)
	}

	c.JSON(http.StatusOK, settings)
}

func UpdateSettings(c *gin.Context) {
	userID := auth.GetUserID(c)

	var settings db.Settings
	if result := db.GetDB().Where("user_id = ?", userID).First(&settings); result.Error != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "settings not found"})
		return
	}

	var req struct {
		Theme       string `json:"theme"`
		FontFamily  string `json:"fontFamily"`
		FontSize    int    `json:"fontSize"`
		CursorStyle string `json:"cursorStyle"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	db.GetDB().Save(&settings)
	c.JSON(http.StatusOK, settings)
}
