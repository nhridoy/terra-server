package api

import (
	"log"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/termvault/termvault/internal/auth"
	"github.com/termvault/termvault/internal/db"
)

type CreateVaultRequest struct {
	Name        string `json:"name" binding:"required"`
	Description string `json:"description"`
}

type UpdateVaultRequest struct {
	Name        *string `json:"name"`
	Description *string `json:"description"`
}

type VaultDataResponse struct {
	Hosts    []db.Host       `json:"hosts"`
	Keys     []db.Keychain   `json:"keys"`
	Groups   []db.Group      `json:"groups"`
	Snippets []db.Snippet    `json:"snippets"`
	History  []db.SessionLog `json:"history"`
}

type UnlockVaultRequest struct {
	Password string `json:"password" binding:"required"`
}

// vaultBelongsToUser reports whether the given vault exists and is owned by the user.
func vaultBelongsToUser(userID, vaultID string) bool {
	if vaultID == "" {
		return false
	}
	var cnt int64
	db.GetDB().Model(&db.Vault{}).Where("id = ? AND user_id = ?", vaultID, userID).Count(&cnt)
	return cnt > 0
}

// strPtrValue returns the value of a *string, or "" if nil.
func strPtrValue(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// defaultVaultID returns the user's default vault id, or "" if none exists.
func defaultVaultID(userID string) string {
	var v db.Vault
	if err := db.GetDB().Where("user_id = ? AND is_default = ?", userID, true).First(&v).Error; err != nil {
		return ""
	}
	return v.ID
}

// resolveVaultID returns the requested vault id after validating ownership,
// falling back to the user's default vault when none is supplied.
func resolveVaultID(userID, requested string) (string, bool) {
	vaultID := requested
	if vaultID == "" {
		vaultID = defaultVaultID(userID)
	}
	if vaultID == "" || !vaultBelongsToUser(userID, vaultID) {
		return "", false
	}
	return vaultID, true
}

func ListVaults(c *gin.Context) {
	userID := auth.GetUserID(c)
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	// Guarantee the system vaults exist for this user (backend is the source of truth).
	ensureDefaultVaults(userID)

	var vaults []db.Vault
	if result := db.GetDB().Where("user_id = ?", userID).Order("created_at DESC").Find(&vaults); result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch vaults"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"vaults": vaults})
}

// ensureDefaultVaults creates the Personal and Team system vaults for a user
// if they do not already exist. It is idempotent and safe to call on every
// request; the unique (user_id, name) constraint handles concurrent races.
func ensureDefaultVaults(userID string) {
	defaults := []db.Vault{
		{
			UserID:         userID,
			Name:           "Personal",
			Description:    "Personal vault for individual use",
			IsDefault:      true,
			IsSystem:       true,
			EncryptedData:  []byte(""),
			IV:             []byte(""),
			Salt:           []byte(""),
		},
		{
			UserID:         userID,
			Name:           "Team",
			Description:    "Team vault for shared resources",
			IsDefault:      false,
			IsSystem:       true,
			EncryptedData:  []byte(""),
			IV:             []byte(""),
			Salt:           []byte(""),
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
		// Ignore errors (e.g. a concurrent insert hitting the unique constraint).
		_ = db.GetDB().Create(&v).Error
	}
}

func CreateVault(c *gin.Context) {
	userID := auth.GetUserID(c)
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	var req CreateVaultRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Explicit duplicate-name check for a clean 409 (the unique index is still the
	// ultimate guard against races).
	var cnt int64
	db.GetDB().Model(&db.Vault{}).Where("user_id = ? AND name = ?", userID, req.Name).Count(&cnt)
	if cnt > 0 {
		c.JSON(http.StatusConflict, gin.H{"error": "vault with this name already exists"})
		return
	}

	vault := db.Vault{
		UserID:      auth.GetUserID(c),
		Name:        req.Name,
		Description: req.Description,
		EncryptedData: []byte(""),
		IV:          []byte(""),
		Salt:        []byte(""),
	}

	if result := db.GetDB().Create(&vault); result.Error != nil {
		errMsg := strings.ToLower(result.Error.Error())
		if strings.Contains(errMsg, "unique") || strings.Contains(errMsg, "duplicate") {
			c.JSON(http.StatusConflict, gin.H{"error": "vault with this name already exists"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create vault"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"vault": vault})
}

func UpdateVault(c *gin.Context) {
	userID := auth.GetUserID(c)
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	vaultID := c.Param("id")

	var vault db.Vault
	if result := db.GetDB().Where("id = ? AND user_id = ?", vaultID, userID).First(&vault); result.Error != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "vault not found"})
		return
	}

	if vault.IsSystem {
		c.JSON(http.StatusForbidden, gin.H{"error": "system vaults cannot be modified"})
		return
	}

	var req UpdateVaultRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	updates := map[string]interface{}{}

	if req.Name != nil {
		newName := *req.Name
		// Only enforce the unique name constraint when the name actually changes.
		// Editing other fields (e.g. description) must not trigger a false conflict.
		if newName != vault.Name {
			var cnt int64
			db.GetDB().Model(&db.Vault{}).
				Where("user_id = ? AND name = ? AND id <> ?", userID, newName, vaultID).
				Count(&cnt)
			if cnt > 0 {
				c.JSON(http.StatusConflict, gin.H{"error": "vault with this name already exists"})
				return
			}
			updates["name"] = newName
		}
	}
	if req.Description != nil {
		updates["description"] = *req.Description
	}

	// Partial update: only change the provided fields. Using Save() rewrites every
	// column (including the NOT NULL blob fields), which can fail on update.
	if len(updates) > 0 {
		if result := db.GetDB().Model(&vault).Updates(updates); result.Error != nil {
			log.Printf("UpdateVault error (vault %s): %v", vaultID, result.Error)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update vault"})
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{"vault": vault})
}

func DeleteVault(c *gin.Context) {
	userID := auth.GetUserID(c)
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	vaultID := c.Param("id")

	var vault db.Vault
	if result := db.GetDB().Where("id = ? AND user_id = ?", vaultID, userID).First(&vault); result.Error != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "vault not found"})
		return
	}

	if vault.IsSystem {
		c.JSON(http.StatusForbidden, gin.H{"error": "system vaults cannot be deleted"})
		return
	}

	if result := db.GetDB().Delete(&vault); result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete vault"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "vault deleted"})
}

func GetVaultData(c *gin.Context) {
	userID := auth.GetUserID(c)
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	vaultID := c.Param("id")

	var vault db.Vault
	if result := db.GetDB().Where("id = ? AND user_id = ?", vaultID, userID).First(&vault); result.Error != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "vault not found"})
		return
	}

	var hosts []db.Host
	db.GetDB().Where("vault_id = ?", vaultID).Find(&hosts)

	var keys []db.Keychain
	db.GetDB().Where("vault_id = ?", vaultID).Find(&keys)

	var groups []db.Group
	db.GetDB().Where("vault_id = ?", vaultID).Find(&groups)

	var snippets []db.Snippet
	db.GetDB().Where("vault_id = ?", vaultID).Find(&snippets)

	var history []db.SessionLog
	db.GetDB().Where("vault_id = ?", vaultID).Order("started_at DESC").Find(&history)

	c.JSON(http.StatusOK, gin.H{"data": VaultDataResponse{
		Hosts:    hosts,
		Keys:     keys,
		Groups:   groups,
		Snippets: snippets,
		History:  history,
	}})
}

func UnlockVault(c *gin.Context) {
	userID := auth.GetUserID(c)
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	vaultID := c.Param("id")

	var vault db.Vault
	if result := db.GetDB().Where("id = ? AND user_id = ?", vaultID, userID).First(&vault); result.Error != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "vault not found"})
		return
	}

	var req UnlockVaultRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// TODO: Implement actual decryption logic
	// For now, just return success
	c.JSON(http.StatusOK, gin.H{"message": "vault unlocked", "vaultId": vaultID})
}
