package api

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/mitchellh/mapstructure"
	"github.com/termvault/termvault/internal/auth"
	"github.com/termvault/termvault/internal/db"
)

const (
	maxPasswordLength   = 4096
	maxPrivateKeyLength = 65536
	maxPassphraseLength = 4096
	maxNameLength       = 255
	maxDescriptionLength = 1024
)

type SyncPushRequest struct {
	Table   string           `json:"table" binding:"required"`
	Records []map[string]any `json:"records" binding:"required"`
}

type SyncPushResponse struct {
	Results []SyncResult `json:"results"`
}

type SyncResult struct {
	ID        string `json:"id"`
	Status    string `json:"status"`
	Operation string `json:"operation"`
}

type SyncFullResponse struct {
	Hosts      []db.Host      `json:"hosts"`
	Groups     []db.Group     `json:"groups"`
	Vaults     []db.Vault     `json:"vaults"`
	Keychain   []db.Keychain  `json:"keychain"`
	Snippets   []db.Snippet   `json:"snippets"`
	Workspaces []db.Workspace `json:"workspaces"`
	TabGroups  []db.TabGroup  `json:"tabGroups"`
	Settings   []db.Settings  `json:"settings"`
}

func SyncFull(c *gin.Context) {
	userID := auth.GetUserID(c)

	var hosts []db.Host
	db.GetDB().Where("user_id = ?", userID).Find(&hosts)

	var groups []db.Group
	db.GetDB().Where("user_id = ?", userID).Find(&groups)

	var vaults []db.Vault
	db.GetDB().Where("user_id = ?", userID).Find(&vaults)

	var keychain []db.Keychain
	db.GetDB().Where("user_id = ?", userID).Find(&keychain)

	var snippets []db.Snippet
	db.GetDB().Where("user_id = ?", userID).Find(&snippets)

	var workspaces []db.Workspace
	db.GetDB().Where("user_id = ?", userID).Find(&workspaces)

	var tabGroups []db.TabGroup
	db.GetDB().Where("user_id = ?", userID).Find(&tabGroups)

	var settings []db.Settings
	db.GetDB().Where("user_id = ?", userID).Find(&settings)

	c.JSON(http.StatusOK, SyncFullResponse{
		Hosts:      hosts,
		Groups:     groups,
		Vaults:     vaults,
		Keychain:   keychain,
		Snippets:   snippets,
		Workspaces: workspaces,
		TabGroups:  tabGroups,
		Settings:   settings,
	})
}

// verifyOwnership checks that a record with the given ID belongs to the authenticated user.
// Returns true if the record exists and belongs to the user, false otherwise.
func verifyOwnership(table, recordID, userID string) bool {
	var count int64
	db.GetDB().Table(table).Where("id = ? AND user_id = ?", recordID, userID).Count(&count)
	return count > 0
}

// ErrConflict is returned when the client's record is older than the server's.
var ErrConflict = errors.New("record conflict: server has newer version")

// ErrOwnershipMismatch is returned when a user tries to modify a record they don't own.
var ErrOwnershipMismatch = errors.New("record does not belong to this user")

// parseTimestamp parses an updated_at value from the client (RFC3339 string or time.Time).
func parseTimestamp(v any) (time.Time, error) {
	switch t := v.(type) {
	case string:
		if parsed, err := time.Parse(time.RFC3339, t); err == nil {
			return parsed, nil
		}
		if parsed, err := time.Parse("2006-01-02T15:04:05", t); err == nil {
			return parsed, nil
		}
		return time.Time{}, errors.New("invalid timestamp format")
	case time.Time:
		return t, nil
	default:
		return time.Time{}, errors.New("unexpected timestamp type")
	}
}

// upsertWithTimestampCheck inserts a new record or updates an existing one after comparing updated_at timestamps.
// Returns ErrConflict if the incoming record is older than the server's version.
func upsertWithTimestampCheck(table, recordID, userID string, record map[string]any, dest any) error {
	var count int64
	db.GetDB().Table(table).Where("id = ?", recordID).Count(&count)
	if count == 0 {
		return db.GetDB().Create(dest).Error
	}

	if !verifyOwnership(table, recordID, userID) {
		return ErrOwnershipMismatch
	}

	incomingTime, err := parseTimestamp(record["updated_at"])
	if err != nil {
		return fmt.Errorf("invalid timestamp: %w", err)
	}

	var existingTime time.Time
	if result := db.GetDB().Table(table).Where("id = ?", recordID).Select("updated_at").Scan(&existingTime); result.Error != nil {
		return db.GetDB().Save(dest).Error
	}

	if !incomingTime.After(existingTime) {
		return ErrConflict
	}

	return db.GetDB().Save(dest).Error
}

func SyncPush(c *gin.Context) {
	userID := auth.GetUserID(c)

	var req SyncPushRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	allowed := map[string]bool{
		"hosts": true, "groups": true, "vaults": true, "keychain": true,
		"snippets": true, "workspaces": true, "tab_groups": true, "settings": true,
	}
	if !allowed[req.Table] {
		c.JSON(http.StatusBadRequest, gin.H{"error": "unknown table"})
		return
	}

	// Enforce max batch size to prevent abuse
	if len(req.Records) > 500 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "batch too large, max 500 records"})
		return
	}

	var results []SyncResult

	// Process each record
	for _, record := range req.Records {
		recordID := toString(record["id"])
		if recordID == "" {
			continue // skip records without an ID
		}

		// Check if this record is marked for deletion
		isDeleted := toBool(record["is_deleted"])
		
		var operation string
		var err error
		
		if isDeleted {
			// Delete the record
			operation = "delete"
			err = deleteRecord(req.Table, recordID, userID)
		} else {
			// Upsert the record
			operation = "upsert"
			err = upsertRecord(req.Table, recordID, userID, record)
		}

		// Build result
		result := SyncResult{
			ID:        recordID,
			Status:    "ok",
			Operation: operation,
		}
		
		if err != nil {
			if errors.Is(err, ErrConflict) {
				result.Status = "conflict"
			} else {
				result.Status = "error"
			}
		}
		
		results = append(results, result)
	}

	c.JSON(http.StatusOK, SyncPushResponse{Results: results})
}

// deleteRecord deletes a record by ID with ownership verification.
// If the record doesn't exist, returns nil (idempotent).
func deleteRecord(table, recordID, userID string) error {
	var count int64
	db.GetDB().Table(table).Where("id = ?", recordID).Count(&count)
	if count == 0 {
		return nil // Already deleted — idempotent success
	}
	if !verifyOwnership(table, recordID, userID) {
		return ErrOwnershipMismatch
	}

	return db.GetDB().Table(table).Where("id = ?", recordID).Delete(nil).Error
}

// validateRecordFields checks credential field lengths for hosts and keychain tables.
// Returns an error if any field exceeds its maximum allowed length.
func validateRecordFields(table string, record map[string]any) error {
	switch table {
	case "hosts":
		if password := toString(record["password"]); len(password) > maxPasswordLength {
			return fmt.Errorf("password exceeds maximum length of %d", maxPasswordLength)
		}
		if privateKey := toString(record["private_key"]); len(privateKey) > maxPrivateKeyLength {
			return fmt.Errorf("private_key exceeds maximum length of %d", maxPrivateKeyLength)
		}
		if passphrase := toString(record["passphrase"]); len(passphrase) > maxPassphraseLength {
			return fmt.Errorf("passphrase exceeds maximum length of %d", maxPassphraseLength)
		}
		if name := toString(record["name"]); len(name) > maxNameLength {
			return fmt.Errorf("name exceeds maximum length of %d", maxNameLength)
		}
	case "keychain":
		if encKey := toString(record["encrypted_private_key"]); len(encKey) > maxPrivateKeyLength {
			return fmt.Errorf("encrypted_private_key exceeds maximum length of %d", maxPrivateKeyLength)
		}
		if name := toString(record["name"]); len(name) > maxNameLength {
			return fmt.Errorf("name exceeds maximum length of %d", maxNameLength)
		}
		if desc := toString(record["description"]); len(desc) > maxDescriptionLength {
			return fmt.Errorf("description exceeds maximum length of %d", maxDescriptionLength)
		}
	}
	return nil
}

// upsertRecord inserts or updates a record with ownership verification and timestamp conflict check.
func upsertRecord(table, recordID, userID string, record map[string]any) error {
	record["user_id"] = userID

	// Validate field lengths before upserting
	if err := validateRecordFields(table, record); err != nil {
		return err
	}

	switch table {
	case "hosts":
		var host db.Host
		mapToStruct(record, &host)
		return upsertWithTimestampCheck("hosts", recordID, userID, record, &host)
	case "groups":
		var group db.Group
		mapToStruct(record, &group)
		return upsertWithTimestampCheck("groups", recordID, userID, record, &group)
	case "vaults":
		var vault db.Vault
		mapToStruct(record, &vault)
		return upsertWithTimestampCheck("vaults", recordID, userID, record, &vault)
	case "keychain":
		var key db.Keychain
		mapToStruct(record, &key)
		return upsertWithTimestampCheck("keychain", recordID, userID, record, &key)
	case "snippets":
		var snippet db.Snippet
		mapToStruct(record, &snippet)
		return upsertWithTimestampCheck("snippets", recordID, userID, record, &snippet)
	case "workspaces":
		var workspace db.Workspace
		mapToStruct(record, &workspace)
		return upsertWithTimestampCheck("workspaces", recordID, userID, record, &workspace)
	case "tab_groups":
		var tabGroup db.TabGroup
		mapToStruct(record, &tabGroup)
		return upsertWithTimestampCheck("tab_groups", recordID, userID, record, &tabGroup)
	case "settings":
		var settings db.Settings
		mapToStruct(record, &settings)
		return upsertWithTimestampCheck("settings", recordID, userID, record, &settings)
	default:
		return ErrOwnershipMismatch
	}
}

// mapToStruct copies fields from a map to a struct pointer using mapstructure.
// Uses the "json" tag for field name mapping. Fields with json:"-" are handled
// explicitly since mapstructure skips them.
func mapToStruct(m map[string]any, dest any) {
	config := &mapstructure.DecoderConfig{
		Result:  dest,
		TagName: "json",
	}
	decoder, err := mapstructure.NewDecoder(config)
	if err != nil {
		return
	}
	decoder.Decode(m)

	// Fields with json:"-" tags are skipped by mapstructure.
	// Assign them explicitly from the map.
	switch d := dest.(type) {
	case *db.Host:
		d.Password = toString(m["password"])
		d.PrivateKey = toString(m["private_key"])
		d.Passphrase = toString(m["passphrase"])
	case *db.Keychain:
		d.Data = toString(m["data"])
	}
}

func toString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func toBool(v any) bool {
	if b, ok := v.(bool); ok {
		return b
	}
	return false
}
