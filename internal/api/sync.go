package api

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/termvault/termvault/internal/db"
)

type SyncRecord struct {
	TableName string    `json:"tableName"`
	RecordID  string    `json:"recordId"`
	Data      string    `json:"data"`
	UpdatedAt time.Time `json:"updatedAt"`
	DeviceID  string    `json:"deviceId"`
	IsDeleted bool      `json:"isDeleted,omitempty"`
}

type SyncPushRequest struct {
	Records  []SyncRecord `json:"records"`
	DeviceID string       `json:"deviceId"`
}

type SyncPullResponse struct {
	Records   []SyncRecord `json:"records"`
	SyncToken string       `json:"syncToken"`
	HasMore   bool         `json:"hasMore"`
}

func SyncPush(c *gin.Context) {
	userID := c.GetString("userId")
	var req SyncPushRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	conflicts := []SyncRecord{}
	for _, record := range req.Records {
		var existing db.SyncTracking
		result := db.DB.Where("table_name = ? AND record_id = ? AND user_id = ?",
			record.TableName, record.RecordID, userID).First(&existing)

		if result.Error == nil {
			if !existing.UpdatedAt.Before(record.UpdatedAt) {
				fullRecord := fetchFullRecord(record.TableName, record.RecordID, userID)
				conflicts = append(conflicts, SyncRecord{
					TableName: record.TableName,
					RecordID:  record.RecordID,
					Data:      fullRecord,
					UpdatedAt: existing.UpdatedAt,
					DeviceID:  existing.DeviceID,
					IsDeleted: existing.IsDeleted,
				})
				continue
			}
		}

		upsertRecord(userID, record)
	}

	var syncState db.SyncState
	db.DB.Where("user_id = ? AND device_id = ?", userID, req.DeviceID).First(&syncState)
	syncState.UserID = userID
	syncState.DeviceID = req.DeviceID
	syncState.LastSyncAt = time.Now()
	db.DB.Save(&syncState)

	c.JSON(http.StatusOK, gin.H{
		"status":    "ok",
		"accepted":  len(req.Records) - len(conflicts),
		"conflicts": conflicts,
	})
}

func SyncPull(c *gin.Context) {
	userID := c.GetString("userId")
	since := c.Query("since")
	deviceID := c.Query("deviceId")

	sinceTime, err := time.Parse(time.RFC3339, since)
	if err != nil {
		sinceTime = time.Now().Add(-24 * time.Hour)
	}

	records := []SyncRecord{}
	var tracking []db.SyncTracking
	db.DB.Where("user_id = ? AND updated_at > ? AND device_id != ?", userID, sinceTime, deviceID).Find(&tracking)

	for _, t := range tracking {
		fullData := fetchFullRecord(t.TableName, t.RecordID, userID)
		records = append(records, SyncRecord{
			TableName: t.TableName,
			RecordID:  t.RecordID,
			Data:      fullData,
			UpdatedAt: t.UpdatedAt,
			DeviceID:  t.DeviceID,
			IsDeleted: t.IsDeleted,
		})
	}

	c.JSON(http.StatusOK, SyncPullResponse{
		Records:   records,
		SyncToken: time.Now().Format(time.RFC3339),
		HasMore:   false,
	})
}

func SyncFull(c *gin.Context) {
	userID := c.GetString("userId")
	records := []SyncRecord{}

	type tableRow struct {
		TableName string
		ID        string
		Data      string
		UpdatedAt time.Time
	}

	queries := []struct {
		TableName string
		Query     string
	}{
		{"vaults", "SELECT id, updated_at, json_object('id', id, 'user_id', user_id, 'name', name, 'description', description, 'is_default', is_default, 'encrypted_data', encrypted_data, 'created_at', created_at, 'updated_at', updated_at) AS data FROM vaults WHERE user_id = ?"},
		{"hosts", "SELECT id, updated_at, json_object('id', id, 'user_id', user_id, 'vault_id', vault_id, 'group_id', group_id, 'name', name, 'hostname', hostname, 'address', address, 'port', port, 'username', username, 'auth_method', auth_method, 'tags', tags, 'color', color, 'icon', icon, 'sort_order', sort_order, 'created_at', created_at, 'updated_at', updated_at) AS data FROM hosts WHERE user_id = ?"},
		{"groups", "SELECT id, COALESCE(updated_at, created_at) AS updated_at, json_object('id', id, 'user_id', user_id, 'vault_id', vault_id, 'parent_id', parent_id, 'name', name, 'sort_order', sort_order, 'created_at', created_at, 'updated_at', COALESCE(updated_at, created_at)) AS data FROM groups WHERE user_id = ?"},
		{"keychain", "SELECT id, COALESCE(updated_at, created_at) AS updated_at, json_object('id', id, 'user_id', user_id, 'vault_id', vault_id, 'name', name, 'description', description, 'key_type', key_type, 'public_key', public_key, 'encrypted_private_key', encrypted_private_key, 'fingerprint', fingerprint, 'created_at', created_at, 'updated_at', COALESCE(updated_at, created_at)) AS data FROM keychain WHERE user_id = ?"},
		{"snippets", "SELECT id, updated_at, json_object('id', id, 'user_id', user_id, 'vault_id', vault_id, 'name', name, 'command', command, 'description', description, 'tags', tags, 'created_at', created_at, 'updated_at', updated_at) AS data FROM snippets WHERE user_id = ?"},
		{"workspaces", "SELECT id, updated_at, json_object('id', id, 'user_id', user_id, 'vault_id', vault_id, 'name', name, 'layout', layout, 'host_ids', host_ids, 'created_at', created_at, 'updated_at', updated_at) AS data FROM workspaces WHERE user_id = ?"},
		{"tab_groups", "SELECT id, updated_at, json_object('id', id, 'user_id', user_id, 'vault_id', vault_id, 'name', name, 'layout', layout, 'created_at', created_at, 'updated_at', updated_at) AS data FROM tab_groups WHERE user_id = ?"},
	}

	for _, q := range queries {
		var rows []struct {
			ID        string
			UpdatedAt time.Time
			Data      string
		}
		db.DB.Raw(q.Query, userID).Scan(&rows)
		for _, row := range rows {
			records = append(records, SyncRecord{
				TableName: q.TableName,
				RecordID:  row.ID,
				Data:      row.Data,
				UpdatedAt: row.UpdatedAt,
				IsDeleted: false,
			})
		}
	}

	c.JSON(http.StatusOK, SyncPullResponse{
		Records:   records,
		SyncToken: time.Now().Format(time.RFC3339),
		HasMore:   false,
	})
}

func upsertRecord(userID string, record SyncRecord) {
	switch record.TableName {
	case "hosts":
		var host db.Host
		if err := json.Unmarshal([]byte(record.Data), &host); err != nil {
			log.Printf("Failed to unmarshal host: %v", err)
			return
		}
		host.UserID = userID
		db.DB.Save(&host)
	case "groups":
		var group db.Group
		if err := json.Unmarshal([]byte(record.Data), &group); err != nil {
			log.Printf("Failed to unmarshal group: %v", err)
			return
		}
		group.UserID = userID
		db.DB.Save(&group)
	case "snippets":
		var snippet db.Snippet
		if err := json.Unmarshal([]byte(record.Data), &snippet); err != nil {
			log.Printf("Failed to unmarshal snippet: %v", err)
			return
		}
		snippet.UserID = userID
		db.DB.Save(&snippet)
	case "workspaces":
		var ws db.Workspace
		if err := json.Unmarshal([]byte(record.Data), &ws); err != nil {
			log.Printf("Failed to unmarshal workspace: %v", err)
			return
		}
		ws.UserID = userID
		db.DB.Save(&ws)
	case "tab_groups":
		var tg db.TabGroup
		if err := json.Unmarshal([]byte(record.Data), &tg); err != nil {
			log.Printf("Failed to unmarshal tab group: %v", err)
			return
		}
		tg.UserID = userID
		db.DB.Save(&tg)
	}

	tracking := db.SyncTracking{
		TableName: record.TableName,
		RecordID:  record.RecordID,
		UserID:    userID,
		UpdatedAt: record.UpdatedAt,
		DeviceID:  record.DeviceID,
		IsDeleted: record.IsDeleted,
	}
	db.DB.Save(&tracking)
}

func fetchFullRecord(tableName, recordID, userID string) string {
	switch tableName {
	case "hosts":
		var host db.Host
		if err := db.DB.Where("id = ? AND user_id = ?", recordID, userID).First(&host).Error; err != nil {
			return "{}"
		}
		data, _ := json.Marshal(host)
		return string(data)
	case "groups":
		var group db.Group
		if err := db.DB.Where("id = ? AND user_id = ?", recordID, userID).First(&group).Error; err != nil {
			return "{}"
		}
		data, _ := json.Marshal(group)
		return string(data)
	case "snippets":
		var snippet db.Snippet
		if err := db.DB.Where("id = ? AND user_id = ?", recordID, userID).First(&snippet).Error; err != nil {
			return "{}"
		}
		data, _ := json.Marshal(snippet)
		return string(data)
	case "workspaces":
		var ws db.Workspace
		if err := db.DB.Where("id = ? AND user_id = ?", recordID, userID).First(&ws).Error; err != nil {
			return "{}"
		}
		data, _ := json.Marshal(ws)
		return string(data)
	case "tab_groups":
		var tg db.TabGroup
		if err := db.DB.Where("id = ? AND user_id = ?", recordID, userID).First(&tg).Error; err != nil {
			return "{}"
		}
		data, _ := json.Marshal(tg)
		return string(data)
	}
	return "{}"
}
