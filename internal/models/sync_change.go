package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// SyncChange is an append-only event. Seq is a global pull cursor, independent
// of a current row's Revision. Append it in the same write transaction as the row.
type SyncChange struct {
	Seq       uint64    `gorm:"primaryKey;autoIncrement;index:idx_sync_changes_vault_seq,priority:2" json:"cursor"`
	VaultID   uuid.UUID `gorm:"type:uuid;not null;index:idx_sync_changes_vault_seq,priority:1" json:"vault_id"`
	TableName string    `gorm:"not null" json:"table"`
	RecordID  uuid.UUID `gorm:"type:uuid;not null" json:"record_id"`
	Envelope  string    `gorm:"type:text;not null" json:"record"`
	CreatedAt string    `gorm:"not null" json:"created_at"`
}

func (c *SyncChange) BeforeCreate(_ *gorm.DB) error {
	if c.CreatedAt == "" {
		c.CreatedAt = CanonicalUTCMillis(time.Now())
	}
	return nil
}
