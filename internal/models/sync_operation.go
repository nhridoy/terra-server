package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// SyncOperation makes retries idempotent, including when a push response is lost.
// Outcome holds the exact serialized result returned to the originating device.
type SyncOperation struct {
	DeviceID    uuid.UUID `gorm:"type:uuid;primaryKey" json:"device_id"`
	OperationID uuid.UUID `gorm:"type:uuid;primaryKey" json:"operation_id"`
	VaultID     uuid.UUID `gorm:"type:uuid;not null;index" json:"vault_id"`
	Outcome     string    `gorm:"type:text;not null" json:"outcome"`
	CreatedAt   string    `gorm:"not null" json:"created_at"`
}

func (SyncOperation) TableName() string { return "sync_operations" }

func (o *SyncOperation) BeforeCreate(_ *gorm.DB) error {
	if o.CreatedAt == "" {
		o.CreatedAt = CanonicalUTCMillis(time.Now())
	}
	return nil
}
