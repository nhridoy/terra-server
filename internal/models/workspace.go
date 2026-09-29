package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Workspace stores only structural metadata in the clear. Its layout is in Data.
type Workspace struct {
	ID          uuid.UUID `gorm:"type:uuid;primaryKey" json:"id"`
	VaultID     uuid.UUID `gorm:"type:uuid;not null;index:idx_workspaces_vault_sort" json:"vault_id"`
	Revision    int       `gorm:"not null;default:1" json:"revision"`
	Name        string    `gorm:"not null" json:"name"`
	SortOrder   int       `gorm:"not null;default:0;index:idx_workspaces_vault_sort" json:"sort_order"`
	Data        string    `gorm:"not null;default:{}" json:"data"`
	DeletedAt   *string   `gorm:"index" json:"deleted_at,omitempty"`
	CreatedAt   string    `gorm:"not null" json:"created_at"`
	UpdatedAt   string    `gorm:"not null" json:"updated_at"`
	EditedAt    string    `gorm:"not null;default:''" json:"edited_at"`
	DeviceID    uuid.UUID `gorm:"type:uuid" json:"device_id"`
	OperationID uuid.UUID `gorm:"type:uuid" json:"operation_id"`
}

func (Workspace) TableName() string { return "workspaces" }

func (w *Workspace) BeforeCreate(_ *gorm.DB) error {
	now := CanonicalUTCMillis(time.Now())
	if w.CreatedAt == "" {
		w.CreatedAt = now
	}
	if w.UpdatedAt == "" {
		w.UpdatedAt = now
	}
	return nil
}
