package models

import "github.com/google/uuid"

// SessionSyncFields contains only the common sync envelope and opaque ciphertext.
// Host details and terminal output are never plaintext database columns.
type SessionSyncFields struct {
	ID          uuid.UUID `gorm:"type:uuid;primaryKey" json:"id"`
	VaultID     uuid.UUID `gorm:"type:uuid;not null;index" json:"vault_id"`
	Revision    int       `gorm:"not null;default:1" json:"revision"`
	Name        string    `gorm:"not null" json:"name"`
	SortOrder   int       `gorm:"not null;default:0" json:"sort_order"`
	Data        string    `gorm:"not null" json:"data"`
	DeletedAt   *string   `gorm:"index" json:"deleted_at,omitempty"`
	CreatedAt   string    `gorm:"not null" json:"created_at"`
	UpdatedAt   string    `gorm:"not null" json:"updated_at"`
	EditedAt    string    `gorm:"not null;default:''" json:"edited_at"`
	DeviceID    uuid.UUID `gorm:"type:uuid" json:"device_id"`
	OperationID uuid.UUID `gorm:"type:uuid" json:"operation_id"`
}

type SessionHistory struct {
	SessionSyncFields `gorm:"embedded"`
}

func (SessionHistory) TableName() string { return "session_history" }
