package models

import (
	"time"

	"github.com/google/uuid"
)

type Record struct {
	ID         uuid.UUID  `gorm:"type:uuid;primaryKey" json:"id"`
	UserID     uuid.UUID  `gorm:"type:uuid;not null;index" json:"user_id"`
	VaultID    uuid.UUID  `gorm:"type:uuid;not null;index" json:"vault_id"`
	RecordType string     `gorm:"not null" json:"record_type"`
	Data       string     `gorm:"not null" json:"data"`
	Revision   int        `gorm:"not null;default:1" json:"revision"`
	DeletedAt  *time.Time `json:"deleted_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
}
