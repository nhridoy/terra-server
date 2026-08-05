package models

import (
	"time"

	"github.com/google/uuid"
)

type Record struct {
	ID         uuid.UUID  `gorm:"type:uuid;primaryKey" json:"id"`
	UserID     uuid.UUID  `gorm:"type:uuid;not null;index;constraint:OnDelete:CASCADE" json:"user_id"`
	VaultID    uuid.UUID  `gorm:"type:uuid;not null;index:idx_records_vault_id_revision;constraint:OnDelete:CASCADE" json:"vault_id"`
	RecordType string     `gorm:"not null" json:"record_type"`
	Data       string     `gorm:"not null" json:"data"`
	Revision   int        `gorm:"not null;default:1;index:idx_records_vault_id_revision" json:"revision"`
	DeletedAt  *time.Time `gorm:"index" json:"deleted_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
}

func (Record) TableName() string {
	return "records"
}
