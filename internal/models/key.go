package models

import (
	"time"

	"github.com/google/uuid"
)

type Key struct {
	ID          uuid.UUID  `gorm:"type:uuid;primaryKey" json:"id"`
	VaultID     uuid.UUID  `gorm:"type:uuid;not null;index:idx_keys_vault_sort;constraint:OnDelete:CASCADE" json:"vault_id"`
	Revision    int        `gorm:"not null;default:1" json:"revision"`
	Name        string     `gorm:"not null" json:"name"`
	Description string     `json:"description,omitempty"`
	KeyType     string     `gorm:"not null;default:ed25519" json:"key_type"`
	Fingerprint string     `json:"fingerprint,omitempty"`
	PublicKey   string     `json:"public_key,omitempty"`
	SortOrder   int        `gorm:"not null;default:0;index:idx_keys_vault_sort" json:"sort_order"`
	Data        string     `gorm:"not null" json:"data"`
	DeletedAt   *time.Time `gorm:"index" json:"deleted_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

func (Key) TableName() string {
	return "keys"
}
