package models

import (
	"github.com/google/uuid"
	"gorm.io/gorm"
	"time"
)

type VaultKeyEnvelope struct {
	ID                   uuid.UUID `gorm:"type:uuid;primaryKey" json:"id"`
	VaultID              uuid.UUID `gorm:"type:uuid;not null;uniqueIndex:idx_vault_epoch_recipient" json:"vault_id"`
	TeamID               uuid.UUID `gorm:"type:uuid;not null;index" json:"team_id"`
	Epoch                int       `gorm:"not null;uniqueIndex:idx_vault_epoch_recipient" json:"epoch"`
	RecipientUserID      uuid.UUID `gorm:"type:uuid;not null;uniqueIndex:idx_vault_epoch_recipient" json:"recipient_user_id"`
	RecipientFingerprint string    `gorm:"not null" json:"recipient_fingerprint"`
	Version              int       `gorm:"not null;default:1" json:"version"`
	EphemeralPublicKey   string    `gorm:"not null" json:"ephemeral_public_key"`
	Nonce                string    `gorm:"not null" json:"nonce"`
	Ciphertext           string    `gorm:"not null" json:"ciphertext"`
	CreatedAt            string    `gorm:"not null" json:"created_at"`
}

func (m *VaultKeyEnvelope) BeforeCreate(_ *gorm.DB) error {
	if m.CreatedAt == "" {
		m.CreatedAt = CanonicalUTCMillis(time.Now())
	}
	return nil
}
