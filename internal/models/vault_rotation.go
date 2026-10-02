package models

import (
	"github.com/google/uuid"
	"gorm.io/gorm"
	"time"
)

type VaultRotation struct {
	ID               uuid.UUID `gorm:"type:uuid;primaryKey" json:"id"`
	VaultID          uuid.UUID `gorm:"type:uuid;not null;index" json:"vault_id"`
	OperationID      uuid.UUID `gorm:"type:uuid;not null;uniqueIndex" json:"operation_id"`
	OldEpoch         int       `gorm:"not null" json:"old_epoch"`
	NewEpoch         int       `gorm:"not null" json:"new_epoch"`
	State            string    `gorm:"not null" json:"state"`
	ExpectedRevision int       `gorm:"not null" json:"expected_revision"`
	Manifest         string    `gorm:"not null;default:''" json:"manifest"`
	CreatedAt        string    `gorm:"not null" json:"created_at"`
	UpdatedAt        string    `gorm:"not null" json:"updated_at"`
}

func (m *VaultRotation) BeforeCreate(_ *gorm.DB) error {
	now := CanonicalUTCMillis(time.Now())
	if m.CreatedAt == "" {
		m.CreatedAt = now
	}
	if m.UpdatedAt == "" {
		m.UpdatedAt = now
	}
	return nil
}
