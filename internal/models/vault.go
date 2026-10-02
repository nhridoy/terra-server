package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type Vault struct {
	ID             uuid.UUID  `gorm:"type:uuid;primaryKey" json:"id"`
	OwnerID        uuid.UUID  `gorm:"type:uuid;not null;index;constraint:OnDelete:CASCADE" json:"owner_id"`
	TeamID         *uuid.UUID `gorm:"type:uuid;index" json:"team_id,omitempty"`
	KeyEpoch       int        `gorm:"not null;default:0" json:"key_epoch"`
	RotationCursor uint64     `gorm:"not null;default:0" json:"rotation_cursor"`
	RotationState  string     `gorm:"not null;default:ready" json:"rotation_state"`
	Revision       int        `gorm:"not null;default:1" json:"revision"`
	Kind           string     `gorm:"not null" json:"kind"`
	Name           string     `gorm:"not null" json:"name"`
	SortOrder      int        `gorm:"not null;default:0" json:"sort_order"`
	IsDefault      bool       `gorm:"not null;default:false" json:"is_default"`
	Data           string     `gorm:"not null;default:{}" json:"data"`
	DeletedAt      *string    `gorm:"index" json:"deleted_at,omitempty"`
	CreatedAt      string     `json:"created_at"`
	UpdatedAt      string     `json:"updated_at"`
	EditedAt       string     `gorm:"not null;default:''" json:"edited_at"`
	DeviceID       uuid.UUID  `gorm:"type:uuid" json:"device_id"`
	OperationID    uuid.UUID  `gorm:"type:uuid" json:"operation_id"`
}

func (Vault) TableName() string {
	return "vaults"
}

func (m *Vault) BeforeCreate(_ *gorm.DB) error {
	now := CanonicalUTCMillis(time.Now())
	if m.CreatedAt == "" {
		m.CreatedAt = now
	}
	if m.UpdatedAt == "" {
		m.UpdatedAt = now
	}
	return nil
}
