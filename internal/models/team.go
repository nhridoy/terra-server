package models

import (
	"github.com/google/uuid"
	"gorm.io/gorm"
	"time"
)

type Team struct {
	ID        uuid.UUID `gorm:"type:uuid;primaryKey" json:"id"`
	OwnerID   uuid.UUID `gorm:"type:uuid;not null;index" json:"owner_id"`
	Name      string    `gorm:"not null" json:"name"`
	CreatedAt string    `gorm:"not null" json:"created_at"`
	UpdatedAt string    `gorm:"not null" json:"updated_at"`
	DeletedAt *string   `gorm:"index" json:"deleted_at,omitempty"`
}

func (m *Team) BeforeCreate(_ *gorm.DB) error {
	now := CanonicalUTCMillis(time.Now())
	if m.CreatedAt == "" {
		m.CreatedAt = now
	}
	if m.UpdatedAt == "" {
		m.UpdatedAt = now
	}
	return nil
}
