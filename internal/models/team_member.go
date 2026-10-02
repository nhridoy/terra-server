package models

import (
	"github.com/google/uuid"
	"gorm.io/gorm"
	"time"
)

type TeamMember struct {
	ID        uuid.UUID `gorm:"type:uuid;primaryKey" json:"id"`
	TeamID    uuid.UUID `gorm:"type:uuid;not null;uniqueIndex:idx_team_member" json:"team_id"`
	UserID    uuid.UUID `gorm:"type:uuid;not null;uniqueIndex:idx_team_member" json:"user_id"`
	Role      string    `gorm:"not null" json:"role"`
	State     string    `gorm:"not null" json:"state"`
	CreatedAt string    `gorm:"not null" json:"created_at"`
	UpdatedAt string    `gorm:"not null" json:"updated_at"`
}

func (m *TeamMember) BeforeCreate(_ *gorm.DB) error {
	now := CanonicalUTCMillis(time.Now())
	if m.CreatedAt == "" {
		m.CreatedAt = now
	}
	if m.UpdatedAt == "" {
		m.UpdatedAt = now
	}
	return nil
}
