package models

import (
	"github.com/google/uuid"
	"gorm.io/gorm"
	"time"
)

type TeamInvite struct {
	ID                   uuid.UUID `gorm:"type:uuid;primaryKey" json:"id"`
	TeamID               uuid.UUID `gorm:"type:uuid;not null;index:idx_team_invite_lookup" json:"team_id"`
	RecipientUserID      uuid.UUID `gorm:"type:uuid;not null;index:idx_team_invite_lookup" json:"recipient_user_id"`
	RecipientEmail       string    `gorm:"not null" json:"recipient_email"`
	RecipientFingerprint string    `gorm:"not null" json:"recipient_fingerprint"`
	Role                 string    `gorm:"not null" json:"role"`
	State                string    `gorm:"not null;index:idx_team_invite_lookup" json:"state"`
	InviterUserID        uuid.UUID `gorm:"type:uuid" json:"inviter_user_id"`
	ExpiresAt            string    `gorm:"not null" json:"expires_at"`
	CreatedAt            string    `gorm:"not null" json:"created_at"`
	UpdatedAt            string    `gorm:"not null" json:"updated_at"`
}

func (m *TeamInvite) BeforeCreate(_ *gorm.DB) error {
	now := time.Now()
	if m.CreatedAt == "" {
		m.CreatedAt = CanonicalUTCMillis(now)
	}
	if m.UpdatedAt == "" {
		m.UpdatedAt = CanonicalUTCMillis(now)
	}
	if m.ExpiresAt == "" {
		m.ExpiresAt = CanonicalUTCMillis(now.Add(7 * 24 * time.Hour))
	}
	return nil
}
