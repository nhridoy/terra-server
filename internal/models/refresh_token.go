package models

import (
	"time"

	"github.com/google/uuid"
)

type RefreshToken struct {
	ID          uint       `gorm:"primaryKey;autoIncrement" json:"id"`
	UserID      uuid.UUID  `gorm:"type:uuid;not null;index" json:"user_id"`
	TokenHash   string     `gorm:"uniqueIndex;not null" json:"-"`
	DeviceID    string     `gorm:"not null" json:"device_id"`
	UserAgent   *string    `json:"user_agent,omitempty"`
	ExpiresAt   time.Time  `gorm:"not null" json:"expires_at"`
	RotatedAt   *time.Time `json:"rotated_at,omitempty"`
	RevokedAt   *time.Time `json:"revoked_at,omitempty"`
	ReplacedBy  *uint      `json:"replaced_by,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
}
