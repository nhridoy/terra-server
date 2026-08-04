package models

import (
	"time"

	"github.com/google/uuid"
)

type AuthCode struct {
	ID        uint       `gorm:"primaryKey;autoIncrement" json:"id"`
	CodeHash  string     `gorm:"uniqueIndex;not null" json:"-"`
	Purpose   string     `gorm:"not null" json:"purpose"`
	UserID    uuid.UUID  `gorm:"type:uuid;not null;index" json:"user_id"`
	DeviceID  string     `gorm:"not null" json:"device_id"`
	ExpiresAt time.Time  `gorm:"not null" json:"expires_at"`
	UsedAt    *time.Time `json:"used_at,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}
