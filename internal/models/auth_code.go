package models

import (
	"time"

	"github.com/google/uuid"
)

type AuthCode struct {
	ID        uint       `gorm:"primaryKey;autoIncrement" json:"id"`
	CodeHash  string     `gorm:"uniqueIndex:idx_auth_codes_code_hash;not null" json:"-"`
	Purpose   string     `gorm:"not null" json:"purpose"`
	UserID    uuid.UUID  `gorm:"type:uuid;not null;index;constraint:OnDelete:CASCADE" json:"user_id"`
	DeviceID  string     `gorm:"not null" json:"device_id"`
	ExpiresAt time.Time  `gorm:"not null;index" json:"expires_at"`
	Attempts  int        `gorm:"not null;default:0" json:"-"`
	UsedAt    *time.Time `json:"used_at,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}

func (AuthCode) TableName() string {
	return "auth_codes"
}
