package models

import "time"

type OAuthState struct {
	State        string     `gorm:"primaryKey" json:"state"`
	Provider     string     `gorm:"not null" json:"provider"`
	CodeVerifier string     `gorm:"not null" json:"code_verifier"`
	DeviceID     string     `gorm:"not null" json:"device_id"`
	ExpiresAt    time.Time  `gorm:"not null;index" json:"expires_at"`
	UsedAt       *time.Time `json:"used_at,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
}

func (OAuthState) TableName() string {
	return "oauth_states"
}
