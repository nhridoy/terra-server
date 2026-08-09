package models

import "time"

type LoginNonce struct {
	ID        uint       `gorm:"primaryKey" json:"id"`
	Email     string     `gorm:"not null;index" json:"email"`
	NonceHash string     `gorm:"uniqueIndex;size:64" json:"nonce_hash"`
	ExpiresAt time.Time  `gorm:"not null;index" json:"expires_at"`
	UsedAt    *time.Time `json:"used_at,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}

func (LoginNonce) TableName() string {
	return "login_nonces"
}