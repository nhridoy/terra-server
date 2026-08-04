package models

import (
	"time"

	"github.com/google/uuid"
)

type UserKey struct {
	ID        uint      `gorm:"primaryKey;autoIncrement" json:"id"`
	UserID    uuid.UUID `gorm:"type:uuid;not null;index" json:"user_id"`
	KeyType   string    `gorm:"not null" json:"key_type"`
	Payload   string    `gorm:"not null" json:"payload"`
	CreatedAt time.Time `json:"created_at"`
}
