package models

import (
	"time"

	"github.com/google/uuid"
)

type UserKey struct {
	ID        uint      `gorm:"primaryKey;autoIncrement" json:"id"`
	UserID    uuid.UUID `gorm:"type:uuid;not null;index;uniqueIndex:idx_user_keys_user_id_key_type;constraint:OnDelete:CASCADE" json:"user_id"`
	KeyType   string    `gorm:"not null;uniqueIndex:idx_user_keys_user_id_key_type" json:"key_type"`
	Payload   string    `gorm:"not null" json:"payload"`
	CreatedAt time.Time `json:"created_at"`
}

func (UserKey) TableName() string {
	return "user_keys"
}
