package models

import (
	"time"

	"github.com/google/uuid"
)

type Vault struct {
	ID        uuid.UUID `gorm:"type:uuid;primaryKey" json:"id"`
	OwnerID   uuid.UUID `gorm:"type:uuid;not null;index" json:"owner_id"`
	Kind      string    `gorm:"not null" json:"kind"`
	Name      string    `gorm:"not null" json:"name"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}
