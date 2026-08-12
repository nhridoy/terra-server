package models

import (
	"time"

	"github.com/google/uuid"
)

type Vault struct {
	ID        uuid.UUID  `gorm:"type:uuid;primaryKey" json:"id"`
	OwnerID   uuid.UUID  `gorm:"type:uuid;not null;index;constraint:OnDelete:CASCADE" json:"owner_id"`
	Revision  int        `gorm:"not null;default:1" json:"revision"`
	Kind      string     `gorm:"not null" json:"kind"`
	Name      string     `gorm:"not null" json:"name"`
	SortOrder int        `gorm:"not null;default:0" json:"sort_order"`
	IsDefault bool       `gorm:"not null;default:false" json:"is_default"`
	Data      string     `gorm:"not null;default:{}" json:"data"`
	DeletedAt *time.Time `gorm:"index" json:"deleted_at,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
}

func (Vault) TableName() string {
	return "vaults"
}
