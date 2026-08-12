package models

import (
	"time"

	"github.com/google/uuid"
)

type Group struct {
	ID        uuid.UUID  `gorm:"type:uuid;primaryKey" json:"id"`
	VaultID   uuid.UUID  `gorm:"type:uuid;not null;index:idx_groups_vault_parent_sort;constraint:OnDelete:CASCADE" json:"vault_id"`
	Revision  int        `gorm:"not null;default:1" json:"revision"`
	Name      string     `gorm:"not null" json:"name"`
	ParentID  *uuid.UUID `gorm:"type:uuid;index:idx_groups_vault_parent_sort;constraint:OnDelete:CASCADE" json:"parent_id,omitempty"`
	SortOrder int        `gorm:"not null;default:0;index:idx_groups_vault_parent_sort" json:"sort_order"`
	Data      string     `gorm:"not null" json:"data"`
	DeletedAt *time.Time `gorm:"index" json:"deleted_at,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
}

func (Group) TableName() string {
	return "groups"
}
