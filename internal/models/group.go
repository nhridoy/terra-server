package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type Group struct {
	ID          uuid.UUID  `gorm:"type:uuid;primaryKey" json:"id"`
	VaultID     uuid.UUID  `gorm:"type:uuid;not null;index:idx_groups_vault_parent_sort;constraint:OnDelete:CASCADE" json:"vault_id"`
	Revision    int        `gorm:"not null;default:1" json:"revision"`
	Name        string     `gorm:"not null" json:"name"`
	ParentID    *uuid.UUID `gorm:"type:uuid;index:idx_groups_vault_parent_sort;constraint:OnDelete:CASCADE" json:"parent_id,omitempty"`
	SortOrder   int        `gorm:"not null;default:0;index:idx_groups_vault_parent_sort" json:"sort_order"`
	Data        string     `gorm:"not null" json:"data"`
	DeletedAt   *string    `gorm:"index" json:"deleted_at,omitempty"`
	CreatedAt   string     `json:"created_at"`
	UpdatedAt   string     `json:"updated_at"`
	EditedAt    string     `gorm:"not null;default:''" json:"edited_at"`
	DeviceID    uuid.UUID  `gorm:"type:uuid" json:"device_id"`
	OperationID uuid.UUID  `gorm:"type:uuid" json:"operation_id"`
}

func (Group) TableName() string {
	return "groups"
}

func (m *Group) BeforeCreate(_ *gorm.DB) error {
	now := CanonicalUTCMillis(time.Now())
	if m.CreatedAt == "" {
		m.CreatedAt = now
	}
	if m.UpdatedAt == "" {
		m.UpdatedAt = now
	}
	return nil
}
