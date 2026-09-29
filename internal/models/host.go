package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type Host struct {
	ID          uuid.UUID  `gorm:"type:uuid;primaryKey" json:"id"`
	VaultID     uuid.UUID  `gorm:"type:uuid;not null;index:idx_hosts_vault_group_sort;constraint:OnDelete:CASCADE" json:"vault_id"`
	Revision    int        `gorm:"not null;default:1" json:"revision"`
	Name        string     `gorm:"not null" json:"name"`
	OS          string     `gorm:"column:os" json:"os,omitempty"`
	AuthType    string     `gorm:"not null;default:password" json:"auth_type"`
	Tags        string     `gorm:"not null;default:[]" json:"tags"`
	Color       string     `json:"color,omitempty"`
	GroupID     *uuid.UUID `gorm:"type:uuid;index:idx_hosts_vault_group_sort;constraint:OnDelete:CASCADE" json:"group_id,omitempty"`
	KeyID       *uuid.UUID `gorm:"type:uuid;constraint:OnDelete:SET NULL" json:"key_id,omitempty"`
	SortOrder   int        `gorm:"not null;default:0;index:idx_hosts_vault_group_sort" json:"sort_order"`
	Data        string     `gorm:"not null" json:"data"`
	DeletedAt   *string    `gorm:"index" json:"deleted_at,omitempty"`
	CreatedAt   string     `json:"created_at"`
	UpdatedAt   string     `json:"updated_at"`
	EditedAt    string     `gorm:"not null;default:''" json:"edited_at"`
	DeviceID    uuid.UUID  `gorm:"type:uuid" json:"device_id"`
	OperationID uuid.UUID  `gorm:"type:uuid" json:"operation_id"`
}

func (Host) TableName() string {
	return "hosts"
}

func (m *Host) BeforeCreate(_ *gorm.DB) error {
	now := CanonicalUTCMillis(time.Now())
	if m.CreatedAt == "" {
		m.CreatedAt = now
	}
	if m.UpdatedAt == "" {
		m.UpdatedAt = now
	}
	return nil
}
