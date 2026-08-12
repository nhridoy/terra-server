package models

import (
	"time"

	"github.com/google/uuid"
)

type Host struct {
	ID        uuid.UUID  `gorm:"type:uuid;primaryKey" json:"id"`
	VaultID   uuid.UUID  `gorm:"type:uuid;not null;index:idx_hosts_vault_group_sort;constraint:OnDelete:CASCADE" json:"vault_id"`
	Revision  int        `gorm:"not null;default:1" json:"revision"`
	Name      string     `gorm:"not null" json:"name"`
	OS        string     `gorm:"column:os" json:"os,omitempty"`
	AuthType  string     `gorm:"not null;default:password" json:"auth_type"`
	Tags      string     `gorm:"not null;default:[]" json:"tags"`
	Color     string     `json:"color,omitempty"`
	GroupID   *uuid.UUID `gorm:"type:uuid;index:idx_hosts_vault_group_sort;constraint:OnDelete:CASCADE" json:"group_id,omitempty"`
	KeyID     *uuid.UUID `gorm:"type:uuid;constraint:OnDelete:SET NULL" json:"key_id,omitempty"`
	SortOrder int        `gorm:"not null;default:0;index:idx_hosts_vault_group_sort" json:"sort_order"`
	Data      string     `gorm:"not null" json:"data"`
	DeletedAt *time.Time `gorm:"index" json:"deleted_at,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
}

func (Host) TableName() string {
	return "hosts"
}
