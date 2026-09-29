package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// PortForward is a saved definition. Runtime listener/session state is never synced.
type PortForward struct {
	ID          uuid.UUID `gorm:"type:uuid;primaryKey" json:"id"`
	VaultID     uuid.UUID `gorm:"type:uuid;not null;index:idx_port_forwards_vault_host" json:"vault_id"`
	HostID      uuid.UUID `gorm:"type:uuid;not null;index:idx_port_forwards_vault_host" json:"host_id"`
	Revision    int       `gorm:"not null;default:1" json:"revision"`
	Mode        string    `gorm:"not null" json:"mode"`
	Name        string    `gorm:"not null" json:"name"`
	SortOrder   int       `gorm:"not null;default:0" json:"sort_order"`
	Data        string    `gorm:"not null;default:{}" json:"data"`
	DeletedAt   *string   `gorm:"index" json:"deleted_at,omitempty"`
	CreatedAt   string    `gorm:"not null" json:"created_at"`
	UpdatedAt   string    `gorm:"not null" json:"updated_at"`
	EditedAt    string    `gorm:"not null;default:''" json:"edited_at"`
	DeviceID    uuid.UUID `gorm:"type:uuid" json:"device_id"`
	OperationID uuid.UUID `gorm:"type:uuid" json:"operation_id"`
}

func (PortForward) TableName() string { return "port_forwards" }

func (p *PortForward) BeforeCreate(_ *gorm.DB) error {
	now := CanonicalUTCMillis(time.Now())
	if p.CreatedAt == "" {
		p.CreatedAt = now
	}
	if p.UpdatedAt == "" {
		p.UpdatedAt = now
	}
	return nil
}
