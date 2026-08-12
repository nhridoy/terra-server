package models

import (
	"time"

	"github.com/google/uuid"
)

type Snippet struct {
	ID          uuid.UUID  `gorm:"type:uuid;primaryKey" json:"id"`
	VaultID     uuid.UUID  `gorm:"type:uuid;not null;index:idx_snippets_vault_sort;constraint:OnDelete:CASCADE" json:"vault_id"`
	Revision    int        `gorm:"not null;default:1" json:"revision"`
	Name        string     `gorm:"not null" json:"name"`
	Description string     `json:"description,omitempty"`
	Tags        string     `gorm:"not null;default:[]" json:"tags"`
	SortOrder   int        `gorm:"not null;default:0;index:idx_snippets_vault_sort" json:"sort_order"`
	Data        string     `gorm:"not null" json:"data"`
	DeletedAt   *time.Time `gorm:"index" json:"deleted_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

func (Snippet) TableName() string {
	return "snippets"
}
