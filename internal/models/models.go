package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

func AutoMigrate(db *gorm.DB) error {
	if err := db.AutoMigrate(
		&User{},
		&UserKey{},
		&RefreshToken{},
		&OAuthState{},
		&AuthCode{},
		&LoginNonce{},
		&Vault{},
		&Group{},
		&Host{},
		&Key{},
		&Snippet{},
	); err != nil {
		return err
	}
	// The pre-typed-schema `records` table is obsolete; drop it so its data
	// cannot shadow the typed tables (nothing ever read from it).
	return db.Migrator().DropTable("records")
}

func SeedPersonalVault(db *gorm.DB, userID uuid.UUID) error {
	var count int64
	if err := db.Model(&Vault{}).Where("owner_id = ? AND kind = ?", userID, "personal").Count(&count).Error; err != nil {
		return err
	}
	if count > 0 {
		return nil
	}

	vault := Vault{
		ID:        uuid.New(),
		OwnerID:   userID,
		Kind:      "personal",
		Name:      "Personal",
		Revision:  1,
		SortOrder: 0,
		IsDefault: true,
		Data:      "{}",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	return db.Create(&vault).Error
}
