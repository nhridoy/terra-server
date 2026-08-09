package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

func AutoMigrate(db *gorm.DB) error {
	return db.AutoMigrate(
		&User{},
		&UserKey{},
		&RefreshToken{},
		&OAuthState{},
		&AuthCode{},
		&LoginNonce{},
		&Vault{},
		&Record{},
	)
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
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	return db.Create(&vault).Error
}
