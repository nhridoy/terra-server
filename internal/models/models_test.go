package models

import (
	"testing"

	"github.com/google/uuid"
	gormsqlite "github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func setupTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(gormsqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to open test db: %v", err)
	}
	return db
}

func TestAutoMigrate(t *testing.T) {
	db := setupTestDB(t)

	err := AutoMigrate(db)
	if err != nil {
		t.Fatalf("AutoMigrate failed: %v", err)
	}

	var tables []string
	db.Raw("SELECT name FROM sqlite_master WHERE type='table'").Pluck("name", &tables)

	t.Logf("tables created: %v", tables)

	expectedTables := map[string]bool{
		"users":          false,
		"user_keys":      false,
		"refresh_tokens": false,
		"oauth_states":   false,
		"auth_codes":     false,
		"vaults":         false,
		"records":        false,
	}

	for _, table := range tables {
		if _, ok := expectedTables[table]; ok {
			expectedTables[table] = true
		}
	}

	for table, found := range expectedTables {
		if !found {
			t.Errorf("expected table %s to exist", table)
		}
	}
}

func TestSeedPersonalVault(t *testing.T) {
	db := setupTestDB(t)
	if err := AutoMigrate(db); err != nil {
		t.Fatalf("AutoMigrate failed: %v", err)
	}

	userID := uuid.New()
	err := SeedPersonalVault(db, userID)
	if err != nil {
		t.Fatalf("SeedPersonalVault failed: %v", err)
	}

	var vault Vault
	if err := db.Where("owner_id = ? AND kind = ?", userID, "personal").First(&vault).Error; err != nil {
		t.Fatalf("expected personal vault to exist: %v", err)
	}
	if vault.Name != "Personal" {
		t.Errorf("expected vault name 'Personal', got '%s'", vault.Name)
	}

	err = SeedPersonalVault(db, userID)
	if err != nil {
		t.Fatalf("SeedPersonalVault idempotent call failed: %v", err)
	}

	var count int64
	db.Model(&Vault{}).Where("owner_id = ? AND kind = ?", userID, "personal").Count(&count)
	if count != 1 {
		t.Errorf("expected exactly 1 personal vault, got %d", count)
	}
}

func TestUserModel(t *testing.T) {
	db := setupTestDB(t)
	if err := AutoMigrate(db); err != nil {
		t.Fatalf("AutoMigrate failed: %v", err)
	}

	user := User{
		ID:           uuid.New(),
		Email:        "test@example.com",
		Name:         "Test User",
		AuthProvider: "password",
		Initialized:  true,
	}

	if err := db.Create(&user).Error; err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	var found User
	if err := db.Where("email = ?", "test@example.com").First(&found).Error; err != nil {
		t.Fatalf("failed to find user: %v", err)
	}
	if found.Name != "Test User" {
		t.Errorf("expected name 'Test User', got '%s'", found.Name)
	}
}
