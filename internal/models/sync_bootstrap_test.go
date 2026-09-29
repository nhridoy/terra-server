package models

import (
	"encoding/json"
	"testing"

	"github.com/google/uuid"
)

func TestExistingVaultGetsOneInitialSyncChange(t *testing.T) {
	db := setupTestDB(t)
	if err := AutoMigrate(db); err != nil {
		t.Fatal(err)
	}
	ownerID := uuid.New()
	if err := db.Create(&User{ID: ownerID, Email: "bootstrap@example.test"}).Error; err != nil {
		t.Fatal(err)
	}
	vault := Vault{ID: uuid.New(), OwnerID: ownerID, Kind: "personal", Name: "Existing", Data: "{}"}
	if err := db.Create(&vault).Error; err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := AutoMigrate(db); err != nil {
			t.Fatal(err)
		}
	}
	var changes []SyncChange
	if err := db.Where("vault_id = ? AND table_name = ?", vault.ID, "vaults").Find(&changes).Error; err != nil {
		t.Fatal(err)
	}
	if len(changes) != 1 {
		t.Fatalf("expected one initial vault event, got %d", len(changes))
	}
	var envelope map[string]any
	if err := json.Unmarshal([]byte(changes[0].Envelope), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope["id"] != vault.ID.String() || envelope["name"] != "Existing" {
		t.Fatalf("bad vault envelope: %#v", envelope)
	}
}

func TestSeedPersonalVaultEmitsChange(t *testing.T) {
	db := setupTestDB(t)
	if err := AutoMigrate(db); err != nil {
		t.Fatal(err)
	}
	ownerID := uuid.New()
	if err := db.Create(&User{ID: ownerID, Email: "seed@example.test"}).Error; err != nil {
		t.Fatal(err)
	}
	if err := SeedPersonalVault(db, ownerID); err != nil {
		t.Fatal(err)
	}
	var count int64
	if err := db.Model(&SyncChange{}).Where("table_name = ?", "vaults").Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("expected seeded vault event, got %d", count)
	}
}
