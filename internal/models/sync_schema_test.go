package models

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestSyncSchema(t *testing.T) {
	db := setupTestDB(t)
	if err := AutoMigrate(db); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"workspaces", "presets", "port_forwards", "sync_changes", "sync_operations"} {
		if !db.Migrator().HasTable(table) {
			t.Errorf("missing sync table %s", table)
		}
	}

	vaultID := uuid.New()
	workspace := Workspace{ID: uuid.New(), VaultID: vaultID, Name: "Daily", Data: "opaque-ciphertext"}
	if err := db.Create(&workspace).Error; err != nil {
		t.Fatal(err)
	}
	var got Workspace
	if err := db.First(&got, "id = ?", workspace.ID).Error; err != nil {
		t.Fatal(err)
	}
	if got.Data != workspace.Data {
		t.Fatalf("encrypted payload changed: %q", got.Data)
	}
}

func TestSyncSequenceAndOperationUniqueness(t *testing.T) {
	db := setupTestDB(t)
	if err := AutoMigrate(db); err != nil {
		t.Fatal(err)
	}
	vaultID := uuid.New()
	first := SyncChange{VaultID: vaultID, TableName: "hosts", RecordID: uuid.New(), Envelope: `{"data":"ciphertext"}`}
	second := SyncChange{VaultID: vaultID, TableName: "keys", RecordID: uuid.New(), Envelope: `{"data":"ciphertext-2"}`}
	if err := db.Create(&first).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&second).Error; err != nil {
		t.Fatal(err)
	}
	if !(first.Seq > 0 && second.Seq > first.Seq) {
		t.Fatalf("server cursor must increase across record types: %d, %d", first.Seq, second.Seq)
	}

	deviceID, operationID := uuid.New(), uuid.New()
	op := SyncOperation{DeviceID: deviceID, OperationID: operationID, VaultID: vaultID, Outcome: `{"fate":"accepted"}`}
	if err := db.Create(&op).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&SyncOperation{DeviceID: deviceID, OperationID: operationID, VaultID: vaultID, Outcome: op.Outcome}).Error; err == nil {
		t.Fatal("duplicate device/operation pair unexpectedly accepted")
	}
	if err := db.Create(&SyncOperation{DeviceID: uuid.New(), OperationID: operationID, VaultID: vaultID, Outcome: op.Outcome}).Error; err != nil {
		t.Fatalf("operation ID must be scoped by device: %v", err)
	}
}

func TestSyncTimestampsCanonical(t *testing.T) {
	db := setupTestDB(t)
	if err := AutoMigrate(db); err != nil {
		t.Fatal(err)
	}
	change := SyncChange{VaultID: uuid.New(), TableName: "hosts", RecordID: uuid.New(), Envelope: `{}`}
	if err := db.Create(&change).Error; err != nil {
		t.Fatal(err)
	}
	var raw string
	if err := db.Raw("SELECT created_at FROM sync_changes WHERE seq = ?", change.Seq).Scan(&raw).Error; err != nil {
		t.Fatal(err)
	}
	if len(raw) != len("2006-01-02T15:04:05.000Z") || !strings.HasSuffix(raw, "Z") {
		t.Fatalf("change timestamp is not canonical UTC millis: %q", raw)
	}
	if _, err := time.Parse("2006-01-02T15:04:05.000Z", raw); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(change)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), raw) {
		t.Fatalf("wire timestamp differs from persisted timestamp: %s", encoded)
	}
}

func TestSyncSchemaPreservesExistingRows(t *testing.T) {
	db := setupTestDB(t)
	if err := db.AutoMigrate(&Vault{}, &Host{}, &Key{}); err != nil {
		t.Fatal(err)
	}
	vaultID := uuid.New()
	hostID := uuid.New()
	keyID := uuid.New()
	if err := db.Create(&Vault{ID: vaultID, OwnerID: uuid.New(), Kind: "personal", Name: "Personal", Data: "vault-cipher"}).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&Host{ID: hostID, VaultID: vaultID, Name: "Server", Data: "host-cipher"}).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&Key{ID: keyID, VaultID: vaultID, Name: "Login", Data: "key-cipher"}).Error; err != nil {
		t.Fatal(err)
	}
	if err := AutoMigrate(db); err != nil {
		t.Fatal(err)
	}
	var host Host
	if err := db.First(&host, "id = ?", hostID).Error; err != nil || host.Data != "host-cipher" {
		t.Fatalf("existing host lost or mutated: %+v, %v", host, err)
	}
	var key Key
	if err := db.First(&key, "id = ?", keyID).Error; err != nil || key.Data != "key-cipher" {
		t.Fatalf("existing key lost or mutated: %+v, %v", key, err)
	}
}
