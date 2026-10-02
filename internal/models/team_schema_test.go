package models

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestTeamSchemaConstraints(t *testing.T) {
	db := setupTestDB(t)
	if err := db.AutoMigrate(&User{}, &Vault{}); err != nil {
		t.Fatal(err)
	}
	legacyID, ownerID := uuid.New(), uuid.New()
	if err := db.Create(&Vault{ID: legacyID, OwnerID: ownerID, Kind: "team", Name: "Legacy private", Data: "{}"}).Error; err != nil {
		t.Fatal(err)
	}
	if err := AutoMigrate(db); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"teams", "team_members", "team_invites", "vault_key_envelopes", "vault_rotations"} {
		if !db.Migrator().HasTable(name) {
			t.Fatalf("missing %s", name)
		}
	}
	var legacy Vault
	if err := db.First(&legacy, "id = ?", legacyID).Error; err != nil {
		t.Fatal(err)
	}
	if legacy.TeamID != nil || legacy.Kind != "team" || legacy.OwnerID != ownerID {
		t.Fatalf("legacy vault was shared or changed: %+v", legacy)
	}
	teamID, userID, vaultID := uuid.New(), uuid.New(), uuid.New()
	if err := db.Create(&Team{ID: teamID, OwnerID: ownerID, Name: "Ops"}).Error; err != nil {
		t.Fatal(err)
	}
	member := TeamMember{ID: uuid.New(), TeamID: teamID, UserID: userID, Role: "member", State: "active"}
	if err := db.Create(&member).Error; err != nil {
		t.Fatal(err)
	}
	member.ID = uuid.New()
	if err := db.Create(&member).Error; err == nil {
		t.Fatal("duplicate member accepted")
	}
	envelope := VaultKeyEnvelope{ID: uuid.New(), VaultID: vaultID, TeamID: teamID, Epoch: 1, RecipientUserID: userID, RecipientFingerprint: "fingerprint", EphemeralPublicKey: "epk", Nonce: "nonce", Ciphertext: "ciphertext"}
	if err := db.Create(&envelope).Error; err != nil {
		t.Fatal(err)
	}
	envelope.ID = uuid.New()
	if err := db.Create(&envelope).Error; err == nil {
		t.Fatal("duplicate envelope accepted")
	}
	invite := TeamInvite{ID: uuid.New(), TeamID: teamID, RecipientUserID: userID, RecipientEmail: "x@example.com", Role: "member", State: "pending"}
	if err := db.Create(&invite).Error; err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{invite.CreatedAt, invite.UpdatedAt, invite.ExpiresAt} {
		if !strings.HasSuffix(value, "Z") {
			t.Fatalf("non-UTC invite time: %q", value)
		}
		if _, err := time.Parse("2006-01-02T15:04:05.000Z", value); err != nil {
			t.Fatal(err)
		}
	}
}
