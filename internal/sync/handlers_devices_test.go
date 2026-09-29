package sync

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/google/uuid"
)

func TestTwoDevicesConvergeAfterDifferentAndSameRecordEdits(t *testing.T) {
	_, router, cfg, owner, _, vaultID := syncTestServer(t)
	deviceA, deviceB := uuid.New(), uuid.New()
	push := func(device, id uuid.UUID, at, name string) PushResult {
		t.Helper()
		op := uuid.New()
		row := map[string]any{
			"id": id.String(), "vault_id": vaultID.String(), "revision": 1,
			"created_at": "2026-09-27T10:00:00.000Z", "updated_at": at, "edited_at": at,
			"device_id": device.String(), "operation_id": op.String(), "name": name,
			"sort_order": 0, "data": encryptedData("hosts"),
		}
		body := map[string]any{"vault_id": vaultID.String(), "device_id": device.String(), "operations": []any{map[string]any{"operation_id": op.String(), "table": "hosts", "record": row}}}
		response := syncRequest(t, router, cfg, owner, device, "/api/v1/sync/push", body)
		if response.Code != http.StatusOK {
			t.Fatalf("push: %d %s", response.Code, response.Body.String())
		}
		var decoded struct {
			Results []PushResult `json:"results"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &decoded); err != nil {
			t.Fatal(err)
		}
		return decoded.Results[0]
	}
	idA, idB := uuid.New(), uuid.New()
	if push(deviceA, idA, "2026-09-27T10:00:01.000Z", "A").Fate != "accepted" {
		t.Fatal("A missing")
	}
	if push(deviceB, idB, "2026-09-27T10:00:02.000Z", "B").Fate != "accepted" {
		t.Fatal("B missing")
	}
	for _, device := range []uuid.UUID{deviceA, deviceB} {
		response := syncRequest(t, router, cfg, owner, device, "/api/v1/sync/pull", map[string]any{"vault_id": vaultID.String(), "after_cursor": 0, "limit": 10})
		var decoded PullResponse
		if err := json.Unmarshal(response.Body.Bytes(), &decoded); err != nil {
			t.Fatal(err)
		}
		if len(decoded.Changes) != 2 {
			t.Fatalf("device %s received %d changes", device, len(decoded.Changes))
		}
	}
	if push(deviceB, idA, "2026-09-27T10:00:03.000Z", "B-newer").Fate != "accepted" {
		t.Fatal("B newer edit lost")
	}
	loser := push(deviceA, idA, "2026-09-27T10:00:02.500Z", "A-older")
	if loser.Fate != "superseded" || loser.CanonicalRecord["name"] != "B-newer" {
		t.Fatalf("bad conflict: %#v", loser)
	}
}
