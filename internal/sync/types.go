package sync

type PushOperation struct {
	OperationID string         `json:"operation_id"`
	Table       string         `json:"table"`
	Record      map[string]any `json:"record"`
}

type PushRequest struct {
	VaultID    string          `json:"vault_id"`
	DeviceID   string          `json:"device_id"`
	Operations []PushOperation `json:"operations"`
}

type PushResult struct {
	OperationID     string         `json:"operation_id"`
	Fate            string         `json:"fate"`
	CanonicalRecord map[string]any `json:"canonical_record"`
	Cursor          uint64         `json:"cursor"`
}

type PullRequest struct {
	VaultID     string `json:"vault_id"`
	AfterCursor uint64 `json:"after_cursor"`
	Limit       int    `json:"limit"`
}

type PullChange struct {
	Cursor uint64         `json:"cursor"`
	Table  string         `json:"table"`
	Record map[string]any `json:"record"`
}

type PullResponse struct {
	Changes     []PullChange `json:"changes"`
	NextCursor  uint64       `json:"next_cursor"`
	UpperCursor uint64       `json:"upper_cursor"`
	HasMore     bool         `json:"has_more"`
}
