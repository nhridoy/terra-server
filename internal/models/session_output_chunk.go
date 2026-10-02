package models

type SessionOutputChunk struct {
	SessionSyncFields `gorm:"embedded"`
}

func (SessionOutputChunk) TableName() string { return "session_output_chunks" }
