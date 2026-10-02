package models

type SessionPreferences struct {
	SessionSyncFields `gorm:"embedded"`
}

func (SessionPreferences) TableName() string { return "session_preferences" }
