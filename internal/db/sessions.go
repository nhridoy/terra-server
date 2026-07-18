package db

import (
	"time"

	"gorm.io/gorm"
)

// CommandLog represents a logged command
type CommandLog struct {
	ID         uint           `gorm:"primaryKey" json:"id"`
	SessionID  string         `gorm:"index;not null" json:"session_id"`
	Command    string         `gorm:"type:text;not null" json:"command"`
	Output     string         `gorm:"type:text" json:"output"`
	ExitCode   int            `json:"exit_code"`
	ExecutedAt time.Time      `gorm:"not null" json:"executed_at"`
	Duration   time.Duration  `json:"duration"`
	CreatedAt  time.Time      `json:"created_at"`
	UpdatedAt  time.Time      `json:"updated_at"`
	DeletedAt  gorm.DeletedAt `gorm:"index" json:"deleted_at"`
}

// SessionManager manages session logging
type SessionManager struct {
	db *gorm.DB
}

// NewSessionManager creates a new session manager
func NewSessionManager() *SessionManager {
	return &SessionManager{db: DB}
}

// StartSession creates a new session log, scoped to the host's vault
func (m *SessionManager) StartSession(userID, hostID string) (*SessionLog, error) {
	session := &SessionLog{
		UserID:    userID,
		HostID:    hostID,
		StartedAt: time.Now(),
	}

	// Associate the session with the host's vault for per-vault history scoping.
	var host Host
	if err := m.db.Where("id = ?", hostID).First(&host).Error; err == nil {
		if host.VaultID != nil {
			session.VaultID = host.VaultID
		}
	}

	if err := m.db.Create(session).Error; err != nil {
		return nil, err
	}

	return session, nil
}

// EndSession ends a session
func (m *SessionManager) EndSession(sessionID string, status string) error {
	now := time.Now()
	return m.db.Model(&SessionLog{}).
		Where("id = ?", sessionID).
		Updates(map[string]interface{}{
			"ended_at": now,
		}).Error
}

// LogCommand logs a command execution
func (m *SessionManager) LogCommand(sessionID string, command, output string, exitCode int, duration time.Duration) error {
	cmdLog := &CommandLog{
		SessionID:  sessionID,
		Command:    command,
		Output:     output,
		ExitCode:   exitCode,
		ExecutedAt: time.Now(),
		Duration:   duration,
	}

	return m.db.Create(cmdLog).Error
}

// GetSession retrieves a session by ID
func (m *SessionManager) GetSession(sessionID string) (*SessionLog, error) {
	var session SessionLog
	if err := m.db.First(&session, "id = ?", sessionID).Error; err != nil {
		return nil, err
	}
	return &session, nil
}

// GetUserSessions retrieves sessions for a user
func (m *SessionManager) GetUserSessions(userID string, limit, offset int) ([]SessionLog, error) {
	var sessions []SessionLog
	err := m.db.Where("user_id = ?", userID).
		Order("started_at DESC").
		Limit(limit).
		Offset(offset).
		Find(&sessions).Error
	return sessions, err
}

// GetSessionCommands retrieves commands for a session
func (m *SessionManager) GetSessionCommands(sessionID string) ([]CommandLog, error) {
	var commands []CommandLog
	err := m.db.Where("session_id = ?", sessionID).
		Order("executed_at ASC").
		Find(&commands).Error
	return commands, err
}

// DeleteSession deletes a session and its commands
func (m *SessionManager) DeleteSession(sessionID string) error {
	// Delete commands first
	if err := m.db.Where("session_id = ?", sessionID).Delete(&CommandLog{}).Error; err != nil {
		return err
	}

	// Delete session
	return m.db.Delete(&SessionLog{}, "id = ?", sessionID).Error
}

// CleanupOldSessions deletes sessions older than specified duration
func (m *SessionManager) CleanupOldSessions(olderThan time.Duration) (int64, error) {
	cutoff := time.Now().Add(-olderThan)

	result := m.db.Where("started_at < ?", cutoff).
		Delete(&SessionLog{})

	return result.RowsAffected, result.Error
}

// GetSessionStats returns statistics for a user
func (m *SessionManager) GetSessionStats(userID string) (map[string]interface{}, error) {
	var totalSessions int64
	var totalCommands int64
	var totalDuration time.Duration

	err := m.db.Model(&SessionLog{}).
		Where("user_id = ?", userID).
		Count(&totalSessions).Error
	if err != nil {
		return nil, err
	}

	err = m.db.Model(&CommandLog{}).
		Joins("JOIN session_logs ON session_logs.id = command_logs.session_id").
		Where("session_logs.user_id = ?", userID).
		Count(&totalCommands).Error
	if err != nil {
		return nil, err
	}

	err = m.db.Model(&CommandLog{}).
		Joins("JOIN session_logs ON session_logs.id = command_logs.session_id").
		Where("session_logs.user_id = ?", userID).
		Select("COALESCE(SUM(command_logs.duration), 0)").
		Scan(&totalDuration).Error
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"totalSessions": totalSessions,
		"totalCommands": totalCommands,
		"totalDuration": totalDuration.String(),
	}, nil
}

// Global session manager
var SessionMgr = NewSessionManager()
