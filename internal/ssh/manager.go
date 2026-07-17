package ssh

import (
	"fmt"
	"sync"
	"time"
)

// Default idle timeout for SSH connections. Connections unused longer than
// this are considered stale and will be replaced on next use.
const DefaultIdleTimeout = 15 * time.Minute

// Manager manages all SSH connections
type Manager struct {
	connections map[string]*Client
	mu          sync.RWMutex
	IdleTimeout time.Duration
}

// NewManager creates a new connection manager
func NewManager() *Manager {
	return &Manager{
		connections: make(map[string]*Client),
		IdleTimeout: DefaultIdleTimeout,
	}
}

// Connect creates and stores a new SSH connection
func (m *Manager) Connect(id string, config *Config) (*Client, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if already connected
	if client, exists := m.connections[id]; exists {
		if client.IsConnected() {
			// Reuse existing connection
			return client, nil
		}
		// Remove stale connection
		delete(m.connections, id)
	}

	// Create new client
	client := NewClient(config)
	if err := client.Connect(); err != nil {
		return nil, err
	}

	m.connections[id] = client
	return client, nil
}

// NewConnection always creates a fresh SSH connection for a terminal session.
// Unlike Connect(), this does NOT reuse existing connections.
// Terminal sessions must have their own clean SSH connection.
func (m *Manager) NewConnection(id string, config *Config) (*Client, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Always disconnect any existing connection for this ID
	if client, exists := m.connections[id]; exists {
		client.Disconnect()
		delete(m.connections, id)
	}

	// Create new client
	client := NewClient(config)
	if err := client.Connect(); err != nil {
		return nil, err
	}

	m.connections[id] = client
	return client, nil
}

// Get returns a connection by ID if it is still connected and within the idle timeout.
func (m *Manager) Get(id string) (*Client, bool) {
	m.mu.RLock()
	client, exists := m.connections[id]
	m.mu.RUnlock()

	if !exists || !client.IsConnected() {
		return nil, false
	}

	// Check if connection has been idle beyond the timeout
	if m.IdleTimeout > 0 && time.Since(client.LastUsed()) > m.IdleTimeout {
		m.mu.Lock()
		// Double-check it hasn't been replaced since we released the read lock
		if c, ok := m.connections[id]; ok && c == client {
			client.Disconnect()
			delete(m.connections, id)
		}
		m.mu.Unlock()
		return nil, false
	}

	return client, true
}

// Disconnect closes and removes a connection
func (m *Manager) Disconnect(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if client, exists := m.connections[id]; exists {
		client.Disconnect()
		delete(m.connections, id)
	}
}

// DisconnectAll closes all connections
func (m *Manager) DisconnectAll() {
	m.mu.Lock()
	defer m.mu.Unlock()

	for id, client := range m.connections {
		client.Disconnect()
		delete(m.connections, id)
	}
}

// List returns all active connections
func (m *Manager) List() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var ids []string
	for id, client := range m.connections {
		if client.IsConnected() {
			ids = append(ids, id)
		}
	}
	return ids
}

// Cleanup removes stale and idle connections
func (m *Manager) Cleanup() {
	m.mu.Lock()
	defer m.mu.Unlock()

	for id, client := range m.connections {
		if !client.IsConnected() {
			delete(m.connections, id)
			continue
		}
		if m.IdleTimeout > 0 && time.Since(client.LastUsed()) > m.IdleTimeout {
			client.Disconnect()
			delete(m.connections, id)
		}
	}
}

// StartCleanup starts a periodic cleanup goroutine
func (m *Manager) StartCleanup(interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for range ticker.C {
			m.Cleanup()
		}
	}()
}

// GetOrCreate gets an existing connection or creates a new one
func (m *Manager) GetOrCreate(id string, config *Config) (*Client, error) {
	// Try to get existing connection
	if client, exists := m.Get(id); exists {
		return client, nil
	}

	// Create new connection
	return m.Connect(id, config)
}

// Stats returns connection statistics
func (m *Manager) Stats() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	active := 0
	for _, client := range m.connections {
		if client.IsConnected() {
			active++
		}
	}

	return map[string]interface{}{
		"total": len(m.connections),
		"active": active,
	}
}

// ConnectFromModel creates a connection from a Host model
func (m *Manager) ConnectFromModel(hostID string, host interface{}) (*Client, error) {
	// Type assert to get host fields
	type HostModel struct {
		ID             string
		Hostname       string
		Port           int
		Username       string
		Password       string
		PrivateKey     []byte
		Passphrase     string
	}

	// Convert to config
	config := &Config{
		Host:     fmt.Sprintf("%v", host.(*HostModel).Hostname),
		Port:     host.(*HostModel).Port,
		Username: host.(*HostModel).Username,
		Password: host.(*HostModel).Password,
		KeyBytes: host.(*HostModel).PrivateKey,
		KeyPassphrase: host.(*HostModel).Passphrase,
	}

	return m.Connect(hostID, config)
}

// Global instance
var DefaultManager = NewManager()

func init() {
	// Start cleanup every 5 minutes
	DefaultManager.StartCleanup(5 * time.Minute)
}
