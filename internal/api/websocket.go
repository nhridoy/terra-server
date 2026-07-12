package api

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/termvault/termvault/internal/db"
	"github.com/termvault/termvault/internal/ssh"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		return true // Allow all origins in dev
	},
}

// WSMessage represents a WebSocket message
type WSMessage struct {
	Type    string      `json:"type"`
	Payload interface{} `json:"payload"`
}

// WSTerminal handles WebSocket terminal connections
type WSTerminal struct {
	conn     *websocket.Conn
	client   *ssh.Client
	session  *ssh.Session
	send     chan []byte
	mu       sync.Mutex
}

// NewWSTerminal creates a new WebSocket terminal handler
func NewWSTerminal(conn *websocket.Conn) *WSTerminal {
	return &WSTerminal{
		conn: conn,
		send: make(chan []byte, 256),
	}
}

func forwardOutput(t *WSTerminal, reader io.Reader, done chan struct{}) {
	buf := make([]byte, 4096)
	for {
		n, err := reader.Read(buf)
		if err != nil {
			close(done)
			return
		}

		t.mu.Lock()
		t.conn.WriteJSON(WSMessage{
			Type:    "output",
			Payload: string(buf[:n]),
		})
		t.mu.Unlock()
	}
}

// HandleSSHWebSocket handles WebSocket connections for SSH terminals
func HandleSSHWebSocket(c *gin.Context) {
	// Get host ID from query
	hostID := c.Query("hostId")
	if hostID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "hostId required"})
		return
	}

	// Upgrade to WebSocket
	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		log.Printf("WebSocket upgrade failed: %v", err)
		return
	}
	defer conn.Close()

	// Build SSH config - try DB first, then direct params
	var targetHost, targetUser, targetPassword string
	var targetPort int
	var targetKeyBytes []byte
	var targetPassphrase string

	// Try to get host from database
	var host db.Host
	if err := db.DB.Where("id = ?", hostID).First(&host).Error; err == nil {
		targetHost = host.Hostname
		if targetHost == "" {
			targetHost = host.Address
		}
		targetPort = host.Port
		targetUser = host.Username
		targetPassword = host.Password
		targetKeyBytes = host.PrivateKey
		targetPassphrase = host.Passphrase
	} else {
		// Direct connection via query params
		targetHost = c.Query("host")
		targetUser = c.Query("username")
		targetPassword = c.Query("password")

		portStr := c.Query("port")
		targetPort = 22
		if portStr != "" {
			targetPort, _ = strconv.Atoi(portStr)
		}
	}

	if targetHost == "" {
		sendWSError(conn, "Host not found")
		return
	}

	// Get or create SSH connection - ALWAYS create a fresh connection for terminal sessions
	// to avoid state pollution from previous sessions
	config := &ssh.Config{
		Host:          targetHost,
		Port:          targetPort,
		Username:      targetUser,
		Password:      targetPassword,
		KeyBytes:      targetKeyBytes,
		KeyPassphrase: targetPassphrase,
	}

	client, err := ssh.DefaultManager.NewConnection(hostID, config)
	if err != nil {
		sendWSError(conn, "Connection failed: "+err.Error())
		return
	}

	// Create terminal handler
	handler := NewWSTerminal(conn)
	handler.client = client

	// Create session
	session, err := client.NewSession(hostID)
	if err != nil {
		sendWSError(conn, "Session failed: "+err.Error())
		return
	}
	handler.session = session

	// Start reading merged stdout/stderr BEFORE the shell starts.
	// The MOTD / PAM output is emitted during session setup,
	// before the shell hands over control — if we attach the readers
	// only after StartShell() returns, that early output is dropped.
	outputDone := make(chan struct{})
	go forwardOutput(handler, handler.session.Output(), outputDone)

	// When the output stream closes, the session has ended
	go func() {
		<-outputDone
		handler.mu.Lock()
		handler.conn.WriteJSON(WSMessage{
			Type:    "disconnected",
			Payload: map[string]interface{}{"reason": "session ended"},
		})
		handler.mu.Unlock()
	}()

	// Request PTY
	cols := 80
	rows := 24
	if c.Query("cols") != "" {
		cols, _ = strconv.Atoi(c.Query("cols"))
	}
	if c.Query("rows") != "" {
		rows, _ = strconv.Atoi(c.Query("rows"))
	}

	if err := session.RequestPTY(cols, rows); err != nil {
		sendWSError(conn, "PTY failed: "+err.Error())
		return
	}

	// Start shell
	if err := session.StartShell(); err != nil {
		sendWSError(conn, "Shell failed: "+err.Error())
		return
	}

	// Send connected message (serialize with the output writers)
	handler.mu.Lock()
	sendWSMessage(conn, WSMessage{
		Type:    "connected",
		Payload: map[string]interface{}{"hostId": hostID},
	})
	handler.mu.Unlock()

	// Read from WebSocket
	handler.readWebSocket()

	// Cleanup
	session.Close()
}

// HandleWSResize handles terminal resize
func HandleWSResize(c *gin.Context) {
	var req struct {
		HostID string `json:"hostId"`
		Cols   int    `json:"cols"`
		Rows   int    `json:"rows"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Get session
	client, exists := ssh.DefaultManager.Get(req.HostID)
	if !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "Session not found"})
		return
	}

	// Get session (simplified - in real code, track sessions)
	_ = client

	// Send resize command via WebSocket (would need to track connections)
	c.JSON(http.StatusOK, gin.H{"status": "resized"})
}

func (t *WSTerminal) readSession() {
	buf := make([]byte, 1024)
	for {
		n, err := t.session.Read(buf)
		if err != nil {
			// Send disconnected message
			t.mu.Lock()
			t.conn.WriteJSON(WSMessage{
				Type:    "disconnected",
				Payload: map[string]interface{}{"reason": err.Error()},
			})
			t.mu.Unlock()
			return
		}

		// Send output
		t.mu.Lock()
		t.conn.WriteJSON(WSMessage{
			Type:    "output",
			Payload: string(buf[:n]),
		})
		t.mu.Unlock()
	}
}

func (t *WSTerminal) readWebSocket() {
	defer t.conn.Close()

	for {
		_, message, err := t.conn.ReadMessage()
		if err != nil {
			return
		}

		var msg WSMessage
		if err := json.Unmarshal(message, &msg); err != nil {
			continue
		}

		switch msg.Type {
		case "input":
			// Handle input
			if payload, ok := msg.Payload.(string); ok {
				t.session.Write([]byte(payload))
			}

		case "resize":
			// Handle resize
			if payload, ok := msg.Payload.(map[string]interface{}); ok {
				cols := int(payload["cols"].(float64))
				rows := int(payload["rows"].(float64))
				t.session.Resize(cols, rows)
			}

		case "ping":
			// Respond to ping
			t.mu.Lock()
			t.conn.WriteJSON(WSMessage{Type: "pong"})
			t.mu.Unlock()
		}
	}
}

// sendWSError sends an error message via WebSocket
func sendWSError(conn *websocket.Conn, msg string) {
	conn.WriteJSON(WSMessage{
		Type:    "error",
		Payload: msg,
	})
}

// sendWSMessage sends a message via WebSocket
func sendWSMessage(conn *websocket.Conn, msg WSMessage) {
	conn.WriteJSON(msg)
}

// ConnectionManager tracks active WebSocket connections
type ConnectionManager struct {
	connections map[string]*WSTerminal
	mu          sync.RWMutex
}

// NewConnectionManager creates a new connection manager
func NewConnectionManager() *ConnectionManager {
	return &ConnectionManager{
		connections: make(map[string]*WSTerminal),
	}
}

// Add adds a connection
func (cm *ConnectionManager) Add(hostID string, terminal *WSTerminal) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	cm.connections[hostID] = terminal
}

// Remove removes a connection
func (cm *ConnectionManager) Remove(hostID string) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	delete(cm.connections, hostID)
}

// Get gets a connection
func (cm *ConnectionManager) Get(hostID string) (*WSTerminal, bool) {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	terminal, exists := cm.connections[hostID]
	return terminal, exists
}

// Broadcast sends a message to all connections
func (cm *ConnectionManager) Broadcast(msg WSMessage) {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	for _, terminal := range cm.connections {
		terminal.mu.Lock()
		terminal.conn.WriteJSON(msg)
		terminal.mu.Unlock()
	}
}

// Global connection manager
var WSManager = NewConnectionManager()

// CleanupStaleConnections removes stale connections
func CleanupStaleConnections() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		WSManager.mu.Lock()
		for hostID, terminal := range WSManager.connections {
			terminal.mu.Lock()
			if err := terminal.conn.WriteJSON(WSMessage{Type: "ping"}); err != nil {
				terminal.conn.Close()
				delete(WSManager.connections, hostID)
			}
			terminal.mu.Unlock()
		}
		WSManager.mu.Unlock()
	}
}

func init() {
	go CleanupStaleConnections()
}

// WsSyncHandler handles WebSocket sync connections
func WsSyncHandler(c *gin.Context) {
	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		log.Printf("WebSocket upgrade failed: %v", err)
		return
	}
	defer conn.Close()

	// Handle sync messages
	for {
		_, message, err := conn.ReadMessage()
		if err != nil {
			return
		}

		var msg WSMessage
		if err := json.Unmarshal(message, &msg); err != nil {
			continue
		}

		switch msg.Type {
		case "sync":
			// Handle sync
			conn.WriteJSON(WSMessage{
				Type:    "synced",
				Payload: "ok",
			})
		}
	}
}
