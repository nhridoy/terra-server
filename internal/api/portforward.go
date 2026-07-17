package api

import (
	"net/http"
	"strconv"
	"sync"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/termvault/termvault/internal/auth"
	"github.com/termvault/termvault/internal/db"
	"github.com/termvault/termvault/internal/ssh"
)

type PortForwardRequest struct {
	HostID     string `json:"hostId" binding:"required"`
	Type       string `json:"type" binding:"required"` // "local" or "remote"
	LocalAddr  string `json:"localAddr" binding:"required"`
	RemoteAddr string `json:"remoteAddr" binding:"required"`
}

type PortForwardResponse struct {
	ID        string `json:"id"`
	Type      string `json:"type"`
	LocalAddr string `json:"localAddr"`
	RemoteAddr string `json:"remoteAddr"`
	Status    string `json:"status"`
}

type PortForwardManager struct {
	forwards map[string]*ssh.PortForward
	clients  map[string]*ssh.Client
	mu       sync.RWMutex
}

func NewPortForwardManager() *PortForwardManager {
	return &PortForwardManager{
		forwards: make(map[string]*ssh.PortForward),
		clients:  make(map[string]*ssh.Client),
	}
}

var PFManager = NewPortForwardManager()

// CreatePortForward creates a new port forwarding rule
func CreatePortForward(c *gin.Context) {
	userID := auth.GetUserID(c)
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	var req PortForwardRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validate host belongs to user
	var host db.Host
	if result := db.GetDB().Where("id = ? AND user_id = ?", req.HostID, userID).First(&host); result.Error != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "host not found"})
		return
	}

	// Get or create SSH connection
	config := &ssh.Config{
		Host:         host.Hostname,
		Port:         host.Port,
		Username:     host.Username,
		Password:     host.Password,
		KeyBytes:     host.PrivateKey,
		KeyPassphrase: host.Passphrase,
	}

	client, err := ssh.DefaultManager.GetOrCreate(userID+":"+req.HostID, config)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "connection failed: " + err.Error()})
		return
	}

	// Create port forward
	id := uuid.New().String()
	pf := &ssh.PortForward{
		ID:         id,
		Type:       req.Type,
		LocalAddr:  req.LocalAddr,
		RemoteAddr: req.RemoteAddr,
	}

	// Start port forwarding
	if err := client.StartPortForward(pf); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to start port forward: " + err.Error()})
		return
	}

	// Store
	PFManager.mu.Lock()
	PFManager.forwards[id] = pf
	PFManager.clients[id] = client
	PFManager.mu.Unlock()

	c.JSON(http.StatusOK, PortForwardResponse{
		ID:         id,
		Type:       pf.Type,
		LocalAddr:  pf.LocalAddr,
		RemoteAddr: pf.RemoteAddr,
		Status:     "active",
	})
}

// ListPortForwards lists all port forwarding rules
func ListPortForwards(c *gin.Context) {
	userID := auth.GetUserID(c)
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	hostID := c.Query("hostId")

	PFManager.mu.RLock()
	defer PFManager.mu.RUnlock()

	var forwards []PortForwardResponse
	for id, pf := range PFManager.forwards {
		// Filter by host if specified
		if hostID != "" && pf.ID != hostID {
			continue
		}

		status := "inactive"
		if pf.IsActive() {
			status = "active"
		}

		forwards = append(forwards, PortForwardResponse{
			ID:         id,
			Type:       pf.Type,
			LocalAddr:  pf.LocalAddr,
			RemoteAddr: pf.RemoteAddr,
			Status:     status,
		})
	}

	c.JSON(http.StatusOK, gin.H{"forwards": forwards})
}

// DeletePortForward stops and removes a port forwarding rule
func DeletePortForward(c *gin.Context) {
	userID := auth.GetUserID(c)
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	id := c.Param("id")

	PFManager.mu.Lock()
	defer PFManager.mu.Unlock()

	pf, exists := PFManager.forwards[id]
	if !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "port forward not found"})
		return
	}

	// Get client and stop
	if client, ok := PFManager.clients[id]; ok {
		client.StopPortForward(pf)
		delete(PFManager.clients, id)
	}

	delete(PFManager.forwards, id)

	c.JSON(http.StatusOK, gin.H{"message": "port forward deleted"})
}

// GetPortForwardStatus returns the status of a port forwarding rule
func GetPortForwardStatus(c *gin.Context) {
	userID := auth.GetUserID(c)
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	id := c.Param("id")

	PFManager.mu.RLock()
	defer PFManager.mu.RUnlock()

	pf, exists := PFManager.forwards[id]
	if !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "port forward not found"})
		return
	}

	status := "inactive"
	if pf.IsActive() {
		status = "active"
	}

	c.JSON(http.StatusOK, PortForwardResponse{
		ID:         id,
		Type:       pf.Type,
		LocalAddr:  pf.LocalAddr,
		RemoteAddr: pf.RemoteAddr,
		Status:     status,
	})
}

// ParsePort parses a port string to int
func ParsePort(portStr string) (int, error) {
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return 0, err
	}
	if port < 1 || port > 65535 {
		return 0, http.ErrNotSupported
	}
	return port, nil
}
