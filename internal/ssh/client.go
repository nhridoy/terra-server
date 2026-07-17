package ssh

import (
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// Client represents an SSH connection to a remote host
type Client struct {
	conn        *ssh.Client
	config      *ssh.ClientConfig
	host        string
	port        int
	username    string
	password    string
	keyBytes    []byte
	keyPassphrase string
	connected   bool
	lastUsed    time.Time
	mu          sync.RWMutex
	sessions    map[string]*Session
}

// Session represents an SSH session (terminal)
type Session struct {
	id      string
	session *ssh.Session
	stdin   io.WriteCloser
	output  io.Reader
	pty     bool
	columns int
	rows    int
}

// PortForward represents a port forwarding rule
type PortForward struct {
	ID        string
	Type      string // "local" or "remote"
	LocalAddr string
	RemoteAddr string
	listener  net.Listener
	active    bool
}

// IsActive returns whether the port forward is active
func (pf *PortForward) IsActive() bool {
	return pf.active
}

// Config holds SSH connection configuration
type Config struct {
	Host         string
	Port         int
	Username     string
	Password     string
	KeyBytes     []byte
	KeyPassphrase string
	Timeout      time.Duration
}

// NewClient creates a new SSH client
func NewClient(config *Config) *Client {
	return &Client{
		host:     config.Host,
		port:     config.Port,
		username: config.Username,
		password: config.Password,
		keyBytes: config.KeyBytes,
		keyPassphrase: config.KeyPassphrase,
		sessions: make(map[string]*Session),
	}
}

// Connect establishes the SSH connection
func (c *Client) Connect() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.connected {
		return nil
	}

	// Build auth methods
	var authMethods []ssh.AuthMethod

	// Password authentication
	if c.password != "" {
		authMethods = append(authMethods, ssh.Password(c.password))
	}

	// Key authentication
	if len(c.keyBytes) > 0 {
		signer, err := parsePrivateKey(c.keyBytes, c.keyPassphrase)
		if err != nil {
			return fmt.Errorf("failed to parse private key: %w", err)
		}
		authMethods = append(authMethods, ssh.PublicKeys(signer))
	}

	if len(authMethods) == 0 {
		return fmt.Errorf("no authentication method provided")
	}

	// SSH client config
	c.config = &ssh.ClientConfig{
		User:            c.username,
		Auth:            authMethods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // In production, use known hosts
		Timeout:         10 * time.Second,
	}

	// Connect
	addr := fmt.Sprintf("%s:%d", c.host, c.port)
	conn, err := ssh.Dial("tcp", addr, c.config)
	if err != nil {
		return fmt.Errorf("failed to connect: %w", err)
	}

	c.conn = conn
	c.connected = true
	c.lastUsed = time.Now()

	return nil
}

// Disconnect closes the SSH connection
func (c *Client) Disconnect() {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Close all sessions
	for _, session := range c.sessions {
		session.session.Close()
	}
	c.sessions = make(map[string]*Session)

	// Close connection
	if c.conn != nil {
		c.conn.Close()
		c.conn = nil
	}

	c.connected = false
}

// IsConnected returns connection status
func (c *Client) IsConnected() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.connected
}

// NewSession creates a new SSH session (terminal) with merged stdout/stderr
func (c *Client) NewSession(id string) (*Session, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.connected {
		return nil, fmt.Errorf("not connected")
	}

	session, err := c.conn.NewSession()
	if err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	stdin, err := session.StdinPipe()
	if err != nil {
		session.Close()
		return nil, fmt.Errorf("failed to get stdin: %w", err)
	}

	// Create a single merged output stream for both stdout and stderr.
	// This avoids the race condition where early PAM/MOTD output
	// is lost when separate stdout/stderr readers.
	pr, pw := io.Pipe()
	session.Stdout = pw
	session.Stderr = pw

	sess := &Session{
		id:      id,
		session: session,
		stdin:   stdin,
		output:  pr,
	}

	c.sessions[id] = sess
	return sess, nil
}

// RequestPTY requests a pseudo-terminal
func (s *Session) RequestPTY(cols, rows int) error {
	modes := ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}

	err := s.session.RequestPty("xterm-256color", rows, cols, modes)
	if err != nil {
		return fmt.Errorf("failed to request PTY: %w", err)
	}

	s.pty = true
	s.columns = cols
	s.rows = rows

	return nil
}

// StartShell starts an interactive shell
func (s *Session) StartShell() error {
	err := s.session.Shell()
	if err != nil {
		return fmt.Errorf("failed to start shell: %w", err)
	}
	return nil
}

// Run executes a command
func (s *Session) Run(command string) (string, error) {
	output, err := s.session.CombinedOutput(command)
	if err != nil {
		return string(output), fmt.Errorf("command failed: %w", err)
	}
	return string(output), nil
}

// Write sends input to the session
func (s *Session) Write(data []byte) (int, error) {
	return s.stdin.Write(data)
}

// Output returns the merged stdout/stderr reader
func (s *Session) Output() io.Reader {
	return s.output
}

// Read reads output from the merged output stream
func (s *Session) Read(buf []byte) (int, error) {
	if s.output == nil {
		return 0, io.EOF
	}
	return s.output.Read(buf)
}

// Resize changes the terminal size
func (s *Session) Resize(cols, rows int) error {
	err := s.session.WindowChange(rows, cols)
	if err != nil {
		return fmt.Errorf("failed to resize: %w", err)
	}
	s.columns = cols
	s.rows = rows
	return nil
}

// Close closes the session
func (s *Session) Close() error {
	s.stdin.Close()
	return s.session.Close()
}

// GetSFTPClient creates a new SFTP client over the shared SSH connection.
// Each caller gets its own SFTP channel and is responsible for closing it.
func (c *Client) GetSFTPClient() (*sftp.Client, error) {
	c.mu.RLock()
	if !c.connected {
		c.mu.RUnlock()
		return nil, fmt.Errorf("not connected")
	}
	conn := c.conn
	c.mu.RUnlock()

	sftpClient, err := sftp.NewClient(conn)
	if err != nil {
		return nil, fmt.Errorf("failed to create SFTP client: %w", err)
	}

	// Track last successful use for idle timeout
	c.mu.Lock()
	c.lastUsed = time.Now()
	c.mu.Unlock()

	return sftpClient, nil
}

// LastUsed returns the time this connection was last actively used.
func (c *Client) LastUsed() time.Time {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.lastUsed
}

// StartPortForward starts a port forwarding rule
func (c *Client) StartPortForward(pf *PortForward) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.connected {
		return fmt.Errorf("not connected")
	}

	var listener net.Listener
	var err error

	switch pf.Type {
	case "local":
		// Listen locally, forward to remote
		listener, err = net.Listen("tcp", pf.LocalAddr)
		if err != nil {
			return fmt.Errorf("failed to listen locally: %w", err)
		}

		go c.handleLocalForward(listener, pf.RemoteAddr)

	case "remote":
		// Listen on remote, forward to local
		listener, err = c.conn.Listen("tcp", pf.LocalAddr)
		if err != nil {
			return fmt.Errorf("failed to listen on remote: %w", err)
		}

		go c.handleRemoteForward(listener, pf.LocalAddr)

	default:
		return fmt.Errorf("invalid port forward type: %s", pf.Type)
	}

	pf.listener = listener
	pf.active = true
	return nil
}

// StopPortForward stops a port forwarding rule
func (c *Client) StopPortForward(pf *PortForward) {
	if pf.listener != nil {
		pf.listener.Close()
		pf.listener = nil
	}
	pf.active = false
}

func (c *Client) handleLocalForward(listener net.Listener, remoteAddr string) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return // Listener closed
		}

		go c.forwardConnection(conn, remoteAddr)
	}
}

func (c *Client) handleRemoteForward(listener net.Listener, localAddr string) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return // Listener closed
		}

		go c.forwardToRemote(conn, localAddr)
	}
}

func (c *Client) forwardConnection(localConn net.Conn, remoteAddr string) {
	defer localConn.Close()

	remoteConn, err := c.conn.Dial("tcp", remoteAddr)
	if err != nil {
		return
	}
	defer remoteConn.Close()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		io.Copy(remoteConn, localConn)
	}()

	go func() {
		defer wg.Done()
		io.Copy(localConn, remoteConn)
	}()

	wg.Wait()
}

func (c *Client) forwardToRemote(remoteConn net.Conn, localAddr string) {
	defer remoteConn.Close()

	localConn, err := net.Dial("tcp", localAddr)
	if err != nil {
		return
	}
	defer localConn.Close()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		io.Copy(localConn, remoteConn)
	}()

	go func() {
		defer wg.Done()
		io.Copy(remoteConn, localConn)
	}()

	wg.Wait()
}

// parsePrivateKey parses a PEM-encoded private key
func parsePrivateKey(keyBytes []byte, passphrase string) (ssh.Signer, error) {
	if passphrase != "" {
		return ssh.ParsePrivateKeyWithPassphrase(keyBytes, []byte(passphrase))
	}
	return ssh.ParsePrivateKey(keyBytes)
}
