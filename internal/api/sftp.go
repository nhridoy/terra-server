package api

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/termvault/termvault/internal/auth"
	"github.com/termvault/termvault/internal/db"
	"github.com/termvault/termvault/internal/ssh"
)

type FileItem struct {
	Name       string `json:"name"`
	Path       string `json:"path"`
	Type       string `json:"type"`
	Size       int64  `json:"size"`
	Permission string `json:"permissions"`
	Owner      string `json:"owner"`
	Group      string `json:"group"`
	ModifiedAt string `json:"modifiedAt"`
	IsHidden   bool   `json:"isHidden"`
}

type ListFilesRequest struct {
	Path string `json:"path" form:"path"`
}

type ReadFileRequest struct {
	Path string `json:"path" form:"path"`
}

type WriteFileRequest struct {
	Path    string `json:"path" binding:"required"`
	Content string `json:"content" binding:"required"`
}

type UploadFileRequest struct {
	RemotePath string `json:"remotePath" binding:"required"`
	FileName   string `json:"fileName" binding:"required"`
	Content    string `json:"content" binding:"required"`
}

type MoveFileRequest struct {
	OldPath string `json:"oldPath" binding:"required"`
	NewPath string `json:"newPath" binding:"required"`
}

type MkdirRequest struct {
	ParentPath string `json:"parentPath" binding:"required"`
	Name       string `json:"name" binding:"required"`
}

// getSFTPClient gets or creates an SFTP client for a host
func getSFTPClient(hostID, userID string) (*ssh.SFTPClient, error) {
	// Validate host belongs to user
	var host db.Host
	if result := db.GetDB().Where("id = ? AND user_id = ?", hostID, userID).First(&host); result.Error != nil {
		return nil, fmt.Errorf("host not found")
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

	client, err := ssh.DefaultManager.GetOrCreate(hostID, config)
	if err != nil {
		return nil, fmt.Errorf("connection failed: %w", err)
	}

	// Get SFTP client
	sftpClient, err := client.GetSFTPClient()
	if err != nil {
		return nil, fmt.Errorf("SFTP failed: %w", err)
	}

	return ssh.NewSFTPClient(sftpClient), nil
}

// ListFiles lists files on a remote host via SFTP
func ListFiles(c *gin.Context) {
	userID := auth.GetUserID(c)
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	hostID := c.Param("hostId")
	path := c.DefaultQuery("path", "/")

	// Get SFTP client
	sftpClient, err := getSFTPClient(hostID, userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer sftpClient.Close()

	// List files
	files, err := sftpClient.ListFiles(path)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list files: " + err.Error()})
		return
	}

	// Convert to FileItem format
	fileItems := make([]FileItem, len(files))
	for i, f := range files {
		fileItems[i] = FileItem{
			Name:       f.Name,
			Path:       f.Path,
			Type:       fileModeToType(f.Mode),
			Size:       f.Size,
			Permission: f.Mode,
			ModifiedAt: f.ModTime,
			IsHidden:   len(f.Name) > 0 && f.Name[0] == '.',
		}
	}

	c.JSON(http.StatusOK, gin.H{"files": fileItems})
}

// ReadFile reads a file from a remote host
func ReadFile(c *gin.Context) {
	userID := auth.GetUserID(c)
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	hostID := c.Param("hostId")
	filePath := c.Query("path")

	if filePath == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "path is required"})
		return
	}

	// Get SFTP client
	sftpClient, err := getSFTPClient(hostID, userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer sftpClient.Close()

	// Read file
	data, err := sftpClient.ReadFile(filePath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to read file: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"content": string(data)})
}

// WriteFile writes a file to a remote host
func WriteFile(c *gin.Context) {
	userID := auth.GetUserID(c)
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	hostID := c.Param("hostId")

	var req WriteFileRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Get SFTP client
	sftpClient, err := getSFTPClient(hostID, userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer sftpClient.Close()

	// Write file
	if err := sftpClient.WriteFile(req.Path, []byte(req.Content)); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to write file: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "file written"})
}

// UploadFile uploads a file to a remote host
func UploadFile(c *gin.Context) {
	userID := auth.GetUserID(c)
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	hostID := c.Param("hostId")

	// Get the uploaded file
	file, header, err := c.Request.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no file provided"})
		return
	}
	defer file.Close()

	remotePath := c.PostForm("path")
	if remotePath == "" {
		remotePath = "/"
	}

	// Get SFTP client
	sftpClient, err := getSFTPClient(hostID, userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer sftpClient.Close()

	// Create remote file
	fullPath := filepath.Join(remotePath, header.Filename)
	data, err := io.ReadAll(file)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to read uploaded file"})
		return
	}

	if err := sftpClient.WriteFile(fullPath, data); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to upload file: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "file uploaded"})
}

// DeleteFile deletes a file on a remote host
func DeleteFile(c *gin.Context) {
	userID := auth.GetUserID(c)
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	hostID := c.Param("hostId")
	filePath := c.Query("path")

	if filePath == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "path is required"})
		return
	}

	// Get SFTP client
	sftpClient, err := getSFTPClient(hostID, userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer sftpClient.Close()

	// Delete file
	if err := sftpClient.DeleteFile(filePath); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete file: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "file deleted"})
}

// MoveFile moves/renames a file on a remote host
func MoveFile(c *gin.Context) {
	userID := auth.GetUserID(c)
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	hostID := c.Param("hostId")

	var req MoveFileRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Get SFTP client
	sftpClient, err := getSFTPClient(hostID, userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer sftpClient.Close()

	// Rename file
	if err := sftpClient.Rename(req.OldPath, req.NewPath); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to move file: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "file moved"})
}

// Mkdir creates a directory on a remote host
func Mkdir(c *gin.Context) {
	userID := auth.GetUserID(c)
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	hostID := c.Param("hostId")

	var req MkdirRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Get SFTP client
	sftpClient, err := getSFTPClient(hostID, userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer sftpClient.Close()

	// Create directory
	fullPath := filepath.Join(req.ParentPath, req.Name)
	if err := sftpClient.Mkdir(fullPath); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create directory: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "directory created"})
}

// Local file operations (for development/testing)
func LocalListFiles(c *gin.Context) {
	userID := auth.GetUserID(c)
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	path := c.DefaultQuery("path", ".")
	baseDir := getBaseDir(userID)
	fullPath := filepath.Join(baseDir, path)

	// Ensure base directory exists
	if err := os.MkdirAll(baseDir, 0755); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create base directory"})
		return
	}

	entries, err := os.ReadDir(fullPath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to read directory"})
		return
	}

	files := make([]FileItem, 0, len(entries))
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			continue
		}

		isHidden := entry.Name()[0] == '.'
		fileType := "file"
		if entry.IsDir() {
			fileType = "directory"
		}

		files = append(files, FileItem{
			Name:       entry.Name(),
			Path:       filepath.Join(path, entry.Name()),
			Type:       fileType,
			Size:       info.Size(),
			Permission: info.Mode().String(),
			Owner:      "user",
			Group:      "user",
			ModifiedAt: info.ModTime().Format(time.RFC3339),
			IsHidden:   isHidden,
		})
	}

	c.JSON(http.StatusOK, gin.H{"files": files})
}

func LocalReadFile(c *gin.Context) {
	userID := auth.GetUserID(c)
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	filePath := c.Query("path")
	if filePath == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "path is required"})
		return
	}

	baseDir := getBaseDir(userID)
	fullPath := filepath.Join(baseDir, filePath)

	data, err := os.ReadFile(fullPath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to read file"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"content": string(data)})
}

func LocalWriteFile(c *gin.Context) {
	userID := auth.GetUserID(c)
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	var req WriteFileRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	baseDir := getBaseDir(userID)
	fullPath := filepath.Join(baseDir, req.Path)

	// Ensure directory exists
	dir := filepath.Dir(fullPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create directory"})
		return
	}

	if err := os.WriteFile(fullPath, []byte(req.Content), 0644); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to write file"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "file written"})
}

func LocalUploadFile(c *gin.Context) {
	userID := auth.GetUserID(c)
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	// Get the uploaded file
	file, header, err := c.Request.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no file provided"})
		return
	}
	defer file.Close()

	remotePath := c.PostForm("path")
	if remotePath == "" {
		remotePath = "/"
	}

	baseDir := getBaseDir(userID)
	fullPath := filepath.Join(baseDir, remotePath, header.Filename)

	// Ensure directory exists
	dir := filepath.Dir(fullPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create directory"})
		return
	}

	// Create the file
	dst, err := os.Create(fullPath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create file"})
		return
	}
	defer dst.Close()

	// Copy the content
	if _, err := io.Copy(dst, file); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save file"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "file uploaded"})
}

func LocalDeleteFile(c *gin.Context) {
	userID := auth.GetUserID(c)
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	filePath := c.Query("path")
	if filePath == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "path is required"})
		return
	}

	baseDir := getBaseDir(userID)
	fullPath := filepath.Join(baseDir, filePath)

	if err := os.RemoveAll(fullPath); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete file"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "file deleted"})
}

func LocalMkdir(c *gin.Context) {
	userID := auth.GetUserID(c)
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	var req MkdirRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	baseDir := getBaseDir(userID)
	fullPath := filepath.Join(baseDir, req.ParentPath, req.Name)

	if err := os.MkdirAll(fullPath, 0755); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create directory"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "directory created"})
}

// Helper functions
func getBaseDir(userID string) string {
	return filepath.Join("/tmp/termvault", userID)
}

func fileModeToType(mode string) string {
	if len(mode) > 0 && mode[0] == 'd' {
		return "directory"
	}
	return "file"
}

func fileModeToPermissions(mode os.FileMode) string {
	perms := ""
	if mode&os.ModeDir != 0 {
		perms += "d"
	} else {
		perms += "-"
	}
	if mode&os.ModeAppend != 0 {
		perms += "a"
	} else {
		perms += "-"
	}
	if mode&os.ModeExclusive != 0 {
		perms += "l"
	} else {
		perms += "-"
	}

	// Owner
	if mode&0400 != 0 {
		perms += "r"
	} else {
		perms += "-"
	}
	if mode&0200 != 0 {
		perms += "w"
	} else {
		perms += "-"
	}
	if mode&0100 != 0 {
		perms += "x"
	} else {
		perms += "-"
	}

	// Group
	if mode&0040 != 0 {
		perms += "r"
	} else {
		perms += "-"
	}
	if mode&0020 != 0 {
		perms += "w"
	} else {
		perms += "-"
	}
	if mode&0010 != 0 {
		perms += "x"
	} else {
		perms += "-"
	}

	// Other
	if mode&0004 != 0 {
		perms += "r"
	} else {
		perms += "-"
	}
	if mode&0002 != 0 {
		perms += "w"
	} else {
		perms += "-"
	}
	if mode&0001 != 0 {
		perms += "x"
	} else {
		perms += "-"
	}

	return perms
}
