package ssh

import (
	"fmt"
	"io"
	"os"
	posixpath "path"
	"path/filepath"
	"time"

	"github.com/pkg/sftp"
)

// SFTPClient wraps the SFTP client for file operations
type SFTPClient struct {
	client *sftp.Client
}

// FileInfo represents file information
type FileInfo struct {
	Name    string `json:"name"`
	Size    int64  `json:"size"`
	Mode    string `json:"mode"`
	ModTime string `json:"modTime"`
	IsDir   bool   `json:"isDir"`
	Path    string `json:"path"`
}

// NewSFTPClient creates a new SFTP client wrapper
func NewSFTPClient(client *sftp.Client) *SFTPClient {
	return &SFTPClient{client: client}
}

// ListFiles lists files in a directory
func (s *SFTPClient) ListFiles(path string) ([]FileInfo, error) {
	entries, err := s.client.ReadDir(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read directory: %w", err)
	}

	var files []FileInfo
	for _, entry := range entries {
		info := entry
		files = append(files, FileInfo{
			Name:    info.Name(),
			Size:    info.Size(),
			Mode:    info.Mode().String(),
			ModTime: info.ModTime().Format(time.RFC3339),
			IsDir:   info.IsDir(),
			Path:    posixpath.Join(path, info.Name()),
		})
	}

	return files, nil
}

// GetFileInfo returns information about a file
func (s *SFTPClient) GetFileInfo(path string) (*FileInfo, error) {
	info, err := s.client.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("failed to stat file: %w", err)
	}

	return &FileInfo{
		Name:    info.Name(),
		Size:    info.Size(),
		Mode:    info.Mode().String(),
		ModTime: info.ModTime().Format(time.RFC3339),
		IsDir:   info.IsDir(),
		Path:    path,
	}, nil
}

// ReadFile reads a file and returns its contents
func (s *SFTPClient) ReadFile(path string) ([]byte, error) {
	file, err := s.client.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	return data, nil
}

// WriteFile writes data to a file
func (s *SFTPClient) WriteFile(path string, data []byte) error {
	file, err := s.client.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	_, err = file.Write(data)
	if err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	return nil
}

// DownloadFile downloads a file to a local path
func (s *SFTPClient) DownloadFile(remotePath, localPath string) error {
	// Create local directory if needed
	dir := filepath.Dir(localPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create local directory: %w", err)
	}

	// Open remote file
	remoteFile, err := s.client.Open(remotePath)
	if err != nil {
		return fmt.Errorf("failed to open remote file: %w", err)
	}
	defer remoteFile.Close()

	// Create local file
	localFile, err := os.Create(localPath)
	if err != nil {
		return fmt.Errorf("failed to create local file: %w", err)
	}
	defer localFile.Close()

	// Copy file contents
	_, err = io.Copy(localFile, remoteFile)
	if err != nil {
		return fmt.Errorf("failed to copy file: %w", err)
	}

	return nil
}

// UploadFile uploads a file from a local path
func (s *SFTPClient) UploadFile(localPath, remotePath string) error {
	// Open local file
	localFile, err := os.Open(localPath)
	if err != nil {
		return fmt.Errorf("failed to open local file: %w", err)
	}
	defer localFile.Close()

	// Create remote file
	remoteFile, err := s.client.Create(remotePath)
	if err != nil {
		return fmt.Errorf("failed to create remote file: %w", err)
	}
	defer remoteFile.Close()

	// Copy file contents
	_, err = io.Copy(remoteFile, localFile)
	if err != nil {
		return fmt.Errorf("failed to copy file: %w", err)
	}

	return nil
}

// DeleteFile deletes a file
func (s *SFTPClient) DeleteFile(path string) error {
	err := s.client.Remove(path)
	if err != nil {
		return fmt.Errorf("failed to delete file: %w", err)
	}
	return nil
}

// Mkdir creates a directory
func (s *SFTPClient) Mkdir(path string) error {
	err := s.client.MkdirAll(path)
	if err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}
	return nil
}

// Rmdir removes a directory
func (s *SFTPClient) Rmdir(path string) error {
	err := s.client.RemoveDirectory(path)
	if err != nil {
		return fmt.Errorf("failed to remove directory: %w", err)
	}
	return nil
}

// Rename renames a file or directory
func (s *SFTPClient) Rename(oldPath, newPath string) error {
	err := s.client.Rename(oldPath, newPath)
	if err != nil {
		return fmt.Errorf("failed to rename: %w", err)
	}
	return nil
}

// CopyFile copies a file from src to dst on the remote host.
func (s *SFTPClient) CopyFile(src, dst string) error {
	srcFile, err := s.client.Open(src)
	if err != nil {
		return fmt.Errorf("failed to open source: %w", err)
	}
	defer srcFile.Close()

	dstFile, err := s.client.Create(dst)
	if err != nil {
		return fmt.Errorf("failed to create destination: %w", err)
	}
	defer dstFile.Close()

	if _, err := io.Copy(dstFile, srcFile); err != nil {
		return fmt.Errorf("failed to copy: %w", err)
	}
	return nil
}

// Chmod changes file permissions
func (s *SFTPClient) Chmod(path string, mode os.FileMode) error {
	err := s.client.Chmod(path, mode)
	if err != nil {
		return fmt.Errorf("failed to change permissions: %w", err)
	}
	return nil
}

// Chown changes file ownership
func (s *SFTPClient) Chown(path string, uid, gid int) error {
	err := s.client.Chown(path, uid, gid)
	if err != nil {
		return fmt.Errorf("failed to change ownership: %w", err)
	}
	return nil
}

// GetDiskUsage returns disk usage information
func (s *SFTPClient) GetDiskUsage(path string) (map[string]int64, error) {
	// This is a simplified version
	// In production, you'd want to walk the directory tree
	info, err := s.client.Stat(path)
	if err != nil {
		return nil, err
	}

	return map[string]int64{
		"size": info.Size(),
	}, nil
}

// Close closes the SFTP client
func (s *SFTPClient) Close() error {
	return s.client.Close()
}
