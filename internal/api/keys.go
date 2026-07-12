package api

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/termvault/termvault/internal/auth"
	"github.com/termvault/termvault/internal/db"
	"golang.org/x/crypto/ssh"
)

type ImportKeyRequest struct {
	Name               string `json:"name" binding:"required"`
	Description        string `json:"description"`
	KeyType            string `json:"keyType"`
	EncryptedPrivKey   string `json:"encryptedPrivateKey" binding:"required"`
	PublicKey          string `json:"publicKey"`
	Fingerprint        string `json:"fingerprint"`
	VaultID            string `json:"vaultId"`
}

type GenerateKeyRequest struct {
	Name        string `json:"name" binding:"required"`
	Description string `json:"description"`
	KeyType     string `json:"keyType" binding:"required,oneof=rsa ed25519 ecdsa"`
	VaultID     string `json:"vaultId"`
}

func ListKeys(c *gin.Context) {
	userID := auth.GetUserID(c)
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	vaultID := c.Query("vaultId")
	if vaultID != "" && !vaultBelongsToUser(userID, vaultID) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid vault"})
		return
	}

	q := db.GetDB().Where("user_id = ?", userID)
	if vaultID != "" {
		q = q.Where("vault_id = ?", vaultID)
	}

	var keys []db.Keychain
	if result := q.Order("created_at DESC").Find(&keys); result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch keys"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"keys": keys})
}

func ImportKey(c *gin.Context) {
	userID := auth.GetUserID(c)
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	var req ImportKeyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	vaultID, ok := resolveVaultID(userID, req.VaultID)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "a valid vault is required"})
		return
	}

	// Auto-derive public key and fingerprint from private key when not provided
	if req.PublicKey == "" || req.Fingerprint == "" {
		parsed, err := ssh.ParseRawPrivateKey([]byte(req.EncryptedPrivKey))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("failed to parse private key: %v", err)})
			return
		}

		signer, err := ssh.NewSignerFromKey(parsed)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("unsupported private key type: %v", err)})
			return
		}

		sshPubKey := signer.PublicKey()

		if req.PublicKey == "" {
			req.PublicKey = string(ssh.MarshalAuthorizedKey(sshPubKey))
		}
		if req.Fingerprint == "" {
			fp := sha256.Sum256(sshPubKey.Marshal())
			req.Fingerprint = "SHA256:" + strings.TrimRight(base64.StdEncoding.EncodeToString(fp[:]), "=")
		}

		if req.KeyType == "" {
			switch sshPubKey.Type() {
			case "ssh-ed25519":
				req.KeyType = "ed25519"
			case "ssh-rsa":
				req.KeyType = "rsa"
			case "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521":
				req.KeyType = "ecdsa"
			}
		}
	}

	key := db.Keychain{
		UserID:           userID,
		VaultID:          &vaultID,
		Name:             req.Name,
		Description:      req.Description,
		KeyType:          req.KeyType,
		PublicKey:        req.PublicKey,
		EncryptedPrivKey: []byte(req.EncryptedPrivKey),
		Fingerprint:      req.Fingerprint,
	}

	if result := db.GetDB().Create(&key); result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to import key"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"key": key})
}

func DeleteKey(c *gin.Context) {
	userID := auth.GetUserID(c)
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	keyID := c.Param("id")

	var key db.Keychain
	if result := db.GetDB().Where("id = ? AND user_id = ?", keyID, userID).First(&key); result.Error != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "key not found"})
		return
	}

	if result := db.GetDB().Delete(&key); result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete key"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "key deleted"})
}

func GenerateKey(c *gin.Context) {
	userID := auth.GetUserID(c)
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	var req GenerateKeyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	vaultID, ok := resolveVaultID(userID, req.VaultID)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "a valid vault is required"})
		return
	}

	var privKey crypto.PrivateKey
	var err error

	switch req.KeyType {
	case "ed25519":
		_, privKey, err = ed25519.GenerateKey(rand.Reader)
	case "rsa":
		privKey, err = rsa.GenerateKey(rand.Reader, 4096)
	case "ecdsa":
		privKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "unsupported key type"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to generate key: %v", err)})
		return
	}

	sshPubKey, err := ssh.NewPublicKey(privKey.(crypto.Signer).Public())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to derive SSH public key: %v", err)})
		return
	}

	pubKeyStr := string(ssh.MarshalAuthorizedKey(sshPubKey))

	fingerprint := sha256.Sum256(sshPubKey.Marshal())
	fingerprintStr := "SHA256:" + strings.TrimRight(base64.StdEncoding.EncodeToString(fingerprint[:]), "=")

	privKeyPEM, err := ssh.MarshalPrivateKey(privKey, "")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to marshal private key: %v", err)})
		return
	}
	privKeyBytes := pem.EncodeToMemory(privKeyPEM)

	key := db.Keychain{
		UserID:           userID,
		VaultID:          &vaultID,
		Name:             req.Name,
		Description:      req.Description,
		KeyType:          req.KeyType,
		PublicKey:        pubKeyStr,
		EncryptedPrivKey: privKeyBytes,
		Fingerprint:      fingerprintStr,
	}

	if result := db.GetDB().Create(&key); result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save key"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"key": key, "privateKey": string(privKeyBytes)})
}
