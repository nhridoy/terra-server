package db

import (
	"time"

	"gorm.io/gorm"
)

type User struct {
	ID                 string         `gorm:"primaryKey" json:"id"`
	Email              string         `gorm:"uniqueIndex;size:255;not null" json:"email"`
	Username           string         `gorm:"size:100;not null" json:"username"`
	SrpSalt            string         `gorm:"size:64" json:"-"`
	SrpVerifier        string         `gorm:"size:512" json:"-"`
	KeyNonce           string         `gorm:"size:64" json:"-"`
	KeySalt            string         `gorm:"size:64" json:"-"`
	EncryptedPK        string         `gorm:"type:text" json:"-"`
	EncryptedPriv      string         `gorm:"type:text" json:"-"`
	PublicKey          string         `gorm:"type:text" json:"-"`
	HasMasterPassword  bool           `gorm:"default:false" json:"-"`
	CreatedAt          time.Time      `json:"createdAt"`
	UpdatedAt          time.Time      `json:"updatedAt"`
	DeletedAt          gorm.DeletedAt `gorm:"index" json:"-"`
}

type Vault struct {
	ID          string         `gorm:"primaryKey" json:"id"`
	UserID      string         `gorm:"index;not null" json:"user_id"`
	Name        string         `gorm:"size:255;not null" json:"name"`
	Description string         `gorm:"type:text" json:"description"`
	IsDefault   bool           `gorm:"default:false" json:"is_default"`
	IsSystem    bool           `gorm:"default:false" json:"is_system"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
	DeletedAt   gorm.DeletedAt `gorm:"index" json:"-"`
}

type Host struct {
	ID            string         `gorm:"primaryKey" json:"id"`
	UserID        string         `gorm:"index;not null" json:"user_id"`
	VaultID       string         `gorm:"index" json:"vault_id"`
	GroupID       string         `gorm:"index" json:"group_id"`
	Name          string         `gorm:"size:255;not null" json:"name"`
	Address       string         `gorm:"size:255;not null" json:"address"`
	Port          int            `gorm:"default:22" json:"port"`
	Username      string         `gorm:"size:255" json:"username"`
	Password      string         `gorm:"type:text" json:"-"`
	PrivateKey    string         `gorm:"type:text" json:"-"`
	Passphrase    string         `gorm:"type:text" json:"-"`
	Color         string         `gorm:"size:32" json:"color"`
	Tags          string         `gorm:"type:text" json:"tags"`
	Icon          string         `gorm:"size:255" json:"icon"`
	SortOrder     int            `gorm:"default:0" json:"sort_order"`
	AuthType      string         `gorm:"size:50;default:password" json:"auth_type"`
	KeyID         string         `gorm:"size:255" json:"key_id"`
	CreatedAt     time.Time      `json:"created_at"`
	UpdatedAt     time.Time      `json:"updated_at"`
	DeletedAt     gorm.DeletedAt `gorm:"index" json:"-"`
}

type Group struct {
	ID        string         `gorm:"primaryKey" json:"id"`
	UserID    string         `gorm:"index;not null" json:"user_id"`
	VaultID   string         `gorm:"index" json:"vault_id"`
	ParentID  string         `gorm:"index" json:"parent_id"`
	Name      string         `gorm:"size:255;not null" json:"name"`
	SortOrder int            `gorm:"default:0" json:"sort_order"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`
}

type Keychain struct {
	ID                  string         `gorm:"primaryKey" json:"id"`
	UserID              string         `gorm:"index;not null" json:"user_id"`
	VaultID             string         `gorm:"index" json:"vault_id"`
	Name                string         `gorm:"size:255;not null" json:"name"`
	Type                string         `gorm:"column:key_type;size:50;not null" json:"key_type"`
	Data                string         `gorm:"type:text" json:"-"`
	Description         string         `gorm:"type:text" json:"description"`
	Fingerprint         string         `gorm:"size:255" json:"fingerprint"`
	PublicKey           string         `gorm:"type:text" json:"public_key"`
	EncryptedPrivateKey string         `gorm:"type:text" json:"encrypted_private_key"`
	CreatedAt           time.Time      `json:"created_at"`
	UpdatedAt           time.Time      `json:"updated_at"`
	DeletedAt           gorm.DeletedAt `gorm:"index" json:"-"`
}

type Snippet struct {
	ID          string         `gorm:"primaryKey" json:"id"`
	UserID      string         `gorm:"index;not null" json:"user_id"`
	VaultID     string         `gorm:"index" json:"vault_id"`
	Name        string         `gorm:"size:255;not null" json:"name"`
	Command     string         `gorm:"type:text;not null" json:"command"`
	Description string         `gorm:"type:text" json:"description"`
	Tags        string         `gorm:"type:text" json:"tags"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
	DeletedAt   gorm.DeletedAt `gorm:"index" json:"-"`
}

type Workspace struct {
	ID        string         `gorm:"primaryKey" json:"id"`
	UserID    string         `gorm:"index;not null" json:"user_id"`
	VaultID   string         `gorm:"index" json:"vault_id"`
	Name      string         `gorm:"size:255;not null" json:"name"`
	Layout    string         `gorm:"type:text" json:"layout"`
	HostIDs   string         `gorm:"type:text" json:"host_ids"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`
}

type TabGroup struct {
	ID        string         `gorm:"primaryKey" json:"id"`
	UserID    string         `gorm:"index;not null" json:"user_id"`
	VaultID   string         `gorm:"index" json:"vault_id"`
	Name      string         `gorm:"size:255;not null" json:"name"`
	Tabs      string         `gorm:"type:text" json:"tabs"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`
}

type Settings struct {
	ID          string         `gorm:"primaryKey" json:"id"`
	UserID      string         `gorm:"uniqueIndex;not null" json:"user_id"`
	Theme       string         `gorm:"size:50" json:"theme"`
	FontFamily  string         `gorm:"size:100" json:"font_family"`
	FontSize    int            `gorm:"default:14" json:"font_size"`
	CursorStyle string         `gorm:"size:50" json:"cursor_style"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
	DeletedAt   gorm.DeletedAt `gorm:"index" json:"-"`
}

type RefreshToken struct {
	ID        string         `gorm:"primaryKey" json:"id"`
	UserID    string         `gorm:"index;not null" json:"userId"`
	Token     string         `gorm:"uniqueIndex;size:512;not null" json:"-"`
	ExpiresAt time.Time      `gorm:"not null" json:"expiresAt"`
	CreatedAt time.Time      `json:"createdAt"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`
}

type Team struct {
	ID          string         `gorm:"primaryKey" json:"id"`
	Name        string         `gorm:"size:255;not null" json:"name"`
	Description string         `gorm:"type:text" json:"description"`
	OwnerID     string         `gorm:"index;not null" json:"ownerId"`
	CreatedAt   time.Time      `json:"createdAt"`
	UpdatedAt   time.Time      `json:"updatedAt"`
	DeletedAt   gorm.DeletedAt `gorm:"index" json:"-"`
}

type TeamMember struct {
	ID       string         `gorm:"primaryKey" json:"id"`
	TeamID   string         `gorm:"index;not null" json:"teamId"`
	UserID   string         `gorm:"index;not null" json:"userId"`
	Username string         `gorm:"size:100" json:"username"`
	Email    string         `gorm:"size:255" json:"email"`
	Role     string         `gorm:"size:20;default:member" json:"role"`
	JoinedAt time.Time      `json:"joinedAt"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`
}

type SharedVault struct {
	ID        string         `gorm:"primaryKey" json:"id"`
	TeamID    string         `gorm:"index;not null" json:"teamId"`
	VaultID   string         `gorm:"index;not null" json:"vaultId"`
	Name      string         `gorm:"size:255" json:"name"`
	CreatedAt time.Time      `json:"createdAt"`
	UpdatedAt time.Time      `json:"updatedAt"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`
}
