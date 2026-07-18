package db

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type User struct {
	ID            string         `gorm:"type:uuid;primaryKey" json:"id"`
	Email         string         `gorm:"type:varchar(255);uniqueIndex;not null" json:"email"`
	Username      string         `gorm:"type:varchar(100);not null" json:"username"`
	PasswordHash  string         `gorm:"type:varchar(255)" json:"-"`
	AvatarURL     string         `gorm:"type:text" json:"avatarUrl,omitempty"`
	SrpSalt       string         `gorm:"type:varchar(255)" json:"-"`
	SrpVerifier   string         `gorm:"type:varchar(255)" json:"-"`
	PublicKey     string         `gorm:"type:text" json:"publicKey,omitempty"`
	EncryptedPK   string         `gorm:"type:text" json:"encryptedPersonalKey,omitempty"`
	EncryptedPriv string         `gorm:"type:text" json:"encryptedPrivateKey,omitempty"`
	KeyNonce      string         `gorm:"type:varchar(255)" json:"nonce,omitempty"`
	KeySalt       string         `gorm:"type:varchar(255)" json:"salt,omitempty"`
	CreatedAt     time.Time      `json:"createdAt"`
	UpdatedAt     time.Time      `json:"updatedAt"`
	DeletedAt     gorm.DeletedAt `gorm:"index" json:"-"`
}

func (u *User) BeforeCreate(tx *gorm.DB) error {
	if u.ID == "" {
		u.ID = uuid.New().String()
	}
	return nil
}

type OAuthConnection struct {
	ID             string    `gorm:"type:uuid;primaryKey" json:"id"`
	UserID         string    `gorm:"type:uuid;index;not null" json:"userId"`
	Provider       string    `gorm:"type:varchar(50);not null" json:"provider"`
	ProviderUserID string    `gorm:"type:varchar(255);not null" json:"providerUserId"`
	AccessToken    string    `gorm:"type:text" json:"-"`
	RefreshToken   string    `gorm:"type:text" json:"-"`
	CreatedAt      time.Time `json:"createdAt"`
}

func (o *OAuthConnection) BeforeCreate(tx *gorm.DB) error {
	if o.ID == "" {
		o.ID = uuid.New().String()
	}
	return nil
}

type Team struct {
	ID        string    `gorm:"type:uuid;primaryKey" json:"id"`
	Name      string    `gorm:"type:varchar(255);not null" json:"name"`
	OwnerID   string    `gorm:"type:uuid;index;not null" json:"ownerId"`
	CreatedAt time.Time `json:"createdAt"`
}

func (t *Team) BeforeCreate(tx *gorm.DB) error {
	if t.ID == "" {
		t.ID = uuid.New().String()
	}
	return nil
}

type TeamMember struct {
	ID        string    `gorm:"type:uuid;primaryKey" json:"id"`
	TeamID    string    `gorm:"type:uuid;index;not null" json:"teamId"`
	UserID    string    `gorm:"type:uuid;index;not null" json:"userId"`
	Role      string    `gorm:"type:varchar(20);default:'member'" json:"role"`
	PublicKey string    `gorm:"type:text" json:"publicKey,omitempty"`
	CreatedAt time.Time `json:"createdAt"`
}

func (tm *TeamMember) BeforeCreate(tx *gorm.DB) error {
	if tm.ID == "" {
		tm.ID = uuid.New().String()
	}
	return nil
}

type Host struct {
	ID             string         `gorm:"type:uuid;primaryKey" json:"id"`
	UserID         string         `gorm:"type:uuid;index" json:"userId"`
	VaultID        *string        `gorm:"type:uuid;index" json:"vaultId,omitempty"`
	TeamID         *string        `gorm:"type:uuid;index" json:"teamId,omitempty"`
	GroupID        *string        `gorm:"type:uuid;index" json:"groupId,omitempty"`
	Name           string         `gorm:"type:varchar(255);not null" json:"name"`
	Hostname       string         `gorm:"type:varchar(255);not null" json:"hostname"`
	Address        string         `gorm:"type:varchar(255)" json:"address,omitempty"`
	Port           int            `gorm:"default:22" json:"port"`
	Username       string         `gorm:"type:varchar(100)" json:"username,omitempty"`
	Password       string         `gorm:"type:varchar(255)" json:"-"`
	PrivateKey     []byte         `gorm:"type:blob" json:"-"`
	Passphrase     string         `gorm:"type:varchar(255)" json:"-"`
	AuthMethod     string         `gorm:"type:varchar(20);default:'password'" json:"authMethod"`
	Tags           string         `gorm:"type:text" json:"tags,omitempty"`
	Color          string         `gorm:"type:varchar(7)" json:"color,omitempty"`
	Icon           string         `gorm:"type:varchar(50)" json:"icon,omitempty"`
	SortOrder      int            `gorm:"default:0" json:"sortOrder"`
	LastConnected  *time.Time     `json:"lastConnected,omitempty"`
	ConnectionCount int           `gorm:"default:0" json:"connectionCount"`
	CreatedAt      time.Time      `json:"createdAt"`
	UpdatedAt      time.Time      `json:"updatedAt"`
	DeletedAt      gorm.DeletedAt `gorm:"index" json:"-"`
}

func (h *Host) BeforeCreate(tx *gorm.DB) error {
	if h.ID == "" {
		h.ID = uuid.New().String()
	}
	return nil
}

type Group struct {
	ID        string         `gorm:"type:uuid;primaryKey" json:"id"`
	UserID    string         `gorm:"type:uuid;index" json:"userId"`
	VaultID   *string        `gorm:"type:uuid;index" json:"vaultId,omitempty"`
	TeamID    *string        `gorm:"type:uuid;index" json:"teamId,omitempty"`
	ParentID  *string        `gorm:"type:uuid;index" json:"parentId,omitempty"`
	Name      string         `gorm:"type:varchar(255);not null" json:"name"`
	SortOrder int            `gorm:"default:0" json:"sortOrder"`
	CreatedAt time.Time      `json:"createdAt"`
	UpdatedAt time.Time      `json:"updatedAt"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`
}

func (g *Group) BeforeCreate(tx *gorm.DB) error {
	if g.ID == "" {
		g.ID = uuid.New().String()
	}
	return nil
}

type Vault struct {
	ID          string         `gorm:"type:uuid;primaryKey" json:"id"`
	UserID      string         `gorm:"type:uuid;index;not null;uniqueIndex:idx_user_vault_name" json:"userId"`
	Name        string         `gorm:"type:varchar(255);not null;uniqueIndex:idx_user_vault_name" json:"name"`
	Description string         `gorm:"type:text" json:"description,omitempty"`
	IsDefault   bool           `gorm:"default:false" json:"isDefault"`
	IsSystem    bool           `gorm:"default:false" json:"isSystem"`
	EncryptedData []byte       `gorm:"type:blob;not null" json:"encryptedData"`
	IV          []byte         `gorm:"type:blob;not null" json:"iv"`
	Salt        []byte         `gorm:"type:blob;not null" json:"salt"`
	CreatedAt   time.Time      `json:"createdAt"`
	UpdatedAt   time.Time      `json:"updatedAt"`
	DeletedAt   gorm.DeletedAt `gorm:"index" json:"-"`
}

func (v *Vault) BeforeCreate(tx *gorm.DB) error {
	if v.ID == "" {
		v.ID = uuid.New().String()
	}
	return nil
}

type Keychain struct {
	ID                 string         `gorm:"type:uuid;primaryKey" json:"id"`
	UserID             string         `gorm:"type:uuid;index" json:"userId"`
	VaultID            *string        `gorm:"type:uuid;index" json:"vaultId,omitempty"`
	TeamID             *string        `gorm:"type:uuid;index" json:"teamId,omitempty"`
	Name               string         `gorm:"type:varchar(255);not null" json:"name"`
	Description        string         `gorm:"type:text" json:"description,omitempty"`
	KeyType            string         `gorm:"type:varchar(20);not null" json:"keyType"`
	PublicKey          string         `gorm:"type:text;not null" json:"publicKey"`
	EncryptedPrivKey   []byte         `gorm:"type:blob" json:"encryptedPrivateKey,omitempty"`
	Fingerprint        string         `gorm:"type:varchar(100)" json:"fingerprint,omitempty"`
	CreatedAt          time.Time      `json:"createdAt"`
	UpdatedAt          time.Time      `json:"updatedAt"`
	DeletedAt          gorm.DeletedAt `gorm:"index" json:"-"`
}

func (k *Keychain) BeforeCreate(tx *gorm.DB) error {
	if k.ID == "" {
		k.ID = uuid.New().String()
	}
	return nil
}

type Snippet struct {
	ID          string         `gorm:"type:uuid;primaryKey" json:"id"`
	UserID      string         `gorm:"type:uuid;index" json:"userId"`
	VaultID     *string        `gorm:"type:uuid;index" json:"vaultId,omitempty"`
	Name        string         `gorm:"type:varchar(255);not null" json:"name"`
	Command     string         `gorm:"type:text;not null" json:"command"`
	Description string         `gorm:"type:text" json:"description,omitempty"`
	Tags        string         `gorm:"type:text" json:"tags,omitempty"`
	CreatedAt   time.Time      `json:"createdAt"`
	DeletedAt   gorm.DeletedAt `gorm:"index" json:"-"`
}

func (s *Snippet) BeforeCreate(tx *gorm.DB) error {
	if s.ID == "" {
		s.ID = uuid.New().String()
	}
	return nil
}

type SessionLog struct {
	ID        string    `gorm:"type:uuid;primaryKey" json:"id"`
	UserID    string    `gorm:"type:uuid;index" json:"userId"`
	VaultID   *string   `gorm:"type:uuid;index" json:"vaultId,omitempty"`
	HostID    string    `gorm:"type:uuid;index" json:"hostId"`
	StartedAt time.Time `json:"startedAt"`
	EndedAt   *time.Time `json:"endedAt,omitempty"`
	Data      []byte    `gorm:"type:blob" json:"data,omitempty"`
	SizeBytes int64     `json:"sizeBytes,omitempty"`
}

func (s *SessionLog) BeforeCreate(tx *gorm.DB) error {
	if s.ID == "" {
		s.ID = uuid.New().String()
	}
	return nil
}

type Workspace struct {
	ID        string         `gorm:"type:uuid;primaryKey" json:"id"`
	UserID    string         `gorm:"type:uuid;index" json:"userId"`
	VaultID   *string        `gorm:"type:uuid;index" json:"vaultId,omitempty"`
	Name      string         `gorm:"type:varchar(255);not null" json:"name"`
	Layout    string         `gorm:"type:text;not null" json:"layout"`
	HostIDs   string         `gorm:"type:text" json:"hostIds,omitempty"`
	CreatedAt time.Time      `json:"createdAt"`
	UpdatedAt time.Time      `json:"updatedAt"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`
}

func (w *Workspace) BeforeCreate(tx *gorm.DB) error {
	if w.ID == "" {
		w.ID = uuid.New().String()
	}
	return nil
}

type TabGroup struct {
	ID        string         `gorm:"type:uuid;primaryKey" json:"id"`
	UserID    string         `gorm:"type:uuid;index" json:"userId"`
	VaultID   *string        `gorm:"type:uuid;index" json:"vaultId,omitempty"`
	Name      string         `gorm:"type:varchar(255);not null" json:"name"`
	Layout    string         `gorm:"type:text;not null" json:"layout"`
	CreatedAt time.Time      `json:"createdAt"`
	UpdatedAt time.Time      `json:"updatedAt"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`
}

func (t *TabGroup) BeforeCreate(tx *gorm.DB) error {
	if t.ID == "" {
		t.ID = uuid.New().String()
	}
	return nil
}

type Settings struct {
	ID          string    `gorm:"type:uuid;primaryKey" json:"id"`
	UserID      string    `gorm:"type:uuid;uniqueIndex;not null" json:"userId"`
	Theme       string    `gorm:"type:varchar(50);default:'dark'" json:"theme"`
	FontFamily  string    `gorm:"type:varchar(100);default:'JetBrains Mono'" json:"fontFamily"`
	FontSize    int       `gorm:"default:14" json:"fontSize"`
	CursorStyle string    `gorm:"type:varchar(20);default:'block'" json:"cursorStyle"`
	Keybindings string    `gorm:"type:text" json:"keybindings,omitempty"`
	CreatedAt   time.Time `json:"createdAt"`
	UpdatedAt   time.Time `json:"updatedAt"`
}

func (s *Settings) BeforeCreate(tx *gorm.DB) error {
	if s.ID == "" {
		s.ID = uuid.New().String()
	}
	return nil
}

type SyncState struct {
	ID         string    `gorm:"type:uuid;primaryKey" json:"id"`
	UserID     string    `gorm:"type:uuid;index;not null" json:"userId"`
	DeviceID   string    `gorm:"type:varchar(255);not null" json:"deviceId"`
	LastSyncAt time.Time `json:"lastSyncAt"`
	CreatedAt  time.Time `json:"createdAt"`
	UpdatedAt  time.Time `json:"updatedAt"`
}

func (s *SyncState) BeforeCreate(tx *gorm.DB) error {
	if s.ID == "" {
		s.ID = uuid.New().String()
	}
	return nil
}

type SyncTracking struct {
	TableName string    `gorm:"type:varchar(100);primaryKey" json:"tableName"`
	RecordID  string    `gorm:"type:varchar(255);primaryKey" json:"recordId"`
	UserID    string    `gorm:"type:uuid;index;not null" json:"userId"`
	UpdatedAt time.Time `json:"updatedAt"`
	DeviceID  string    `gorm:"type:varchar(255);not null" json:"deviceId"`
	IsDeleted bool      `gorm:"default:false" json:"isDeleted"`
}
