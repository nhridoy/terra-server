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
	AvatarURL     string         `gorm:"type:text" json:"avatar_url,omitempty"`
	SrpSalt       string         `gorm:"type:varchar(255)" json:"-"`
	SrpVerifier   string         `gorm:"type:varchar(255)" json:"-"`
	PublicKey     string         `gorm:"type:text" json:"public_key,omitempty"`
	EncryptedPK   string         `gorm:"type:text" json:"encrypted_personal_key,omitempty"`
	EncryptedPriv string         `gorm:"type:text" json:"encrypted_private_key,omitempty"`
	KeyNonce      string         `gorm:"type:varchar(255)" json:"nonce,omitempty"`
	KeySalt       string         `gorm:"type:varchar(255)" json:"salt,omitempty"`
	CreatedAt     time.Time      `json:"created_at"`
	UpdatedAt     time.Time      `json:"updated_at"`
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
	UserID         string    `gorm:"type:uuid;index;not null" json:"user_id"`
	Provider       string    `gorm:"type:varchar(50);not null" json:"provider"`
	ProviderUserID string    `gorm:"type:varchar(255);not null" json:"provider_user_id"`
	AccessToken    string    `gorm:"type:text" json:"-"`
	RefreshToken   string    `gorm:"type:text" json:"-"`
	CreatedAt      time.Time `json:"created_at"`
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
	OwnerID   string    `gorm:"type:uuid;index;not null" json:"owner_id"`
	CreatedAt time.Time `json:"created_at"`
}

func (t *Team) BeforeCreate(tx *gorm.DB) error {
	if t.ID == "" {
		t.ID = uuid.New().String()
	}
	return nil
}

type TeamMember struct {
	ID        string    `gorm:"type:uuid;primaryKey" json:"id"`
	TeamID    string    `gorm:"type:uuid;index;not null" json:"team_id"`
	UserID    string    `gorm:"type:uuid;index;not null" json:"user_id"`
	Role      string    `gorm:"type:varchar(20);default:'member'" json:"role"`
	PublicKey string    `gorm:"type:text" json:"public_key,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

func (tm *TeamMember) BeforeCreate(tx *gorm.DB) error {
	if tm.ID == "" {
		tm.ID = uuid.New().String()
	}
	return nil
}

type Host struct {
	ID              string         `gorm:"type:uuid;primaryKey" json:"id"`
	UserID          string         `gorm:"type:uuid;index" json:"user_id"`
	VaultID         *string        `gorm:"type:uuid;index" json:"vault_id,omitempty"`
	TeamID          *string        `gorm:"type:uuid;index" json:"team_id,omitempty"`
	GroupID         *string        `gorm:"type:uuid;index" json:"group_id,omitempty"`
	Name            string         `gorm:"type:varchar(255);not null" json:"name"`
	Hostname        string         `gorm:"type:varchar(255);not null" json:"hostname"`
	Address         string         `gorm:"type:varchar(255)" json:"address,omitempty"`
	Port            int            `gorm:"default:22" json:"port"`
	Username        string         `gorm:"type:varchar(100)" json:"username,omitempty"`
	Password        string         `gorm:"type:text" json:"password,omitempty"`
	PrivateKey      string         `gorm:"type:text" json:"private_key,omitempty"`
	Passphrase      string         `gorm:"type:text" json:"passphrase,omitempty"`
	AuthMethod      string         `gorm:"type:varchar(20);default:'password'" json:"auth_method"`
	Tags            string         `gorm:"type:text" json:"tags,omitempty"`
	Color           string         `gorm:"type:varchar(7)" json:"color,omitempty"`
	Icon            string         `gorm:"type:varchar(50)" json:"icon,omitempty"`
	SortOrder       int            `gorm:"default:0" json:"sort_order"`
	LastConnected   *time.Time     `json:"last_connected,omitempty"`
	ConnectionCount int            `gorm:"default:0" json:"connection_count"`
	CreatedAt       time.Time      `json:"created_at"`
	UpdatedAt       time.Time      `json:"updated_at"`
	DeletedAt       gorm.DeletedAt `gorm:"index" json:"-"`
}

func (h *Host) BeforeCreate(tx *gorm.DB) error {
	if h.ID == "" {
		h.ID = uuid.New().String()
	}
	return nil
}

type Group struct {
	ID        string         `gorm:"type:uuid;primaryKey" json:"id"`
	UserID    string         `gorm:"type:uuid;index" json:"user_id"`
	VaultID   *string        `gorm:"type:uuid;index" json:"vault_id,omitempty"`
	TeamID    *string        `gorm:"type:uuid;index" json:"team_id,omitempty"`
	ParentID  *string        `gorm:"type:uuid;index" json:"parent_id,omitempty"`
	Name      string         `gorm:"type:varchar(255);not null" json:"name"`
	SortOrder int            `gorm:"default:0" json:"sort_order"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`
}

func (g *Group) BeforeCreate(tx *gorm.DB) error {
	if g.ID == "" {
		g.ID = uuid.New().String()
	}
	return nil
}

type Vault struct {
	ID            string         `gorm:"type:uuid;primaryKey" json:"id"`
	UserID        string         `gorm:"type:uuid;index;not null;uniqueIndex:idx_user_vault_name" json:"user_id"`
	Name          string         `gorm:"type:varchar(255);not null;uniqueIndex:idx_user_vault_name" json:"name"`
	Description   string         `gorm:"type:text" json:"description,omitempty"`
	IsDefault     bool           `gorm:"default:false" json:"is_default"`
	IsSystem      bool           `gorm:"default:false" json:"is_system"`
	EncryptedData string         `gorm:"type:text;not null" json:"encrypted_data"`
	IV            string         `gorm:"type:text;not null" json:"iv"`
	Salt          string         `gorm:"type:text;not null" json:"salt"`
	CreatedAt     time.Time      `json:"created_at"`
	UpdatedAt     time.Time      `json:"updated_at"`
	DeletedAt     gorm.DeletedAt `gorm:"index" json:"-"`
}

func (v *Vault) BeforeCreate(tx *gorm.DB) error {
	if v.ID == "" {
		v.ID = uuid.New().String()
	}
	return nil
}

type Keychain struct {
	ID               string         `gorm:"type:uuid;primaryKey" json:"id"`
	UserID           string         `gorm:"type:uuid;index" json:"user_id"`
	VaultID          *string        `gorm:"type:uuid;index" json:"vault_id,omitempty"`
	TeamID           *string        `gorm:"type:uuid;index" json:"team_id,omitempty"`
	Name             string         `gorm:"type:varchar(255);not null" json:"name"`
	Description      string         `gorm:"type:text" json:"description,omitempty"`
	KeyType          string         `gorm:"type:varchar(20);not null" json:"key_type"`
	PublicKey        string         `gorm:"type:text;not null" json:"public_key"`
	EncryptedPrivKey string         `gorm:"type:text" json:"encrypted_private_key,omitempty"`
	Fingerprint      string         `gorm:"type:varchar(100)" json:"fingerprint,omitempty"`
	CreatedAt        time.Time      `json:"created_at"`
	UpdatedAt        time.Time      `json:"updated_at"`
	DeletedAt        gorm.DeletedAt `gorm:"index" json:"-"`
}

func (k *Keychain) BeforeCreate(tx *gorm.DB) error {
	if k.ID == "" {
		k.ID = uuid.New().String()
	}
	return nil
}

type Snippet struct {
	ID          string         `gorm:"type:uuid;primaryKey" json:"id"`
	UserID      string         `gorm:"type:uuid;index" json:"user_id"`
	VaultID     *string        `gorm:"type:uuid;index" json:"vault_id,omitempty"`
	Name        string         `gorm:"type:varchar(255);not null" json:"name"`
	Command     string         `gorm:"type:text;not null" json:"command"`
	Description string         `gorm:"type:text" json:"description,omitempty"`
	Tags        string         `gorm:"type:text" json:"tags,omitempty"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
	DeletedAt   gorm.DeletedAt `gorm:"index" json:"-"`
}

func (s *Snippet) BeforeCreate(tx *gorm.DB) error {
	if s.ID == "" {
		s.ID = uuid.New().String()
	}
	return nil
}

type SessionLog struct {
	ID        string     `gorm:"type:uuid;primaryKey" json:"id"`
	UserID    string     `gorm:"type:uuid;index" json:"user_id"`
	VaultID   *string    `gorm:"type:uuid;index" json:"vault_id,omitempty"`
	HostID    string     `gorm:"type:uuid;index" json:"host_id"`
	StartedAt time.Time  `json:"started_at"`
	EndedAt   *time.Time `json:"ended_at,omitempty"`
	Data      string     `gorm:"type:text" json:"data,omitempty"`
	SizeBytes int64      `json:"size_bytes,omitempty"`
}

func (s *SessionLog) BeforeCreate(tx *gorm.DB) error {
	if s.ID == "" {
		s.ID = uuid.New().String()
	}
	return nil
}

type Workspace struct {
	ID        string         `gorm:"type:uuid;primaryKey" json:"id"`
	UserID    string         `gorm:"type:uuid;index" json:"user_id"`
	VaultID   *string        `gorm:"type:uuid;index" json:"vault_id,omitempty"`
	Name      string         `gorm:"type:varchar(255);not null" json:"name"`
	Layout    string         `gorm:"type:text;not null" json:"layout"`
	HostIDs   string         `gorm:"type:text" json:"host_ids,omitempty"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
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
	UserID    string         `gorm:"type:uuid;index" json:"user_id"`
	VaultID   *string        `gorm:"type:uuid;index" json:"vault_id,omitempty"`
	Name      string         `gorm:"type:varchar(255);not null" json:"name"`
	Layout    string         `gorm:"type:text;not null" json:"layout"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
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
	UserID      string    `gorm:"type:uuid;uniqueIndex;not null" json:"user_id"`
	Theme       string    `gorm:"type:varchar(50);default:'dark'" json:"theme"`
	FontFamily  string    `gorm:"type:varchar(100);default:'JetBrains Mono'" json:"font_family"`
	FontSize    int       `gorm:"default:14" json:"font_size"`
	CursorStyle string    `gorm:"type:varchar(20);default:'block'" json:"cursor_style"`
	Keybindings string    `gorm:"type:text" json:"keybindings,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

func (s *Settings) BeforeCreate(tx *gorm.DB) error {
	if s.ID == "" {
		s.ID = uuid.New().String()
	}
	return nil
}

type SyncState struct {
	ID         string    `gorm:"type:uuid;primaryKey" json:"id"`
	UserID     string    `gorm:"type:uuid;index;not null" json:"user_id"`
	DeviceID   string    `gorm:"type:varchar(255);not null" json:"device_id"`
	LastSyncAt time.Time `json:"last_sync_at"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

func (s *SyncState) BeforeCreate(tx *gorm.DB) error {
	if s.ID == "" {
		s.ID = uuid.New().String()
	}
	return nil
}

type SyncTracking struct {
	TableName string    `gorm:"type:varchar(100);primaryKey" json:"table_name"`
	RecordID  string    `gorm:"type:varchar(255);primaryKey" json:"record_id"`
	UserID    string    `gorm:"type:uuid;index;not null" json:"user_id"`
	UpdatedAt time.Time `json:"updated_at"`
	DeviceID  string    `gorm:"type:varchar(255);not null" json:"device_id"`
	IsDeleted bool      `gorm:"default:false" json:"is_deleted"`
}
