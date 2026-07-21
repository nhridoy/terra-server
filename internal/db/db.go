package db

import (
	"fmt"
	"log/slog"
	"strings"

	"github.com/glebarez/sqlite"
	"github.com/termvault/termvault/internal/config"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var DB *gorm.DB

func Init() error {
	cfg := config.AppConfig
	dsn := cfg.DBUrl

	var dialector gorm.Dialector

	switch {
	case strings.HasPrefix(dsn, "sqlite"):
		path := strings.TrimPrefix(dsn, "sqlite://")
		path = strings.TrimPrefix(path, "sqlite:")
		dialector = sqlite.Open(path + "?_journal_mode=WAL&_busy_timeout=5000&_synchronous=NORMAL&_foreign_keys=ON")
	case strings.HasPrefix(dsn, "postgres") || strings.HasPrefix(dsn, "postgresql"):
		dialector = postgres.Open(dsn)
	case strings.HasPrefix(dsn, "mysql"):
		dialector = mysql.Open(dsn)
	default:
		return fmt.Errorf("unsupported database driver for: %s", dsn)
	}

	var err error
	DB, err = gorm.Open(dialector, &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}

	err = DB.AutoMigrate(
		&User{},
		&Vault{},
		&Host{},
		&Group{},
		&Keychain{},
		&Snippet{},
		&Workspace{},
		&TabGroup{},
		&Settings{},
		&RefreshToken{},
		&Team{},
		&TeamMember{},
		&SharedVault{},
	)
	if err != nil {
		return fmt.Errorf("failed to migrate database: %w", err)
	}

	if err := createIndexes(); err != nil {
		return fmt.Errorf("failed to create indexes: %w", err)
	}

	slog.Info("Database initialized successfully")
	return nil
}

func createIndexes() error {
	type indexDef struct {
		table string
	 cols  string
	}

	indexes := []indexDef{
		{"hosts", "user_id, vault_id"},
		{"hosts", "user_id, group_id"},
		{"groups", "user_id, vault_id"},
		{"groups", "user_id, parent_id"},
		{"keychain", "user_id, vault_id"},
		{"snippets", "user_id, vault_id"},
		{"workspaces", "user_id, vault_id"},
		{"tab_groups", "user_id, vault_id"},
		{"team_members", "team_id, user_id"},
		{"team_members", "user_id"},
		{"shared_vaults", "team_id"},
		{"shared_vaults", "vault_id"},
		{"refresh_tokens", "user_id"},
		{"refresh_tokens", "expires_at"},
	}

	for _, idx := range indexes {
		idxName := fmt.Sprintf("idx_%s_%s", idx.table, strings.ReplaceAll(idx.cols, ", ", "_"))
		sql := fmt.Sprintf("CREATE INDEX IF NOT EXISTS %s ON %s (%s)", idxName, idx.table, idx.cols)
		if err := DB.Exec(sql).Error; err != nil {
			slog.Warn("Failed to create index", "index", idxName, "error", err)
		}
	}

	return nil
}

func GetDB() *gorm.DB {
	return DB
}

func InTransaction(fn func(tx *gorm.DB) error) error {
	return DB.Transaction(fn)
}
