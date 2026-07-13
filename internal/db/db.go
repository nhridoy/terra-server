package db

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/glebarez/sqlite"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var DB *gorm.DB

func Init() error {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		dsn = "termvault.db"
	}

	var dialector gorm.Dialector

	switch {
	case strings.HasPrefix(dsn, "sqlite"):
		dbPath := strings.TrimPrefix(dsn, "sqlite://")
		dbPath = strings.TrimPrefix(dbPath, "file:")
		if idx := strings.Index(dbPath, "?"); idx != -1 {
			dbPath = dbPath[:idx]
		}
		if dbPath == "" {
			dbPath = "termvault.db"
		}
		dialector = sqlite.Open(dbPath)
		log.Printf("Using SQLite database: %s", dbPath)

	case strings.HasPrefix(dsn, "postgres"):
		dialector = postgres.Open(dsn)
		log.Println("Using PostgreSQL database")

	case strings.HasPrefix(dsn, "mysql"):
		dialector = mysql.Open(dsn)
		log.Println("Using MySQL database")

	default:
		dialector = sqlite.Open("termvault.db")
		log.Println("Using default SQLite database")
	}

	var err error
	DB, err = gorm.Open(dialector, &gorm.Config{
		Logger: logger.Default.LogMode(logger.Info),
	})
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}

	if err := Migrate(); err != nil {
		return fmt.Errorf("failed to run migrations: %w", err)
	}

	log.Println("Database initialized successfully")
	return nil
}

func Migrate() error {
	return DB.AutoMigrate(
		&User{},
		&OAuthConnection{},
		&Team{},
		&TeamMember{},
		&Host{},
		&Group{},
		&Vault{},
		&Keychain{},
		&Snippet{},
		&SessionLog{},
		&Workspace{},
		&TabGroup{},
		&Settings{},
	)
}

func GetDB() *gorm.DB {
	return DB
}
