package database

import (
	"fmt"
	"os"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/deutschland-stack/transparenz/internal/models"
)

// Connect establishes a connection to the PostgreSQL database using GORM
//
// SECURITY & COMPLIANCE:
// - Requires DATABASE_URL environment variable (no fallback for production safety)
// - Does NOT run AutoMigrate (use explicit Migrate() function instead)
// - Follows BSI TR-03183-2 deterministic deployment requirements
func Connect() (*gorm.DB, error) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		return nil, fmt.Errorf("DATABASE_URL environment variable is required (no default DSN for security)")
	}

	// Configure GORM with logger
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	// Get underlying SQL DB to test connection and configure pool
	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("failed to get database instance: %w", err)
	}

	// Test connection
	if err := sqlDB.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	// Configure connection pool
	sqlDB.SetMaxIdleConns(10)
	sqlDB.SetMaxOpenConns(100)

	return db, nil
}

// Migrate runs database migrations explicitly
//
// IMPORTANT: This function must be called explicitly via CLI command or deployment script.
// It is NOT called automatically on Connect() to ensure:
//  1. Deterministic deployments (EU CRA requirement)
//  2. Migration control and rollback capability
//  3. Production safety (migrations don't run on every connection)
//
// Usage: Call this from a dedicated "db migrate" CLI command
func Migrate(db *gorm.DB) error {
	return db.AutoMigrate(
		&models.SBOM{},
		&models.Package{},
		&models.PackageHash{},
		&models.Vulnerability{},
		&models.PackageVulnerability{},
		&models.Scan{},
	)
}

// Close closes the database connection
func Close(db *gorm.DB) error {
	sqlDB, err := db.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}
