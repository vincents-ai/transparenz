// SPDX-License-Identifier: AGPL-3.0-or-later OR Commercial
// Copyright (c) 2026 Vincent Palmer

// Package testutil provides shared test helpers for transparenz-go tests.
// It mirrors the testing infrastructure from transparenz-server to keep
// the two codebases aligned.
package testutil

import (
	"context"
	"fmt"
	"os"
	"sync"
	"testing"

	"github.com/google/uuid"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	gormpostgres "gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/shift/transparenz/internal/models"
)

// ─── PostgreSQL singleton ────────────────────────────────────────────────────

var (
	pgOnce      sync.Once
	pgDB        *gorm.DB
	pgContainer *tcpostgres.PostgresContainer
)

// TestDB returns a shared *gorm.DB backed by a real PostgreSQL container.
// The container is started exactly once per test binary run (sync.Once) so
// multiple tests share the same database instance rather than each paying the
// ~3 s Docker start-up cost.
//
// The database is auto-migrated with all production models on first use.
//
// Call this only from integration tests. Short or unit tests should use
// SetupTestDB instead.
func TestDB(t *testing.T) *gorm.DB {
	t.Helper()

	if os.Getenv("INTEGRATION_TEST") != "true" {
		t.Skip("Skipping integration test. Set INTEGRATION_TEST=true to run.")
	}

	pgOnce.Do(func() {
		ctx := context.Background()

		container, err := tcpostgres.Run(ctx,
			"postgres:16-alpine",
			tcpostgres.WithDatabase("transparenz_test"),
			tcpostgres.WithUsername("test"),
			tcpostgres.WithPassword("test"),
		)
		if err != nil {
			panic(fmt.Sprintf("testutil.TestDB: failed to start PostgreSQL container: %v", err))
		}
		pgContainer = container

		connStr, err := container.ConnectionString(ctx, "sslmode=disable")
		if err != nil {
			panic(fmt.Sprintf("testutil.TestDB: failed to get connection string: %v", err))
		}

		db, err := gorm.Open(gormpostgres.Open(connStr), &gorm.Config{
			Logger: logger.Default.LogMode(logger.Silent),
		})
		if err != nil {
			panic(fmt.Sprintf("testutil.TestDB: failed to open GORM connection: %v", err))
		}

		if err := db.AutoMigrate(
			&models.SBOM{},
			&models.Package{},
			&models.Scan{},
			&models.Vulnerability{},
			&models.PackageHash{},
		); err != nil {
			panic(fmt.Sprintf("testutil.TestDB: failed to migrate: %v", err))
		}

		pgDB = db
	})

	return pgDB
}

// ─── In-memory SQLite ────────────────────────────────────────────────────────

// SetupTestDB creates a throw-away in-memory SQLite database and auto-migrates
// the provided model types. Suitable for property-based testing loops and unit
// tests that need a real database without Docker overhead.
//
// Example:
//
//	db := testutil.SetupTestDB(t, &models.SBOM{}, &models.Package{})
func SetupTestDB(t *testing.T, models ...interface{}) *gorm.DB {
	t.Helper()

	// glebarez/sqlite provides a pure-Go SQLite driver (no CGO required).
	// We use a unique file per test using t.TempDir() so parallel tests
	// never share state.
	dbPath := fmt.Sprintf("%s/test.db", t.TempDir())

	db, err := gorm.Open(sqliteOpen(dbPath), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatalf("testutil.SetupTestDB: failed to open SQLite: %v", err)
	}

	if len(models) > 0 {
		if err := db.AutoMigrate(models...); err != nil {
			t.Fatalf("testutil.SetupTestDB: failed to migrate: %v", err)
		}
	}

	t.Cleanup(func() {
		sqlDB, _ := db.DB()
		if sqlDB != nil {
			_ = sqlDB.Close()
		}
	})

	return db
}

// ─── Test factory helpers ────────────────────────────────────────────────────

// CreateTestSBOM inserts a minimal SPDX SBOM into db and returns its UUID.
// It is useful for setting up test fixtures without repeating boilerplate.
func CreateTestSBOM(t *testing.T, db *gorm.DB) uuid.UUID {
	t.Helper()

	id := uuid.New()
	ns := "https://example.com/test-sbom/" + id.String()
	sbom := models.SBOM{
		ID:                id,
		Name:              "test-project",
		Version:           "1.0.0",
		Format:            "SPDX",
		FormatVersion:     "SPDX-2.3",
		DocumentNamespace: ns,
		SBOMJson: models.JSONB{
			"spdxVersion":       "SPDX-2.3",
			"name":              "test-project",
			"documentNamespace": ns,
		},
	}

	if err := db.Create(&sbom).Error; err != nil {
		t.Fatalf("testutil.CreateTestSBOM: failed to create SBOM: %v", err)
	}

	return id
}
