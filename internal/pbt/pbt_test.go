// SPDX-License-Identifier: AGPL-3.0-or-later OR Commercial
// Copyright (c) 2026 Vincent Palmer

// Package pbt_test contains property-based tests for transparenz-go using
// pgregory.net/rapid. The tests verify invariants across randomly generated
// inputs without requiring external services.
package pbt_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/glebarez/sqlite"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"pgregory.net/rapid"

	"github.com/vincents-ai/transparenz/cmd"
)

// ─── Suite 1: BSI score always in [0.0, 1.0] ────────────────────────────────

// TestBSIScoreAlwaysInRange verifies that RunBSICheck returns a score in [0.0, 1.0]
// regardless of the component counts in the SBOM. It generates synthetic CycloneDX
// SBOMs with random numbers of components that have varying coverage of hash,
// license, and supplier fields.
func TestBSIScoreAlwaysInRange(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		// Generate random number of components (0-100 for test speed)
		numComponents := rapid.IntRange(0, 100).Draw(rt, "numComponents")

		components := make([]interface{}, 0, numComponents)
		for i := 0; i < numComponents; i++ {
			hasHash := rapid.Bool().Draw(rt, fmt.Sprintf("hasHash_%d", i))
			hasLicense := rapid.Bool().Draw(rt, fmt.Sprintf("hasLicense_%d", i))
			hasSupplier := rapid.Bool().Draw(rt, fmt.Sprintf("hasSupplier_%d", i))
			hasProps := rapid.Bool().Draw(rt, fmt.Sprintf("hasProps_%d", i))

			comp := map[string]interface{}{
				"type":    "library",
				"name":    fmt.Sprintf("component-%d", i),
				"version": "1.0.0",
				"purl":    fmt.Sprintf("pkg:golang/example.com/comp-%d@v1.0.0", i),
			}

			if hasHash {
				comp["hashes"] = []interface{}{
					map[string]interface{}{
						"alg":     "SHA-512",
						"content": "a3b4c5d6e7f8a3b4c5d6e7f8a3b4c5d6e7f8a3b4c5d6e7f8a3b4c5d6e7f8a3b4c5d6e7f8a3b4c5d6e7f8a3b4c5d6e7f8a3b4c5d6e7f8a3b4c5d6e7f8",
					},
				}
			}

			if hasLicense {
				comp["licenses"] = []interface{}{
					map[string]interface{}{
						"license": map[string]interface{}{"id": "MIT"},
					},
				}
			}

			if hasSupplier {
				comp["supplier"] = map[string]interface{}{"name": "Example Corp"}
			}

			if hasProps {
				comp["properties"] = []interface{}{
					map[string]interface{}{"name": "executable", "value": "false"},
					map[string]interface{}{"name": "archive", "value": "false"},
					map[string]interface{}{"name": "structured", "value": "true"},
				}
			}

			components = append(components, comp)
		}

		sbomData := map[string]interface{}{
			"bomFormat":   "CycloneDX",
			"specVersion": "1.6",
			"version":     1,
			"metadata": map[string]interface{}{
				"component": map[string]interface{}{
					"type":    "application",
					"name":    "test-app",
					"version": "1.0.0",
				},
				"properties": []interface{}{
					map[string]interface{}{"name": "completeness", "value": "complete"},
					map[string]interface{}{"name": "completeness:scope", "value": "transitive"},
				},
			},
			"components": components,
		}

		sbomJSON, err := json.Marshal(sbomData)
		if err != nil {
			rt.Fatalf("failed to marshal test SBOM: %v", err)
		}

		_, score, err := cmd.RunBSICheck(string(sbomJSON))
		if err != nil {
			rt.Fatalf("RunBSICheck failed unexpectedly: %v", err)
		}

		// Core invariant: score must always be in [0.0, 1.0]
		if score < 0.0 || score > 1.0 {
			rt.Fatalf("BSI score %.6f is outside [0.0, 1.0] range for %d components", score, numComponents)
		}
	})
}

// ─── Suite 2: SBOM repository CRUD state machine ────────────────────────────

// pbtSBOM is a SQLite-compatible SBOM model without the PostgreSQL-specific
// check constraint (check:format IN ('SPDX', 'CycloneDX')) that SQLite cannot
// parse. It mirrors the fields needed for CRUD state machine testing.
type pbtSBOM struct {
	ID                string `gorm:"primaryKey"`
	Name              string
	Version           string
	Format            string
	FormatVersion     string
	DocumentNamespace string `gorm:"uniqueIndex"`
	SBOMJson          string // stored as text in SQLite instead of JSONB
}

func (pbtSBOM) TableName() string { return "sboms" }

// setupPBTDB creates a throw-away SQLite DB with a SQLite-compatible sboms table.
// The models.SBOM GORM model cannot be used with SQLite because it carries a
// PostgreSQL-specific CHECK constraint. We define pbtSBOM above as a
// constraint-free mirror suitable for property-based testing.
func setupPBTDB(t *testing.T) *gorm.DB {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "pbt_test.db")
	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatalf("setupPBTDB: failed to open SQLite: %v", err)
	}
	if err := db.AutoMigrate(&pbtSBOM{}); err != nil {
		t.Fatalf("setupPBTDB: failed to migrate: %v", err)
	}
	t.Cleanup(func() {
		sqlDB, _ := db.DB()
		if sqlDB != nil {
			_ = sqlDB.Close()
		}
		_ = os.Remove(dbPath)
	})
	return db
}

// TestSBOMRepositoryCRUDStateMachine verifies that creating and deleting SBOMs
// keeps an in-memory counter consistent with the database row count.
// Uses a SQLite-compatible schema mirror (pbtSBOM) instead of models.SBOM to
// avoid the PostgreSQL CHECK constraint that SQLite cannot parse.
func TestSBOMRepositoryCRUDStateMachine(t *testing.T) {
	db := setupPBTDB(t)

	rapid.Check(t, func(rt *rapid.T) {
		// Clean state at the start of each trial.
		db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&pbtSBOM{})

		expectedCount := 0
		var liveIDs []string

		numOps := rapid.IntRange(1, 20).Draw(rt, "numOps")

		for i := 0; i < numOps; i++ {
			createOp := len(liveIDs) == 0 || rapid.Bool().Draw(rt, fmt.Sprintf("createOp_%d", i))

			if createOp {
				id := uuid.New().String()
				ns := "https://pbt.test/sbom/" + id
				sbomData, _ := json.Marshal(map[string]interface{}{
					"spdxVersion":       "SPDX-2.3",
					"name":              fmt.Sprintf("pbt-sbom-%d", i),
					"documentNamespace": ns,
				})
				row := pbtSBOM{
					ID:                id,
					Name:              fmt.Sprintf("pbt-sbom-%d", i),
					Version:           "1.0.0",
					Format:            "SPDX",
					FormatVersion:     "2.3",
					DocumentNamespace: ns,
					SBOMJson:          string(sbomData),
				}
				if err := db.Create(&row).Error; err != nil {
					rt.Fatalf("db.Create failed: %v", err)
				}
				liveIDs = append(liveIDs, id)
				expectedCount++
			} else {
				idx := rapid.IntRange(0, len(liveIDs)-1).Draw(rt, fmt.Sprintf("deleteIdx_%d", i))
				targetID := liveIDs[idx]

				result := db.Delete(&pbtSBOM{}, "id = ?", targetID)
				if result.Error != nil {
					rt.Fatalf("db.Delete failed: %v", result.Error)
				}

				liveIDs = append(liveIDs[:idx], liveIDs[idx+1:]...)
				expectedCount--
			}

			var actualCount int64
			if err := db.Model(&pbtSBOM{}).Count(&actualCount).Error; err != nil {
				rt.Fatalf("count query failed: %v", err)
			}

			if int(actualCount) != expectedCount {
				rt.Fatalf("count mismatch after op %d: expected %d, got %d", i, expectedCount, actualCount)
			}
		}
	})
}

// ─── Suite 3: No panic on malformed SBOM input ──────────────────────────────

// TestNoPanicOnMalformedSBOM verifies that RunBSICheck never panics regardless
// of the input string. Panics in validation code would crash the server process.
// The property uses a character set that produces realistic-looking but malformed
// JSON to stress-test the parsing and validation paths.
func TestNoPanicOnMalformedSBOM(t *testing.T) {
	malformedRunes := []rune(`{}[]":,abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 .-_/\@#`)

	rapid.Check(t, func(rt *rapid.T) {
		input := rapid.StringOf(rapid.RuneFrom(malformedRunes)).Draw(rt, "sbomInput")

		panicked := false
		func() {
			defer func() {
				if r := recover(); r != nil {
					panicked = true
				}
			}()
			// We intentionally discard the return values; we only care about panics.
			_, _, _ = cmd.RunBSICheck(input)
		}()

		if panicked {
			rt.Fatalf("RunBSICheck panicked on input: %q", input)
		}
	})
}
