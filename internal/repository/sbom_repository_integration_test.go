// SPDX-License-Identifier: AGPL-3.0-or-later OR Commercial
// Copyright (c) 2026 Vincent Palmer

package repository

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vincents-ai/transparenz/internal/testutil"
)

// helpers ─────────────────────────────────────────────────────────────────────

// minimalSPDX returns a well-formed SPDX 2.3 JSON string with the given name
// and a unique documentNamespace derived from the run UUID.
func minimalSPDX(name, ns string) string {
	return fmt.Sprintf(`{
		"spdxVersion": "SPDX-2.3",
		"dataLicense": "CC0-1.0",
		"SPDXID": "SPDXRef-DOCUMENT",
		"name": %q,
		"documentNamespace": %q,
		"documentDescribes": ["SPDXRef-Package"],
		"creationInfo": {"created": "2026-01-01T00:00:00Z", "creators": ["Tool: test"]},
		"packages": []
	}`, name, ns)
}

// minimalSPDXWithPackage is like minimalSPDX but includes one package entry.
func minimalSPDXWithPackage(name, ns string) string {
	return fmt.Sprintf(`{
		"spdxVersion": "SPDX-2.3",
		"dataLicense": "CC0-1.0",
		"SPDXID": "SPDXRef-DOCUMENT",
		"name": %q,
		"documentNamespace": %q,
		"documentDescribes": ["SPDXRef-Package"],
		"creationInfo": {"created": "2026-01-01T00:00:00Z", "creators": ["Tool: test"]},
		"packages": [
			{
				"SPDXID": "SPDXRef-Package",
				"name": "test-package",
				"versionInfo": "1.0.0",
				"downloadLocation": "https://example.com/package",
				"licenseConcluded": "MIT",
				"supplier": "Test Supplier",
				"description": "A test package",
				"externalRefs": [
					{
						"referenceCategory": "PACKAGE-MANAGER",
						"referenceType": "purl",
						"referenceLocator": "pkg:npm/test-package@1.0.0"
					}
				]
			}
		]
	}`, name, ns)
}

// ns creates a unique, test-scoped documentNamespace.
func ns(prefix string) string {
	return fmt.Sprintf("https://example.com/%s/%s", prefix, uuid.New().String())
}

// ─── Tests ────────────────────────────────────────────────────────────────────

func TestSaveSBOM_WithRealPostgreSQL(t *testing.T) {
	db := testutil.TestDB(t)
	ctx := context.Background()
	repo := NewSBOMRepository(db)

	sbomJSON := minimalSPDXWithPackage("test-project", ns("save-test"))

	sbomID, err := repo.SaveSBOM(ctx, sbomJSON, "/test/path")
	require.NoError(t, err)
	assert.NotEqual(t, uuid.Nil, sbomID)

	// Verify via a fresh Get so we exercise the full round-trip.
	found, err := repo.GetSBOM(ctx, sbomID)
	require.NoError(t, err)
	assert.Equal(t, "test-project", found.Name)
	assert.Equal(t, "SPDX", found.Format)

	// Verify associated package was persisted.
	require.NotEmpty(t, found.Packages, "expected packages to be preloaded")
	assert.Equal(t, "test-package", found.Packages[0].Name)
}

func TestGetSBOM_WithRealPostgreSQL(t *testing.T) {
	db := testutil.TestDB(t)
	ctx := context.Background()
	repo := NewSBOMRepository(db)

	sbomJSON := minimalSPDX("get-test-project", ns("get-test"))
	sbomID, err := repo.SaveSBOM(ctx, sbomJSON, "/test/path")
	require.NoError(t, err)

	found, err := repo.GetSBOM(ctx, sbomID)
	require.NoError(t, err)
	assert.Equal(t, "get-test-project", found.Name)
	assert.Equal(t, "SPDX", found.Format)
}

func TestGetSBOM_NotFound_WithRealPostgreSQL(t *testing.T) {
	db := testutil.TestDB(t)
	ctx := context.Background()
	repo := NewSBOMRepository(db)

	_, err := repo.GetSBOM(ctx, uuid.New())
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrSBOMNotFound)
}

func TestListSBOMs_WithRealPostgreSQL(t *testing.T) {
	db := testutil.TestDB(t)
	ctx := context.Background()
	repo := NewSBOMRepository(db)

	// Insert 5 SBOMs with unique namespaces so we can filter precisely.
	prefix := "list-test-" + uuid.New().String()
	var insertedIDs []uuid.UUID
	for i := 0; i < 5; i++ {
		name := fmt.Sprintf("list-project-%d", i)
		sbomJSON := minimalSPDX(name, fmt.Sprintf("https://example.com/%s-%d", prefix, i))
		id, err := repo.SaveSBOM(ctx, sbomJSON, "/test/path")
		require.NoError(t, err)
		insertedIDs = append(insertedIDs, id)
	}

	// Collect all SBOMs; look for our 5 specifically to avoid interference
	// from rows inserted by other tests sharing the same container.
	all, err := repo.ListSBOMs(ctx, 1000, 0)
	require.NoError(t, err)

	found := 0
	for _, s := range all {
		for _, id := range insertedIDs {
			if s.ID == id {
				found++
			}
		}
	}
	assert.Equal(t, 5, found, "expected exactly 5 inserted SBOMs to appear in list")

	// Pagination still works relative to the full set.
	page, err := repo.ListSBOMs(ctx, 2, 0)
	require.NoError(t, err)
	assert.LessOrEqual(t, len(page), 2)
}

func TestDeleteSBOM_WithRealPostgreSQL(t *testing.T) {
	db := testutil.TestDB(t)
	ctx := context.Background()
	repo := NewSBOMRepository(db)

	sbomJSON := minimalSPDX("delete-test-project", ns("delete-test"))
	sbomID, err := repo.SaveSBOM(ctx, sbomJSON, "/test/path")
	require.NoError(t, err)

	err = repo.DeleteSBOM(ctx, sbomID)
	require.NoError(t, err)

	_, err = repo.GetSBOM(ctx, sbomID)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrSBOMNotFound)
}

func TestDeleteSBOM_NotFound_WithRealPostgreSQL(t *testing.T) {
	db := testutil.TestDB(t)
	ctx := context.Background()
	repo := NewSBOMRepository(db)

	err := repo.DeleteSBOM(ctx, uuid.New())
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrSBOMNotFound)
}

func TestSaveSBOM_CycloneDX_WithRealPostgreSQL(t *testing.T) {
	db := testutil.TestDB(t)
	ctx := context.Background()
	repo := NewSBOMRepository(db)

	cdxSBOM := fmt.Sprintf(`{
		"bomFormat": "CycloneDX",
		"specVersion": "1.5",
		"version": 1,
		"serialNumber": "urn:uuid:%s",
		"metadata": {
			"timestamp": "2026-01-01T00:00:00Z",
			"tools": [{"vendor": "Test", "name": "test-tool", "version": "1.0.0"}],
			"component": {"type": "application", "name": "cyclone-test", "version": "2.0.0"}
		},
		"components": [
			{
				"type": "library",
				"name": "test-lib",
				"version": "1.0.0",
				"purl": "pkg:npm/test-lib@1.0.0",
				"cpe": "cpe:2.3:a:test:lib:1.0.0:*:*:*:*:*:*:*",
				"description": "A test library",
				"licenses": [{"license": {"id": "MIT"}}],
				"supplier": {"name": "Test Supplier"}
			}
		]
	}`, uuid.New().String())

	sbomID, err := repo.SaveSBOM(ctx, cdxSBOM, "/test/cdx/path")
	require.NoError(t, err)
	assert.NotEqual(t, uuid.Nil, sbomID)

	found, err := repo.GetSBOM(ctx, sbomID)
	require.NoError(t, err)
	assert.Equal(t, "cyclone-test", found.Name)
	assert.Equal(t, "CycloneDX", found.Format)
	require.NotEmpty(t, found.Packages)
	assert.Equal(t, "test-lib", found.Packages[0].Name)
	assert.Equal(t, "pkg:npm/test-lib@1.0.0", *found.Packages[0].PURL)
}
