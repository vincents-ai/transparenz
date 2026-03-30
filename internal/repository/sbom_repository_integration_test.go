// SPDX-License-Identifier: AGPL-3.0-or-later OR Commercial
// Copyright (c) 2026 Vincent Palmer

package repository

import (
	"context"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	gormpostgres "gorm.io/driver/postgres"
	"gorm.io/gorm"

	"github.com/shift/transparenz/internal/models"
)

func TestSaveSBOM_WithRealPostgreSQL(t *testing.T) {
	if os.Getenv("INTEGRATION_TEST") != "true" {
		t.Skip("Skipping integration test. Set INTEGRATION_TEST=true to run.")
	}

	ctx := context.Background()

	container, err := tcpostgres.Run(ctx,
		"postgres:16-alpine",
		tcpostgres.WithDatabase("transparenz_test"),
		tcpostgres.WithUsername("test"),
		tcpostgres.WithPassword("test"),
	)
	require.NoError(t, err)
	t.Cleanup(func() {
		assert.NoError(t, container.Terminate(ctx))
	})

	connStr, err := container.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)

	db, err := gorm.Open(gormpostgres.Open(connStr), &gorm.Config{})
	require.NoError(t, err)

	err = db.AutoMigrate(&models.SBOM{}, &models.Package{}, &models.Scan{})
	require.NoError(t, err)

	repo := NewSBOMRepository(db)

	spdxSBOM := `{
		"spdxVersion": "SPDX-2.3",
		"dataLicense": "CC0-1.0",
		"SPDXID": "SPDXRef-DOCUMENT",
		"name": "test-project",
		"documentNamespace": "https://example.com/test-project",
		"documentDescribes": ["SPDXRef-Package"],
		"creationInfo": {
			"created": "2026-01-01T00:00:00Z",
			"creators": ["Tool: test"]
		},
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
	}`

	sbomID, err := repo.SaveSBOM(ctx, spdxSBOM, "/test/path")
	require.NoError(t, err)
	assert.NotEqual(t, uuid.Nil, sbomID)

	var savedSBOM models.SBOM
	err = db.Preload("Packages").First(&savedSBOM, "id = ?", sbomID).Error
	require.NoError(t, err)
	assert.Equal(t, "test-project", savedSBOM.Name)
	assert.Equal(t, "SPDX", savedSBOM.Format)
	assert.Len(t, savedSBOM.Packages, 1)
	assert.Equal(t, "test-package", savedSBOM.Packages[0].Name)
}

func TestGetSBOM_WithRealPostgreSQL(t *testing.T) {
	if os.Getenv("INTEGRATION_TEST") != "true" {
		t.Skip("Skipping integration test. Set INTEGRATION_TEST=true to run.")
	}

	ctx := context.Background()

	container, err := tcpostgres.Run(ctx,
		"postgres:16-alpine",
		tcpostgres.WithDatabase("transparenz_test"),
		tcpostgres.WithUsername("test"),
		tcpostgres.WithPassword("test"),
	)
	require.NoError(t, err)
	t.Cleanup(func() {
		assert.NoError(t, container.Terminate(ctx))
	})

	connStr, _ := container.ConnectionString(ctx, "sslmode=disable")
	db, err := gorm.Open(gormpostgres.Open(connStr), &gorm.Config{})
	require.NoError(t, err)

	err = db.AutoMigrate(&models.SBOM{}, &models.Package{}, &models.Scan{})
	require.NoError(t, err)

	repo := NewSBOMRepository(db)

	spdxSBOM := `{
		"spdxVersion": "SPDX-2.3",
		"dataLicense": "CC0-1.0",
		"SPDXID": "SPDXRef-DOCUMENT",
		"name": "get-test-project",
		"documentNamespace": "https://example.com/get-test",
		"documentDescribes": ["SPDXRef-Package"],
		"creationInfo": {
			"created": "2026-01-01T00:00:00Z"
		},
		"packages": []
	}`

	sbomID, err := repo.SaveSBOM(ctx, spdxSBOM, "/test/path")
	require.NoError(t, err)

	foundSBOM, err := repo.GetSBOM(ctx, sbomID)
	require.NoError(t, err)
	assert.Equal(t, "get-test-project", foundSBOM.Name)
	assert.Equal(t, "SPDX", foundSBOM.Format)
}

func TestGetSBOM_NotFound_WithRealPostgreSQL(t *testing.T) {
	if os.Getenv("INTEGRATION_TEST") != "true" {
		t.Skip("Skipping integration test. Set INTEGRATION_TEST=true to run.")
	}

	ctx := context.Background()

	container, err := tcpostgres.Run(ctx,
		"postgres:16-alpine",
		tcpostgres.WithDatabase("transparenz_test"),
		tcpostgres.WithUsername("test"),
		tcpostgres.WithPassword("test"),
	)
	require.NoError(t, err)
	t.Cleanup(func() {
		assert.NoError(t, container.Terminate(ctx))
	})

	connStr, _ := container.ConnectionString(ctx, "sslmode=disable")
	db, err := gorm.Open(gormpostgres.Open(connStr), &gorm.Config{})
	require.NoError(t, err)

	err = db.AutoMigrate(&models.SBOM{}, &models.Package{}, &models.Scan{})
	require.NoError(t, err)

	repo := NewSBOMRepository(db)

	_, err = repo.GetSBOM(ctx, uuid.New())
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrSBOMNotFound)
}

func TestListSBOMs_WithRealPostgreSQL(t *testing.T) {
	if os.Getenv("INTEGRATION_TEST") != "true" {
		t.Skip("Skipping integration test. Set INTEGRATION_TEST=true to run.")
	}

	ctx := context.Background()

	container, err := tcpostgres.Run(ctx,
		"postgres:16-alpine",
		tcpostgres.WithDatabase("transparenz_test"),
		tcpostgres.WithUsername("test"),
		tcpostgres.WithPassword("test"),
	)
	require.NoError(t, err)
	t.Cleanup(func() {
		assert.NoError(t, container.Terminate(ctx))
	})

	connStr, _ := container.ConnectionString(ctx, "sslmode=disable")
	db, err := gorm.Open(gormpostgres.Open(connStr), &gorm.Config{})
	require.NoError(t, err)

	err = db.AutoMigrate(&models.SBOM{}, &models.Package{}, &models.Scan{})
	require.NoError(t, err)

	repo := NewSBOMRepository(db)

	for i := 0; i < 5; i++ {
		spdxSBOM := `{
			"spdxVersion": "SPDX-2.3",
			"dataLicense": "CC0-1.0",
			"SPDXID": "SPDXRef-DOCUMENT",
			"name": "list-test-project-` + string(rune('0'+i)) + `",
			"documentNamespace": "https://example.com/list-test-` + string(rune('0'+i)) + `",
			"documentDescribes": ["SPDXRef-Package"],
			"creationInfo": {
				"created": "2026-01-01T00:00:00Z"
			},
			"packages": []
		}`
		_, err := repo.SaveSBOM(ctx, spdxSBOM, "/test/path")
		require.NoError(t, err)
	}

	sboms, err := repo.ListSBOMs(ctx, 10, 0)
	require.NoError(t, err)
	assert.Len(t, sboms, 5)

	sboms, err = repo.ListSBOMs(ctx, 2, 0)
	require.NoError(t, err)
	assert.Len(t, sboms, 2)

	sboms, err = repo.ListSBOMs(ctx, 2, 2)
	require.NoError(t, err)
	assert.Len(t, sboms, 2)
}

func TestDeleteSBOM_WithRealPostgreSQL(t *testing.T) {
	if os.Getenv("INTEGRATION_TEST") != "true" {
		t.Skip("Skipping integration test. Set INTEGRATION_TEST=true to run.")
	}

	ctx := context.Background()

	container, err := tcpostgres.Run(ctx,
		"postgres:16-alpine",
		tcpostgres.WithDatabase("transparenz_test"),
		tcpostgres.WithUsername("test"),
		tcpostgres.WithPassword("test"),
	)
	require.NoError(t, err)
	t.Cleanup(func() {
		assert.NoError(t, container.Terminate(ctx))
	})

	connStr, _ := container.ConnectionString(ctx, "sslmode=disable")
	db, err := gorm.Open(gormpostgres.Open(connStr), &gorm.Config{})
	require.NoError(t, err)

	err = db.AutoMigrate(&models.SBOM{}, &models.Package{}, &models.Scan{})
	require.NoError(t, err)

	repo := NewSBOMRepository(db)

	spdxSBOM := `{
		"spdxVersion": "SPDX-2.3",
		"dataLicense": "CC0-1.0",
		"SPDXID": "SPDXRef-DOCUMENT",
		"name": "delete-test-project",
		"documentNamespace": "https://example.com/delete-test",
		"documentDescribes": ["SPDXRef-Package"],
		"creationInfo": {
			"created": "2026-01-01T00:00:00Z"
		},
		"packages": []
	}`

	sbomID, err := repo.SaveSBOM(ctx, spdxSBOM, "/test/path")
	require.NoError(t, err)

	err = repo.DeleteSBOM(ctx, sbomID)
	require.NoError(t, err)

	_, err = repo.GetSBOM(ctx, sbomID)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrSBOMNotFound)
}

func TestDeleteSBOM_NotFound_WithRealPostgreSQL(t *testing.T) {
	if os.Getenv("INTEGRATION_TEST") != "true" {
		t.Skip("Skipping integration test. Set INTEGRATION_TEST=true to run.")
	}

	ctx := context.Background()

	container, err := tcpostgres.Run(ctx,
		"postgres:16-alpine",
		tcpostgres.WithDatabase("transparenz_test"),
		tcpostgres.WithUsername("test"),
		tcpostgres.WithPassword("test"),
	)
	require.NoError(t, err)
	t.Cleanup(func() {
		assert.NoError(t, container.Terminate(ctx))
	})

	connStr, _ := container.ConnectionString(ctx, "sslmode=disable")
	db, err := gorm.Open(gormpostgres.Open(connStr), &gorm.Config{})
	require.NoError(t, err)

	err = db.AutoMigrate(&models.SBOM{}, &models.Package{}, &models.Scan{})
	require.NoError(t, err)

	repo := NewSBOMRepository(db)

	err = repo.DeleteSBOM(ctx, uuid.New())
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrSBOMNotFound)
}

func TestSaveSBOM_CycloneDX_WithRealPostgreSQL(t *testing.T) {
	if os.Getenv("INTEGRATION_TEST") != "true" {
		t.Skip("Skipping integration test. Set INTEGRATION_TEST=true to run.")
	}

	ctx := context.Background()

	container, err := tcpostgres.Run(ctx,
		"postgres:16-alpine",
		tcpostgres.WithDatabase("transparenz_test"),
		tcpostgres.WithUsername("test"),
		tcpostgres.WithPassword("test"),
	)
	require.NoError(t, err)
	t.Cleanup(func() {
		assert.NoError(t, container.Terminate(ctx))
	})

	connStr, _ := container.ConnectionString(ctx, "sslmode=disable")
	db, err := gorm.Open(gormpostgres.Open(connStr), &gorm.Config{})
	require.NoError(t, err)

	err = db.AutoMigrate(&models.SBOM{}, &models.Package{}, &models.Scan{})
	require.NoError(t, err)

	repo := NewSBOMRepository(db)

	cdxSBOM := `{
		"bomFormat": "CycloneDX",
		"specVersion": "1.5",
		"version": 1,
		"serialNumber": "urn:uuid:6e8d4e2c-9f3a-4b5e-a7c8-d9e1f2a3b4c5",
		"metadata": {
			"timestamp": "2026-01-01T00:00:00Z",
			"tools": [
				{
					"vendor": "Test",
					"name": "test-tool",
					"version": "1.0.0"
				}
			],
			"component": {
				"type": "application",
				"name": "cyclone-test",
				"version": "2.0.0"
			}
		},
		"components": [
			{
				"type": "library",
				"name": "test-lib",
				"version": "1.0.0",
				"purl": "pkg:npm/test-lib@1.0.0",
				"cpe": "cpe:2.3:a:test:lib:1.0.0:*:*:*:*:*:*:*",
				"description": "A test library",
				"licenses": [
					{
						"license": {
							"id": "MIT"
						}
					}
				],
				"supplier": {
					"name": "Test Supplier"
				}
			}
		]
	}`

	sbomID, err := repo.SaveSBOM(ctx, cdxSBOM, "/test/cdx/path")
	require.NoError(t, err)
	assert.NotEqual(t, uuid.Nil, sbomID)

	var savedSBOM models.SBOM
	err = db.Preload("Packages").First(&savedSBOM, "id = ?", sbomID).Error
	require.NoError(t, err)
	assert.Equal(t, "cyclone-test", savedSBOM.Name)
	assert.Equal(t, "CycloneDX", savedSBOM.Format)
	assert.Len(t, savedSBOM.Packages, 1)
	assert.Equal(t, "test-lib", savedSBOM.Packages[0].Name)
	assert.Equal(t, "pkg:npm/test-lib@1.0.0", *savedSBOM.Packages[0].PURL)
}
