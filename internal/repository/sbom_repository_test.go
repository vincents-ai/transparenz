package repository

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func loadTestFixture(t *testing.T, filename string) string {
	data, err := os.ReadFile(filepath.Join("testdata", filename))
	require.NoError(t, err)
	return string(data)
}

func TestSaveSBOM_InvalidFormat(t *testing.T) {
	invalidJSON := `{"invalid": "format"}`

	var doc SPDXDocument
	err := json.Unmarshal([]byte(invalidJSON), &doc)
	assert.NoError(t, err)
	assert.Empty(t, doc.SPDXVersion)
}

func TestSaveSBOM_InvalidJSON(t *testing.T) {
	invalidJSON := `not valid json`

	var doc SPDXDocument
	err := json.Unmarshal([]byte(invalidJSON), &doc)
	require.Error(t, err)
}

func TestSPDXParsing(t *testing.T) {
	data := loadTestFixture(t, "spdx_sample.json")

	var doc SPDXDocument
	err := json.Unmarshal([]byte(data), &doc)
	require.NoError(t, err)

	assert.Equal(t, "SPDX-2.3", doc.SPDXVersion)
	assert.Equal(t, "test-project", doc.Name)
	assert.Len(t, doc.Packages, 3)
}

func TestCycloneDXParsing(t *testing.T) {
	data := loadTestFixture(t, "cyclonedx_sample.json")

	var doc CycloneDXDocument
	err := json.Unmarshal([]byte(data), &doc)
	require.NoError(t, err)

	assert.Equal(t, "CycloneDX", doc.BomFormat)
	assert.Equal(t, "1.5", doc.SpecVersion)
	assert.Len(t, doc.Components, 3)
}

func TestGrypeParsing(t *testing.T) {
	data := loadTestFixture(t, "grype_scan.json")

	var scan GrypeScanResult
	err := json.Unmarshal([]byte(data), &scan)
	require.NoError(t, err)

	assert.Equal(t, "grype", scan.Descriptor.Name)
	assert.Equal(t, "0.80.0", scan.Descriptor.Version)
	assert.Len(t, scan.Matches, 4)
}

func TestNormalizeHashAlgorithm(t *testing.T) {
	cases := []struct {
		input    string
		expected string
	}{
		{"SHA1", "SHA1"},
		{"SHA-1", "SHA1"},
		{"sha1", "SHA1"},
		{"SHA256", "SHA256"},
		{"SHA-256", "SHA256"},
		{"sha-256", "SHA256"},
		{"SHA384", "SHA384"},
		{"SHA-384", "SHA384"},
		{"SHA512", "SHA512"},
		{"SHA-512", "SHA512"},
		{"MD5", "MD5"},
		{"md5", "MD5"},
		{"SHA3-256", "SHA3-256"},
		{"SHA3-384", "SHA3-384"},
		{"SHA3-512", "SHA3-512"},
		{"BLAKE2B-256", "BLAKE2b-256"},
		{"BLAKE2b-256", "BLAKE2b-256"},
		{"BLAKE2B-384", "BLAKE2b-384"},
		{"BLAKE2B-512", "BLAKE2b-512"},
		{"UNKNOWN-ALG", ""},
		{"", ""},
	}

	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			result := normalizeHashAlgorithm(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestExtractSPDXPackages_Hashes(t *testing.T) {
	data := loadTestFixture(t, "spdx_sample.json")

	var doc SPDXDocument
	require.NoError(t, json.Unmarshal([]byte(data), &doc))

	repo := &SBOMRepository{}
	sbomID := uuid.New()
	packages, hashes, err := repo.extractSPDXPackages(doc, sbomID)
	require.NoError(t, err)

	assert.Len(t, packages, 3)

	// Locate the main package by name
	var mainPkg, dep1Pkg, dep2Pkg *struct{ idx int }
	for i, p := range packages {
		switch p.Name {
		case "test-project":
			mainPkg = &struct{ idx int }{i}
		case "dependency-one":
			dep1Pkg = &struct{ idx int }{i}
		case "dependency-two":
			dep2Pkg = &struct{ idx int }{i}
		}
	}
	require.NotNil(t, mainPkg, "test-project package not found")
	require.NotNil(t, dep1Pkg, "dependency-one package not found")
	require.NotNil(t, dep2Pkg, "dependency-two package not found")

	// test-project has 2 checksums (SHA256 + SHA1), dependency-one has 1 (MD5), dependency-two has 0
	assert.Len(t, hashes, 3)

	// Collect hashes per package
	mainHashes := make([]string, 0)
	dep1Hashes := make([]string, 0)
	for _, h := range hashes {
		switch h.PackageId {
		case packages[mainPkg.idx].ID:
			mainHashes = append(mainHashes, h.Algorithm)
		case packages[dep1Pkg.idx].ID:
			dep1Hashes = append(dep1Hashes, h.Algorithm)
		}
		// dep2 has no hashes
		assert.NotEqual(t, packages[dep2Pkg.idx].ID, h.PackageId, "dep2 should have no hashes")
	}

	assert.ElementsMatch(t, []string{"SHA256", "SHA1"}, mainHashes)
	assert.ElementsMatch(t, []string{"MD5"}, dep1Hashes)
}

func TestExtractCycloneDXPackages_Hashes(t *testing.T) {
	data := loadTestFixture(t, "cyclonedx_sample.json")

	var doc CycloneDXDocument
	require.NoError(t, json.Unmarshal([]byte(data), &doc))

	repo := &SBOMRepository{}
	sbomID := uuid.New()
	packages, hashes, err := repo.extractCycloneDXPackages(doc, sbomID)
	require.NoError(t, err)

	assert.Len(t, packages, 3)

	// Locate packages by name
	var mainPkg, dep1Pkg, dep2Pkg *struct{ idx int }
	for i, p := range packages {
		switch p.Name {
		case "test-project":
			mainPkg = &struct{ idx int }{i}
		case "dependency-one":
			dep1Pkg = &struct{ idx int }{i}
		case "dependency-two":
			dep2Pkg = &struct{ idx int }{i}
		}
	}
	require.NotNil(t, mainPkg, "test-project package not found")
	require.NotNil(t, dep1Pkg, "dependency-one package not found")
	require.NotNil(t, dep2Pkg, "dependency-two package not found")

	// test-project: SHA-256 + SHA-512 (normalized), dependency-one: MD5, dependency-two: 0
	assert.Len(t, hashes, 3)

	mainHashes := make([]string, 0)
	dep1Hashes := make([]string, 0)
	for _, h := range hashes {
		switch h.PackageId {
		case packages[mainPkg.idx].ID:
			mainHashes = append(mainHashes, h.Algorithm)
		case packages[dep1Pkg.idx].ID:
			dep1Hashes = append(dep1Hashes, h.Algorithm)
		}
		assert.NotEqual(t, packages[dep2Pkg.idx].ID, h.PackageId, "dep2 should have no hashes")
	}

	assert.ElementsMatch(t, []string{"SHA256", "SHA512"}, mainHashes)
	assert.ElementsMatch(t, []string{"MD5"}, dep1Hashes)
}

func TestExtractSPDXPackages_HashesHaveCorrectPackageIDs(t *testing.T) {
	doc := SPDXDocument{
		Packages: []SPDXPackage{
			{
				Name:        "pkg-a",
				VersionInfo: "1.0",
				Checksums: []SPDXChecksum{
					{Algorithm: "SHA256", ChecksumValue: "aabbcc"},
				},
			},
			{
				Name:        "pkg-b",
				VersionInfo: "2.0",
				Checksums: []SPDXChecksum{
					{Algorithm: "SHA1", ChecksumValue: "112233"},
					{Algorithm: "MD5", ChecksumValue: "ffeedd"},
				},
			},
		},
	}

	repo := &SBOMRepository{}
	packages, hashes, err := repo.extractSPDXPackages(doc, uuid.New())
	require.NoError(t, err)
	assert.Len(t, packages, 2)
	assert.Len(t, hashes, 3)

	// Each hash must reference the UUID of one of the returned packages
	pkgIDs := map[uuid.UUID]bool{packages[0].ID: true, packages[1].ID: true}
	for _, h := range hashes {
		assert.True(t, pkgIDs[h.PackageId], "hash PackageId %s not in package set", h.PackageId)
		assert.NotEmpty(t, h.Algorithm)
		assert.NotEmpty(t, h.HashValue)
	}
}

func TestExtractSPDXPackages_SkipsUnknownAlgorithms(t *testing.T) {
	doc := SPDXDocument{
		Packages: []SPDXPackage{
			{
				Name: "pkg",
				Checksums: []SPDXChecksum{
					{Algorithm: "UNKNOWN-ALG", ChecksumValue: "deadbeef"},
					{Algorithm: "SHA256", ChecksumValue: "aabbcc"},
				},
			},
		},
	}

	repo := &SBOMRepository{}
	_, hashes, err := repo.extractSPDXPackages(doc, uuid.New())
	require.NoError(t, err)
	// Only the recognized algorithm should produce a hash record
	assert.Len(t, hashes, 1)
	assert.Equal(t, "SHA256", hashes[0].Algorithm)
}
