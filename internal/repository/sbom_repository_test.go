package repository

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

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
