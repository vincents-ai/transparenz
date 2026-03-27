package bsi

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestEnricherSPDX(t *testing.T) {
	// Create temp directory with go.sum
	tmpDir := t.TempDir()
	goSumContent := `github.com/spf13/cobra v1.10.2 h1:test123
github.com/google/uuid v1.6.0 h1:abcd1234
`
	goSumPath := filepath.Join(tmpDir, "go.sum")
	if err := os.WriteFile(goSumPath, []byte(goSumContent), 0644); err != nil {
		t.Fatal(err)
	}

	enricher := NewEnricher(tmpDir)

	sbomJSON := `{
		"spdxVersion": "SPDX-2.3",
		"packages": [
			{
				"name": "github.com/spf13/cobra",
				"versionInfo": "v1.10.2",
				"licenseConcluded": "NOASSERTION"
			}
		]
	}`

	enriched, err := enricher.EnrichSBOM(sbomJSON)
	if err != nil {
		t.Fatalf("EnrichSBOM failed: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal([]byte(enriched), &result); err != nil {
		t.Fatal(err)
	}

	packages := result["packages"].([]interface{})
	if len(packages) == 0 {
		t.Fatal("No packages in enriched SBOM")
	}

	pkg := packages[0].(map[string]interface{})

	// Check license enrichment
	if license := pkg["licenseConcluded"].(string); license != "Apache-2.0" {
		t.Errorf("Expected Apache-2.0 license, got %s", license)
	}

	// Check supplier enrichment
	if supplier := pkg["supplier"].(string); supplier != "Organization: Steve Francia" {
		t.Errorf("Expected Steve Francia supplier, got %s", supplier)
	}

	// Check hash enrichment
	checksums := pkg["checksums"].([]interface{})
	if len(checksums) == 0 {
		t.Error("Expected checksums to be added")
	}
}

func TestDetectLicense(t *testing.T) {
	enricher := NewEnricher(".")

	tests := []struct {
		pkg      string
		expected string
	}{
		{"github.com/spf13/cobra", "Apache-2.0"},
		{"github.com/google/uuid", "BSD-3-Clause"},
		{"gorm.io/gorm", "MIT"},
		{"golang.org/x/crypto", "BSD-3-Clause"},
		{"unknown/package", ""},
	}

	for _, tt := range tests {
		t.Run(tt.pkg, func(t *testing.T) {
			result := enricher.detectLicense(tt.pkg)
			if result != tt.expected {
				t.Errorf("detectLicense(%s) = %s, want %s", tt.pkg, result, tt.expected)
			}
		})
	}
}

func TestDetectSupplier(t *testing.T) {
	enricher := NewEnricher(".")

	tests := []struct {
		pkg      string
		expected string
	}{
		{"github.com/spf13/cobra", "Steve Francia"},
		{"github.com/google/uuid", "Google LLC"},
		{"gorm.io/gorm", "GORM Team"},
		{"golang.org/x/text", "The Go Authors"},
		{"unknown/package", ""},
	}

	for _, tt := range tests {
		t.Run(tt.pkg, func(t *testing.T) {
			result := enricher.detectSupplier(tt.pkg)
			if result != tt.expected {
				t.Errorf("detectSupplier(%s) = %s, want %s", tt.pkg, result, tt.expected)
			}
		})
	}
}

func TestLoadGoSum(t *testing.T) {
	tmpDir := t.TempDir()
	goSumContent := `github.com/spf13/cobra v1.10.2 h1:test123hash
github.com/google/uuid v1.6.0 h1:abcd1234hash
`
	goSumPath := filepath.Join(tmpDir, "go.sum")
	if err := os.WriteFile(goSumPath, []byte(goSumContent), 0644); err != nil {
		t.Fatal(err)
	}

	enricher := NewEnricher(tmpDir)
	hashes := enricher.loadGoSum()

	if len(hashes) != 2 {
		t.Errorf("Expected 2 hashes, got %d", len(hashes))
	}

	if hash := hashes["github.com/spf13/cobra@v1.10.2"]; hash != "test123hash" {
		t.Errorf("Expected test123hash, got %s", hash)
	}
}
