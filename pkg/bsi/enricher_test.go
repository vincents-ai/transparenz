package bsi

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
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

func TestEnrichSBOMModel(t *testing.T) {
	// Create temp directory with go.sum
	tmpDir := t.TempDir()
	goSumContent := `github.com/spf13/cobra v1.10.2 h1:test123hash
github.com/google/uuid v1.6.0 h1:abcd1234hash
`
	goSumPath := filepath.Join(tmpDir, "go.sum")
	if err := os.WriteFile(goSumPath, []byte(goSumContent), 0644); err != nil {
		t.Fatal(err)
	}

	enricher := NewEnricher(tmpDir)

	// Create a mock SBOM model
	sbomModel := &sbom.SBOM{
		Artifacts: sbom.Artifacts{
			Packages: pkg.NewCollection(),
		},
	}

	// Add test packages
	testPkg1 := pkg.Package{
		Name:     "github.com/spf13/cobra",
		Version:  "v1.10.2",
		Type:     pkg.GoModulePkg,
		Licenses: pkg.NewLicenseSet(),
		Metadata: pkg.GolangModuleEntry{},
	}
	testPkg1.SetID()

	testPkg2 := pkg.Package{
		Name:     "github.com/google/uuid",
		Version:  "v1.6.0",
		Type:     pkg.GoModulePkg,
		Licenses: pkg.NewLicenseSet(),
		Metadata: pkg.GolangModuleEntry{},
	}
	testPkg2.SetID()

	sbomModel.Artifacts.Packages.Add(testPkg1)
	sbomModel.Artifacts.Packages.Add(testPkg2)

	// Enrich the model
	enrichedModel, err := enricher.EnrichSBOMModel(sbomModel)
	if err != nil {
		t.Fatalf("EnrichSBOMModel failed: %v", err)
	}

	// Verify enrichment
	packages := enrichedModel.Artifacts.Packages.Sorted()
	if len(packages) != 2 {
		t.Fatalf("Expected 2 packages, got %d", len(packages))
	}

	// Find cobra package
	var cobraPkg *pkg.Package
	for i := range packages {
		if packages[i].Name == "github.com/spf13/cobra" {
			cobraPkg = &packages[i]
			break
		}
	}

	if cobraPkg == nil {
		t.Fatal("Could not find cobra package")
	}

	// Check cobra package license
	if cobraPkg.Licenses.Empty() {
		t.Error("Expected licenses to be enriched for cobra")
	} else {
		licenses := cobraPkg.Licenses.ToSlice()
		foundApache := false
		for _, lic := range licenses {
			if lic.SPDXExpression == "Apache-2.0" || lic.Value == "Apache-2.0" {
				foundApache = true
				break
			}
		}
		if !foundApache {
			t.Errorf("Expected Apache-2.0 license for cobra, got %v", licenses)
		}
	}

	// Check hash enrichment for cobra
	if meta, ok := cobraPkg.Metadata.(pkg.GolangModuleEntry); ok {
		if meta.H1Digest != "test123hash" {
			t.Errorf("Expected H1Digest to be 'test123hash' for cobra, got '%s'", meta.H1Digest)
		}
	} else {
		t.Error("Expected metadata to be GolangModuleEntry")
	}

	// Find uuid package
	var uuidPkg *pkg.Package
	for i := range packages {
		if packages[i].Name == "github.com/google/uuid" {
			uuidPkg = &packages[i]
			break
		}
	}

	if uuidPkg == nil {
		t.Fatal("Could not find uuid package")
	}

	// Check uuid package hash
	if meta, ok := uuidPkg.Metadata.(pkg.GolangModuleEntry); ok {
		if meta.H1Digest != "abcd1234hash" {
			t.Errorf("Expected H1Digest to be 'abcd1234hash' for uuid, got '%s'", meta.H1Digest)
		}
	} else {
		t.Error("Expected metadata to be GolangModuleEntry for uuid")
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
