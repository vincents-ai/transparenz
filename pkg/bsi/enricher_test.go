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
	tmpDir := t.TempDir()

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

	// Check BSI annotations (executable, archive, structured metadata)
	if annotations, ok := pkg["annotations"].([]interface{}); ok {
		if len(annotations) == 0 {
			t.Error("Expected BSI TR-03183-2 annotations to be added")
		}
	}

	// Check dependency completeness annotation
	if annotations, ok := result["annotations"].([]interface{}); ok && len(annotations) > 0 {
		found := false
		for _, ann := range annotations {
			if annMap, ok := ann.(map[string]interface{}); ok {
				if comment, ok := annMap["comment"].(string); ok {
					if comment != "" {
						found = true
						break
					}
				}
			}
		}
		if !found {
			t.Error("Expected dependency completeness annotation in document-level annotations")
		}
	}
}

func TestEnricherCycloneDX(t *testing.T) {
	tmpDir := t.TempDir()

	enricher := NewEnricher(tmpDir)

	sbomJSON := `{
		"bomFormat": "CycloneDX",
		"specVersion": "1.5",
		"metadata": {},
		"components": [
			{
				"name": "github.com/spf13/cobra",
				"version": "v1.10.2",
				"type": "library"
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

	// Check specVersion bumped to 1.6 for BSI compliance
	if specVer, ok := result["specVersion"].(string); ok {
		if specVer != "1.6" {
			t.Errorf("Expected specVersion 1.6, got %s", specVer)
		}
	} else {
		t.Error("Expected specVersion to be set")
	}

	components := result["components"].([]interface{})
	if len(components) == 0 {
		t.Fatal("No components in enriched SBOM")
	}

	comp := components[0].(map[string]interface{})

	// Check license enrichment
	licenses := comp["licenses"].([]interface{})
	if len(licenses) == 0 {
		t.Fatal("Expected license to be added")
	}
	licData := licenses[0].(map[string]interface{})["license"].(map[string]interface{})
	if licData["id"].(string) != "Apache-2.0" {
		t.Errorf("Expected Apache-2.0 license, got %s", licData["id"])
	}

	// Check supplier enrichment
	supplier := comp["supplier"].(map[string]interface{})
	if supplier["name"].(string) != "Steve Francia" {
		t.Errorf("Expected Steve Francia supplier, got %s", supplier["name"])
	}

	// Check BSI TR-03183-2 mandatory component properties
	properties := comp["properties"].([]interface{})
	requiredProps := map[string]string{
		"executable": "false",
		"archive":    "false",
		"structured": "true",
	}
	foundProps := make(map[string]string)
	for _, prop := range properties {
		propMap := prop.(map[string]interface{})
		foundProps[propMap["name"].(string)] = propMap["value"].(string)
	}
	for name, expected := range requiredProps {
		if val, ok := foundProps[name]; !ok {
			t.Errorf("Missing BSI property: %s", name)
		} else if val != expected {
			t.Errorf("Property %s: expected %s, got %s", name, expected, val)
		}
	}

	// Check dependency completeness in metadata
	metadata := result["metadata"].(map[string]interface{})
	metaProps := metadata["properties"].([]interface{})
	foundCompleteness := false
	for _, prop := range metaProps {
		propMap := prop.(map[string]interface{})
		if propMap["name"].(string) == "completeness" && propMap["value"].(string) == "complete" {
			foundCompleteness = true
			break
		}
	}
	if !foundCompleteness {
		t.Error("Expected dependency completeness property in metadata")
	}
}

func TestEnrichSBOMModel(t *testing.T) {
	enricher := NewEnricher(".")

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

func TestCalculateArtifactHash(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test-binary")
	content := []byte("test binary content for SHA-512 hashing")
	if err := os.WriteFile(testFile, content, 0644); err != nil {
		t.Fatal(err)
	}

	hash, err := CalculateArtifactHash(testFile)
	if err != nil {
		t.Fatalf("CalculateArtifactHash failed: %v", err)
	}

	// SHA-512 produces 128 hex characters
	if len(hash) != 128 {
		t.Errorf("Expected 128 hex chars for SHA-512, got %d", len(hash))
	}
}

func TestBuildBSIProperties(t *testing.T) {
	enricher := NewEnricher(".")

	// Test library component
	libComp := map[string]interface{}{
		"name": "test-lib",
		"type": "library",
	}
	props := enricher.buildBSIProperties(libComp)
	if len(props) != 3 {
		t.Fatalf("Expected 3 properties, got %d", len(props))
	}

	propMap := make(map[string]string)
	for _, p := range props {
		pm := p.(map[string]interface{})
		propMap[pm["name"].(string)] = pm["value"].(string)
	}

	if propMap["executable"] != "false" {
		t.Errorf("Library should not be executable, got %s", propMap["executable"])
	}
	if propMap["archive"] != "false" {
		t.Errorf("Library should not be archive, got %s", propMap["archive"])
	}
	if propMap["structured"] != "true" {
		t.Errorf("All components should be structured, got %s", propMap["structured"])
	}
}
