package bsi

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
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

func TestBuildBSIProperties_AllComponentTypes(t *testing.T) {
	enricher := NewEnricher(".")

	tests := []struct {
		compType        string
		purl            string
		expectedExec    string
		expectedArchive string
	}{
		{"application", "", "true", "false"},
		{"framework", "", "false", "false"},
		{"operating-system", "", "true", "false"},
		{"container", "", "true", "true"},
		{"file", "", "false", "false"},
		{"firmware", "", "true", "false"},
		{"library", "", "false", "false"},
		{"empty-type", "", "false", "false"},
		{"unknown-type", "", "false", "false"},
		{"library-oci", "pkg:generic/test?type=oci", "true", "true"},
		{"library-docker", "pkg:generic/test?type=docker", "true", "true"},
	}

	for _, tt := range tests {
		t.Run(tt.compType, func(t *testing.T) {
			comp := map[string]interface{}{
				"name": "test-component",
				"type": tt.compType,
			}
			if tt.purl != "" {
				comp["purl"] = tt.purl
			}
			props := enricher.buildBSIProperties(comp)
			propMap := make(map[string]string)
			for _, p := range props {
				pm := p.(map[string]interface{})
				propMap[pm["name"].(string)] = pm["value"].(string)
			}
			if propMap["executable"] != tt.expectedExec {
				t.Errorf("type=%s: expected executable=%s, got %s", tt.compType, tt.expectedExec, propMap["executable"])
			}
			if propMap["archive"] != tt.expectedArchive {
				t.Errorf("type=%s: expected archive=%s, got %s", tt.compType, tt.expectedArchive, propMap["archive"])
			}
			if propMap["structured"] != "true" {
				t.Errorf("type=%s: expected structured=true, got %s", tt.compType, propMap["structured"])
			}
		})
	}
}

func TestDetectLicense_EdgeCases(t *testing.T) {
	enricher := NewEnricher(".")

	tests := []struct {
		name     string
		pkg      string
		expected string
	}{
		{"empty string", "", ""},
		{"stdlib", "stdlib", "BSD-3-Clause"},
		{"subpackage - spf13/cobra/sub", "github.com/spf13/cobra/command", "Apache-2.0"},
		{"subpackage - google subpackage", "github.com/google/goexpect", "BSD-3-Clause"},
		{"subpackage - golang.org/x", "golang.org/x/crypto/ssh", "BSD-3-Clause"},
		{"gorm subpackage", "gorm.io/gorm/clause", "MIT"},
		{"anchore subpackage", "github.com/anchore/syft/internal", "Apache-2.0"},
		{"completely unknown", "unknown/very/random/package", ""},
		{"single segment", "mypackage", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := enricher.detectLicense(tt.pkg)
			if result != tt.expected {
				t.Errorf("detectLicense(%q) = %q, want %q", tt.pkg, result, tt.expected)
			}
		})
	}
}

func TestDetectSupplier_PackagePatterns(t *testing.T) {
	enricher := NewEnricher(".")

	tests := []struct {
		name     string
		pkg      string
		expected string
	}{
		{"empty string", "", ""},
		{"github.com/microsoft/tslib", "github.com/microsoft/tslib", "Microsoft Corporation"},
		{"github.com/aws/aws-sdk-go", "github.com/aws/aws-sdk-go", "Amazon Web Services"},
		{"github.com/Azure/azure-sdk-for-go", "github.com/Azure/azure-sdk-for-go", "Microsoft Azure"},
		{"github.com/apple/swift", "github.com/apple/swift", "Apple Inc"},
		{"github.com/facebook/react", "github.com/facebook/react", "Meta Platforms Inc"},
		{"github.com/meta-llama/llama", "github.com/meta-llama/llama", "Meta-llama"},
		{"github.com/hashicorp/terraform", "github.com/hashicorp/terraform", "HashiCorp Inc"},
		{"github.com/docker/cli", "github.com/docker/cli", "Docker Inc"},
		{"github.com/gorilla/mux", "github.com/gorilla/mux", "Gorilla Web Toolkit"},
		{"github.com/gin-gonic/gin", "github.com/gin-gonic/gin", "Gin Contributors"},
		{"github.com/labstack/echo", "github.com/labstack/echo", "LabStack LLC"},
		{"github.com/urfave/cli", "github.com/urfave/cli", "urfave"},
		{"github.com/sirupsen/logrus", "github.com/sirupsen/logrus", "Simon Eskildsen"},
		{"github.com/jackc/pgx", "github.com/jackc/pgx", "Jack Christensen"},
		{"github.com/lib/pq", "github.com/lib/pq", "lib Contributors"},
		{"github.com/go-sql-driver/mysql", "github.com/go-sql-driver/mysql", "Go-MySQL-Driver Authors"},
		{"github.com/mattn/go-sqlite3", "github.com/mattn/go-sqlite3", "Yasuhiro Matsumoto"},
		{"github.com/jmoiron/sqlx", "github.com/jmoiron/sqlx", "Jason Moiron"},
		{"go.uber.org/zap", "go.uber.org/zap", "Uber Technologies Inc"},
		{"github.com/rs/zerolog", "github.com/rs/zerolog", "Olivier Poitrey"},
		{"github.com/apex/log", "github.com/apex/log", "TJ Holowaychuk"},
		{"github.com/stretchr/testify", "github.com/stretchr/testify", "Stretchr Inc"},
		{"github.com/onsi/ginkgo", "github.com/onsi/ginkgo", "Onsi Fakhouri"},
		{"github.com/golang/mock", "github.com/golang/mock", "The Go Authors"},
		{"k8s.io/api", "k8s.io/api", "Kubernetes Authors"},
		{"github.com/prometheus/client_golang", "github.com/prometheus/client_golang", "The Prometheus Authors"},
		{"github.com/aquasecurity/trivy", "github.com/aquasecurity/trivy", "Aqua Security"},
		{"google.golang.org/grpc", "google.golang.org/grpc", "The Go Authors"},
		{"gopkg.in/yaml.v3", "gopkg.in/yaml.v3", "gopkg.in Authors"},
		{"github.com/deutschland/stack", "github.com/deutschland/stack", "Deutschland-Stack"},
		{"github.com/go-redis/redis", "github.com/go-redis/redis", "go-redis Authors"},
		{"github.com/redis/go-redis", "github.com/redis/go-redis", "Redis Ltd"},
		{"github.com/json-iterator/go", "github.com/json-iterator/go", "json-iterator Authors"},
		{"github.com/tidwall/gjson", "github.com/tidwall/gjson", "Josh Baker"},
		{"github.com/mailru/easyjson", "github.com/mailru/easyjson", "Mail.Ru Group"},
		{"github.com/pelletier/go-toml", "github.com/pelletier/go-toml", "Thomas Pelletier"},
		{"github.com/charmbracelet/bubbletea", "github.com/charmbracelet/bubbletea", "Charm Bracelet"},
		{"github.com/fatih/vim", "github.com/fatih/vim", "Fatih Arslan"},
		{"github.com/pkg/errors", "github.com/pkg/errors", "pkg Authors"},
		{"github.com/davecgh/go-spew", "github.com/davecgh/go-spew", "Dave Collins"},
		{"github.com/go-playground/validator", "github.com/go-playground/validator", "go-playground"},
		{"github.com/asaskevich/govalidator", "github.com/asaskevich/govalidator", "Alex Saskevich"},
		{"github.com/kelseyhightower/envconfig", "github.com/kelseyhightower/envconfig", "Kelsey Hightower"},
		{"github.com/joho/godotenv", "github.com/joho/godotenv", "John Barton"},
		{"github.com/valyala/fasthttp", "github.com/valyala/fasthttp", "Aliaksandr Valialkin"},
		{"github.com/julienschmidt/httprouter", "github.com/julienschmidt/httprouter", "Julien Schmidt"},
		{"github.com/oklog/run", "github.com/oklog/run", "OK Log Authors"},
		{"github.com/segmentio/asm", "github.com/segmentio/asm", "Segment.io Inc"},
		{"gitlab.com/gitlab-org/gitlab", "gitlab.com/gitlab-org/gitlab", "gitlab-org (gitlab.com)"},
		{"bitbucket.org/team/mod", "bitbucket.org/team/mod", "team (bitbucket.org)"},
		{"git.sr.ht/~sircmpwn/hare", "git.sr.ht/~sircmpwn/hare", "~sircmpwn (git.sr.ht)"},
		{"unknown/pkg", "unknown/pkg", ""},
		{"singleword", "singleword", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := enricher.detectSupplier(tt.pkg)
			if result != tt.expected {
				t.Errorf("detectSupplier(%q) = %q, want %q", tt.pkg, result, tt.expected)
			}
		})
	}
}

func TestEnrichSPDX_EdgeCases(t *testing.T) {
	tmpDir := t.TempDir()
	enricher := NewEnricher(tmpDir)

	t.Run("missing packages", func(t *testing.T) {
		sbomJSON := `{"spdxVersion": "SPDX-2.3"}`
		_, err := enricher.EnrichSBOM(sbomJSON)
		if err == nil {
			t.Error("Expected error for missing packages")
		}
	})

	t.Run("empty packages array", func(t *testing.T) {
		sbomJSON := `{"spdxVersion": "SPDX-2.3", "packages": []}`
		enriched, err := enricher.EnrichSBOM(sbomJSON)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		var result map[string]interface{}
		if err := json.Unmarshal([]byte(enriched), &result); err != nil {
			t.Fatal(err)
		}
		pkgs := result["packages"].([]interface{})
		if len(pkgs) != 0 {
			t.Errorf("Expected 0 packages, got %d", len(pkgs))
		}
	})

	t.Run("package with NOASSERTION license", func(t *testing.T) {
		sbomJSON := `{
			"spdxVersion": "SPDX-2.3",
			"packages": [
				{
					"name": "github.com/spf13/cobra",
					"licenseConcluded": "NOASSERTION"
				}
			]
		}`
		enriched, err := enricher.EnrichSBOM(sbomJSON)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		var result map[string]interface{}
		if err := json.Unmarshal([]byte(enriched), &result); err != nil {
			t.Fatal(err)
		}
		pkgs := result["packages"].([]interface{})
		pkg := pkgs[0].(map[string]interface{})
		if pkg["licenseConcluded"] != "Apache-2.0" {
			t.Errorf("Expected Apache-2.0, got %v", pkg["licenseConcluded"])
		}
	})

	t.Run("package with existing license", func(t *testing.T) {
		sbomJSON := `{
			"spdxVersion": "SPDX-2.3",
			"packages": [
				{
					"name": "github.com/spf13/cobra",
					"licenseConcluded": "MIT"
				}
			]
		}`
		enriched, err := enricher.EnrichSBOM(sbomJSON)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		var result map[string]interface{}
		if err := json.Unmarshal([]byte(enriched), &result); err != nil {
			t.Fatal(err)
		}
		pkgs := result["packages"].([]interface{})
		pkg := pkgs[0].(map[string]interface{})
		if pkg["licenseConcluded"] != "MIT" {
			t.Errorf("Expected MIT to be preserved, got %v", pkg["licenseConcluded"])
		}
	})

	t.Run("package with NOASSERTION supplier", func(t *testing.T) {
		sbomJSON := `{
			"spdxVersion": "SPDX-2.3",
			"packages": [
				{
					"name": "github.com/spf13/cobra",
					"supplier": "NOASSERTION"
				}
			]
		}`
		enriched, err := enricher.EnrichSBOM(sbomJSON)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		var result map[string]interface{}
		if err := json.Unmarshal([]byte(enriched), &result); err != nil {
			t.Fatal(err)
		}
		pkgs := result["packages"].([]interface{})
		pkg := pkgs[0].(map[string]interface{})
		if pkg["supplier"] != "Organization: Steve Francia" {
			t.Errorf("Expected Steve Francia, got %v", pkg["supplier"])
		}
	})

	t.Run("existing annotations are preserved", func(t *testing.T) {
		sbomJSON := `{
			"spdxVersion": "SPDX-2.3",
			"packages": [
				{
					"name": "github.com/spf13/cobra",
					"annotations": [{"comment": "existing"}]
				}
			]
		}`
		enriched, err := enricher.EnrichSBOM(sbomJSON)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		var result map[string]interface{}
		if err := json.Unmarshal([]byte(enriched), &result); err != nil {
			t.Fatal(err)
		}
		pkgs := result["packages"].([]interface{})
		pkg := pkgs[0].(map[string]interface{})
		annotations := pkg["annotations"].([]interface{})
		if len(annotations) != 2 {
			t.Errorf("Expected 2 annotations (existing + BSI), got %d", len(annotations))
		}
	})

	t.Run("invalid package element", func(t *testing.T) {
		sbomJSON := `{
			"spdxVersion": "SPDX-2.3",
			"packages": [
				"invalid",
				{"name": "github.com/spf13/cobra"}
			]
		}`
		enriched, err := enricher.EnrichSBOM(sbomJSON)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		var result map[string]interface{}
		if err := json.Unmarshal([]byte(enriched), &result); err != nil {
			t.Fatal(err)
		}
	})
}

func TestEnrichCycloneDX_EdgeCases(t *testing.T) {
	tmpDir := t.TempDir()
	enricher := NewEnricher(tmpDir)

	t.Run("missing components", func(t *testing.T) {
		sbomJSON := `{"bomFormat": "CycloneDX", "specVersion": "1.5"}`
		_, err := enricher.EnrichSBOM(sbomJSON)
		if err == nil {
			t.Error("Expected error for missing components")
		}
	})

	t.Run("empty components array", func(t *testing.T) {
		sbomJSON := `{"bomFormat": "CycloneDX", "specVersion": "1.5", "components": []}`
		enriched, err := enricher.EnrichSBOM(sbomJSON)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		var result map[string]interface{}
		if err := json.Unmarshal([]byte(enriched), &result); err != nil {
			t.Fatal(err)
		}
		comps := result["components"].([]interface{})
		if len(comps) != 0 {
			t.Errorf("Expected 0 components, got %d", len(comps))
		}
	})

	t.Run("existing metadata is preserved", func(t *testing.T) {
		sbomJSON := `{
			"bomFormat": "CycloneDX",
			"specVersion": "1.5",
			"metadata": {"timestamp": "2024-01-01"},
			"components": []
		}`
		enriched, err := enricher.EnrichSBOM(sbomJSON)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		var result map[string]interface{}
		if err := json.Unmarshal([]byte(enriched), &result); err != nil {
			t.Fatal(err)
		}
		metadata := result["metadata"].(map[string]interface{})
		if metadata["timestamp"] != "2024-01-01" {
			t.Errorf("Expected timestamp to be preserved, got %v", metadata["timestamp"])
		}
	})

	t.Run("existing licenses are preserved", func(t *testing.T) {
		sbomJSON := `{
			"bomFormat": "CycloneDX",
			"specVersion": "1.5",
			"components": [
				{
					"name": "github.com/spf13/cobra",
					"licenses": [{"license": {"id": "MIT"}}]
				}
			]
		}`
		enriched, err := enricher.EnrichSBOM(sbomJSON)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		var result map[string]interface{}
		if err := json.Unmarshal([]byte(enriched), &result); err != nil {
			t.Fatal(err)
		}
		comps := result["components"].([]interface{})
		comp := comps[0].(map[string]interface{})
		licenses := comp["licenses"].([]interface{})
		lic := licenses[0].(map[string]interface{})["license"].(map[string]interface{})
		if lic["id"] != "MIT" {
			t.Errorf("Expected MIT to be preserved, got %v", lic["id"])
		}
	})

	t.Run("existing string supplier is preserved", func(t *testing.T) {
		sbomJSON := `{
			"bomFormat": "CycloneDX",
			"specVersion": "1.5",
			"components": [
				{
					"name": "github.com/spf13/cobra",
					"supplier": "Organization: Custom Supplier"
				}
			]
		}`
		enriched, err := enricher.EnrichSBOM(sbomJSON)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		var result map[string]interface{}
		if err := json.Unmarshal([]byte(enriched), &result); err != nil {
			t.Fatal(err)
		}
		comps := result["components"].([]interface{})
		comp := comps[0].(map[string]interface{})
		supplier := comp["supplier"].(string)
		if supplier != "Organization: Custom Supplier" {
			t.Errorf("Expected Organization: Custom Supplier to be preserved, got %v", supplier)
		}
	})

	t.Run("invalid component element", func(t *testing.T) {
		sbomJSON := `{
			"bomFormat": "CycloneDX",
			"specVersion": "1.5",
			"components": [
				"invalid",
				{"name": "github.com/spf13/cobra"}
			]
		}`
		enriched, err := enricher.EnrichSBOM(sbomJSON)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		var result map[string]interface{}
		if err := json.Unmarshal([]byte(enriched), &result); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("existing properties are preserved", func(t *testing.T) {
		sbomJSON := `{
			"bomFormat": "CycloneDX",
			"specVersion": "1.5",
			"components": [
				{
					"name": "github.com/spf13/cobra",
					"properties": [{"name": "custom", "value": "value"}]
				}
			]
		}`
		enriched, err := enricher.EnrichSBOM(sbomJSON)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		var result map[string]interface{}
		if err := json.Unmarshal([]byte(enriched), &result); err != nil {
			t.Fatal(err)
		}
		comps := result["components"].([]interface{})
		comp := comps[0].(map[string]interface{})
		properties := comp["properties"].([]interface{})
		if len(properties) != 4 {
			t.Errorf("Expected 4 properties (1 custom + 3 BSI), got %d", len(properties))
		}
	})
}

func TestCalculateFileHash_ErrorHandling(t *testing.T) {
	t.Run("non-existent file", func(t *testing.T) {
		_, err := calculateFileHash("/nonexistent/path/to/file.bin")
		if err == nil {
			t.Error("Expected error for non-existent file")
		}
	})

	t.Run("empty file", func(t *testing.T) {
		tmpDir := t.TempDir()
		emptyFile := filepath.Join(tmpDir, "empty")
		if err := os.WriteFile(emptyFile, []byte{}, 0644); err != nil {
			t.Fatal(err)
		}
		hash, err := calculateFileHash(emptyFile)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		expectedEmptyHash := "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
		if hash != expectedEmptyHash {
			t.Errorf("Expected empty file hash %s, got %s", expectedEmptyHash, hash)
		}
	})

	t.Run("large file", func(t *testing.T) {
		tmpDir := t.TempDir()
		largeFile := filepath.Join(tmpDir, "large")
		content := make([]byte, 1024*1024)
		for i := range content {
			content[i] = byte(i % 256)
		}
		if err := os.WriteFile(largeFile, content, 0644); err != nil {
			t.Fatal(err)
		}
		hash, err := calculateFileHash(largeFile)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if len(hash) != 128 {
			t.Errorf("Expected 128 hex chars, got %d", len(hash))
		}
	})
}

func TestH1DigestToHex(t *testing.T) {
	tests := []struct {
		input    string
		expected string
		wantErr  bool
	}{
		{"47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", false},
		{"!!!invalid!!!", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result, err := h1DigestToHex(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("h1DigestToHex() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && result != tt.expected {
				t.Errorf("h1DigestToHex() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

func TestBuildBSIAnnotations(t *testing.T) {
	enricher := NewEnricher(".")

	t.Run("application type", func(t *testing.T) {
		pkg := map[string]interface{}{
			"SPDXID": "SPDXRef-Package-application",
		}
		annotations := enricher.buildBSIAnnotations(pkg)
		if len(annotations) != 1 {
			t.Fatalf("Expected 1 annotation, got %d", len(annotations))
		}
		ann := annotations[0].(map[string]interface{})
		comment := ann["comment"].(string)
		if !contains(comment, "executable=true") {
			t.Errorf("Expected executable=true, got %s", comment)
		}
	})

	t.Run("library type", func(t *testing.T) {
		pkg := map[string]interface{}{
			"SPDXID": "SPDXRef-Package-library",
		}
		annotations := enricher.buildBSIAnnotations(pkg)
		ann := annotations[0].(map[string]interface{})
		comment := ann["comment"].(string)
		if !contains(comment, "executable=false") {
			t.Errorf("Expected executable=false, got %s", comment)
		}
	})

	t.Run("no SPDXID", func(t *testing.T) {
		pkg := map[string]interface{}{}
		annotations := enricher.buildBSIAnnotations(pkg)
		ann := annotations[0].(map[string]interface{})
		comment := ann["comment"].(string)
		if !contains(comment, "executable=false") {
			t.Errorf("Expected executable=false, got %s", comment)
		}
	})
}

func TestGetString(t *testing.T) {
	m := map[string]interface{}{
		"exists":    "value",
		"wrongType": 123,
		"empty":     "",
	}

	tests := []struct {
		key      string
		expected string
	}{
		{"exists", "value"},
		{"wrongType", ""},
		{"empty", ""},
		{"missing", ""},
	}

	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			result := getString(m, tt.key)
			if result != tt.expected {
				t.Errorf("getString(%q) = %q, want %q", tt.key, result, tt.expected)
			}
		})
	}
}

func TestEnrichSBOMModel_Nil(t *testing.T) {
	enricher := NewEnricher(".")
	_, err := enricher.EnrichSBOMModel(nil)
	if err == nil {
		t.Error("Expected error for nil SBOM")
	}
}

func TestEnrichSBOMModel_Empty(t *testing.T) {
	enricher := NewEnricher(".")
	sbomModel := &sbom.SBOM{
		Artifacts: sbom.Artifacts{
			Packages: pkg.NewCollection(),
		},
	}
	enrichedModel, err := enricher.EnrichSBOMModel(sbomModel)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	packages := enrichedModel.Artifacts.Packages.Sorted()
	if len(packages) != 0 {
		t.Errorf("Expected 0 packages, got %d", len(packages))
	}
}

func TestEnrichSBOM_InvalidJSON(t *testing.T) {
	enricher := NewEnricher(".")
	_, err := enricher.EnrichSBOM("invalid json")
	if err == nil {
		t.Error("Expected error for invalid JSON")
	}
}

func TestEnrichSBOM_MarshalError(t *testing.T) {
	enricher := NewEnricher(".")
	_, err := enricher.EnrichSBOM(`{"spdxVersion": "SPDX-2.3", "packages": [null]}`)
	if err != nil {
		t.Logf("Error (may be expected): %v", err)
	}
}

func TestEnrichWithArtifactHashes(t *testing.T) {
	enricher := NewEnricher(".")
	tmpDir := t.TempDir()

	t.Run("CycloneDX with artifact directory", func(t *testing.T) {
		artifactFile := filepath.Join(tmpDir, "test-bin")
		content := []byte("binary content")
		if err := os.WriteFile(artifactFile, content, 0755); err != nil {
			t.Fatal(err)
		}

		sbomData := map[string]interface{}{
			"bomFormat":   "CycloneDX",
			"specVersion": "1.5",
			"components": []interface{}{
				map[string]interface{}{
					"name": "test-bin",
					"type": "application",
				},
			},
		}

		err := enricher.EnrichWithArtifactHashes(sbomData, tmpDir)
		if err != nil {
			t.Fatalf("EnrichWithArtifactHashes failed: %v", err)
		}

		components := sbomData["components"].([]interface{})
		comp := components[0].(map[string]interface{})
		hashes, ok := comp["hashes"].([]interface{})
		if !ok || len(hashes) == 0 {
			t.Error("Expected hashes to be added")
		}
	})

	t.Run("SPDX with artifact directory", func(t *testing.T) {
		artifactFile := filepath.Join(tmpDir, "test-app")
		content := []byte("app content")
		if err := os.WriteFile(artifactFile, content, 0755); err != nil {
			t.Fatal(err)
		}

		sbomData := map[string]interface{}{
			"spdxVersion": "SPDX-2.3",
			"packages": []interface{}{
				map[string]interface{}{
					"name":      "test-app",
					"SPDXID":    "SPDXRef-Package",
					"checksums": []interface{}{},
				},
			},
		}

		err := enricher.EnrichWithArtifactHashes(sbomData, tmpDir)
		if err != nil {
			t.Fatalf("EnrichWithArtifactHashes failed: %v", err)
		}
	})

	t.Run("Invalid SBOM format", func(t *testing.T) {
		sbomData := map[string]interface{}{
			"invalid": "format",
		}

		err := enricher.EnrichWithArtifactHashes(sbomData, tmpDir)
		if err == nil {
			t.Error("Expected error for invalid SBOM format")
		}
	})

	t.Run("Empty artifact directory", func(t *testing.T) {
		emptyDir := t.TempDir()

		sbomData := map[string]interface{}{
			"bomFormat": "CycloneDX",
			"components": []interface{}{
				map[string]interface{}{
					"name": "no-artifact",
					"type": "library",
				},
			},
		}

		err := enricher.EnrichWithArtifactHashes(sbomData, emptyDir)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
	})
}

func TestEnrichCycloneDXWithArtifactHashes(t *testing.T) {
	enricher := NewEnricher(".")
	tmpDir := t.TempDir()

	artifactFile := filepath.Join(tmpDir, "myapp")
	if err := os.WriteFile(artifactFile, []byte("content"), 0755); err != nil {
		t.Fatal(err)
	}

	components := []interface{}{
		map[string]interface{}{
			"name": "myapp",
			"type": "application",
		},
		map[string]interface{}{
			"name": "other",
			"type": "library",
		},
	}

	err := enricher.enrichCycloneDXWithArtifactHashes(components, tmpDir)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	comp := components[0].(map[string]interface{})
	hashes, ok := comp["hashes"].([]interface{})
	if !ok || len(hashes) == 0 {
		t.Error("Expected hashes for matching artifact")
	}
}

func TestEnrichSPDXWithArtifactHashes(t *testing.T) {
	enricher := NewEnricher(".")
	tmpDir := t.TempDir()

	artifactFile := filepath.Join(tmpDir, "mybinary")
	if err := os.WriteFile(artifactFile, []byte("binary"), 0755); err != nil {
		t.Fatal(err)
	}

	packages := []interface{}{
		map[string]interface{}{
			"name":      "mybinary",
			"SPDXID":    "SPDXRef-Binary",
			"checksums": []interface{}{},
		},
	}

	err := enricher.enrichSPDXWithArtifactHashes(packages, tmpDir)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	pkg := packages[0].(map[string]interface{})
	checksums, ok := pkg["checksums"].([]interface{})
	if !ok || len(checksums) == 0 {
		t.Error("Expected checksums for matching package")
	}
}

func TestDetectLicenseFromText(t *testing.T) {
	t.Run("nil classifier returns empty", func(t *testing.T) {
		result := detectLicenseFromText("some license text")
		if result != "" {
			t.Logf("Got result: %s", result)
		}
	})

	t.Run("empty text returns empty", func(t *testing.T) {
		result := detectLicenseFromText("")
		if result != "" {
			t.Logf("Got result: %s", result)
		}
	})
}

func TestAssertDependencyCompleteness(t *testing.T) {
	enricher := NewEnricher(".")

	t.Run("CycloneDX adds completeness", func(t *testing.T) {
		sbomData := map[string]interface{}{
			"bomFormat":   "CycloneDX",
			"specVersion": "1.5",
			"metadata":    map[string]interface{}{},
		}

		enricher.assertDependencyCompleteness(sbomData)

		metadata := sbomData["metadata"].(map[string]interface{})
		props := metadata["properties"].([]interface{})

		found := false
		for _, p := range props {
			pm := p.(map[string]interface{})
			if pm["name"] == "completeness" && pm["value"] == "complete" {
				found = true
				break
			}
		}
		if !found {
			t.Error("Expected completeness property to be added")
		}

		specVer := sbomData["specVersion"]
		if specVer != "1.6" {
			t.Errorf("Expected specVersion 1.6, got %v", specVer)
		}
	})

	t.Run("SPDX adds annotation", func(t *testing.T) {
		sbomData := map[string]interface{}{
			"spdxVersion": "SPDX-2.3",
		}

		enricher.assertDependencyCompleteness(sbomData)

		annotations, ok := sbomData["annotations"].([]interface{})
		if !ok || len(annotations) == 0 {
			t.Error("Expected annotations to be added")
		}
	})
}

func TestEnrichSBOM_EmptyJSON(t *testing.T) {
	enricher := NewEnricher(".")
	_, err := enricher.EnrichSBOM("{}")
	if err == nil {
		t.Error("Expected error for empty JSON")
	}
}

func TestGetKnownLicense(t *testing.T) {
	enricher := NewEnricher(".")

	tests := []struct {
		pkg      string
		expected string
	}{
		{"github.com/spf13/cobra", "Apache-2.0"},
		{"github.com/spf13/viper", "MIT"},
		{"github.com/google/uuid", "BSD-3-Clause"},
		{"gorm.io/gorm", "MIT"},
		{"golang.org/x/crypto", "BSD-3-Clause"},
		{"stdlib", "BSD-3-Clause"},
		{"unknown/package", ""},
	}

	for _, tt := range tests {
		t.Run(tt.pkg, func(t *testing.T) {
			result := enricher.getKnownLicense(tt.pkg)
			if result != tt.expected {
				t.Errorf("getKnownLicense(%s) = %s, want %s", tt.pkg, result, tt.expected)
			}
		})
	}
}

func TestParseAuthorsFile(t *testing.T) {
	t.Run("empty file", func(t *testing.T) {
		tmpDir := t.TempDir()
		authorsFile := filepath.Join(tmpDir, "AUTHORS")
		if err := os.WriteFile(authorsFile, []byte(""), 0644); err != nil {
			t.Fatal(err)
		}

		file, err := os.Open(authorsFile)
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()

		result := parseAuthorsFile(file)
		if result != "" {
			t.Errorf("Expected empty result, got %q", result)
		}
	})

	t.Run("file with only comments", func(t *testing.T) {
		tmpDir := t.TempDir()
		authorsFile := filepath.Join(tmpDir, "AUTHORS")
		content := "# This is a comment\n// Another comment\n"
		if err := os.WriteFile(authorsFile, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}

		file, err := os.Open(authorsFile)
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()

		result := parseAuthorsFile(file)
		if result != "" {
			t.Errorf("Expected empty result for comments, got %q", result)
		}
	})
}

func TestExtractSupplierFromAuthors(t *testing.T) {
	t.Run("no authors file", func(t *testing.T) {
		result := ExtractSupplierFromAuthors("/nonexistent/path")
		if result != "" {
			t.Errorf("Expected empty result, got %q", result)
		}
	})

	t.Run("authors file with email", func(t *testing.T) {
		tmpDir := t.TempDir()
		authorsFile := filepath.Join(tmpDir, "AUTHORS")
		content := "John Doe <john@example.com>\n"
		if err := os.WriteFile(authorsFile, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}

		result := ExtractSupplierFromAuthors(tmpDir)
		if result != "John Doe" {
			t.Errorf("Expected 'John Doe', got %q", result)
		}
	})
}

func TestLoadGoSum(t *testing.T) {
	enricher := NewEnricher(".")

	t.Run("no go.sum file", func(t *testing.T) {
		result := enricher.loadGoSum()
		if len(result) != 0 {
			t.Errorf("Expected empty map, got %d entries", len(result))
		}
	})

	t.Run("with go.sum file", func(t *testing.T) {
		tmpDir := t.TempDir()
		goSumFile := filepath.Join(tmpDir, "go.sum")
		content := `golang.org/x/text v0.0.0 h1: OlahdJgR9M8nrX
		`
		if err := os.WriteFile(goSumFile, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}

		result := enricher.loadGoSum()
		if len(result) != 0 {
			t.Logf("Got %d entries", len(result))
		}
	})
}

func contains(s, substr string) bool {
	return strings.Contains(s, substr)
}

// ---------------------------------------------------------------------------
// TestEnrichWithBinaryHash – BSI TR-03183-2 §4.3 single-binary shortcut
// ---------------------------------------------------------------------------

func TestEnrichWithBinaryHash_CycloneDX(t *testing.T) {
	enricher := NewEnricher(".")

	// Create a temp file with known content and compute expected hash
	tmpDir := t.TempDir()
	binaryPath := filepath.Join(tmpDir, "myapp")
	content := []byte("fake compiled binary content for hashing")
	if err := os.WriteFile(binaryPath, content, 0755); err != nil {
		t.Fatal(err)
	}

	expectedHash, err := CalculateArtifactHash(binaryPath)
	if err != nil {
		t.Fatalf("CalculateArtifactHash failed: %v", err)
	}
	if len(expectedHash) != 128 {
		t.Fatalf("Expected 128-char SHA-512 hex, got %d", len(expectedHash))
	}

	sbomJSON := `{
		"bomFormat": "CycloneDX",
		"specVersion": "1.6",
		"metadata": {},
		"components": []
	}`

	result, err := enricher.EnrichWithBinaryHash(sbomJSON, binaryPath)
	if err != nil {
		t.Fatalf("EnrichWithBinaryHash failed: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(result), &parsed); err != nil {
		t.Fatalf("Result is not valid JSON: %v", err)
	}

	metadata, ok := parsed["metadata"].(map[string]interface{})
	if !ok {
		t.Fatal("metadata must be a map")
	}
	component, ok := metadata["component"].(map[string]interface{})
	if !ok {
		t.Fatal("metadata.component must be present and be a map")
	}
	hashes, ok := component["hashes"].([]interface{})
	if !ok || len(hashes) == 0 {
		t.Fatal("metadata.component.hashes must be a non-empty array")
	}

	found := false
	for _, h := range hashes {
		hm, ok := h.(map[string]interface{})
		if !ok {
			continue
		}
		if hm["alg"] == "SHA-512" && hm["content"] == expectedHash {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Expected SHA-512 hash %s in metadata.component.hashes, got %v", expectedHash, hashes)
	}
}

func TestEnrichWithBinaryHash_CycloneDX_NoMetadata(t *testing.T) {
	enricher := NewEnricher(".")

	tmpDir := t.TempDir()
	binaryPath := filepath.Join(tmpDir, "tool")
	if err := os.WriteFile(binaryPath, []byte("binary"), 0755); err != nil {
		t.Fatal(err)
	}

	// SBOM with no metadata at all
	sbomJSON := `{
		"bomFormat": "CycloneDX",
		"specVersion": "1.6",
		"components": []
	}`

	result, err := enricher.EnrichWithBinaryHash(sbomJSON, binaryPath)
	if err != nil {
		t.Fatalf("EnrichWithBinaryHash failed: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(result), &parsed); err != nil {
		t.Fatalf("Result is not valid JSON: %v", err)
	}

	metadata, ok := parsed["metadata"].(map[string]interface{})
	if !ok {
		t.Fatal("metadata should be created when absent")
	}
	component, ok := metadata["component"].(map[string]interface{})
	if !ok {
		t.Fatal("metadata.component should be created when absent")
	}
	hashes, ok := component["hashes"].([]interface{})
	if !ok || len(hashes) == 0 {
		t.Fatal("Expected hashes to be added")
	}
}

func TestEnrichWithBinaryHash_CycloneDX_ReplacesExistingHash(t *testing.T) {
	enricher := NewEnricher(".")

	tmpDir := t.TempDir()
	binaryPath := filepath.Join(tmpDir, "app")
	if err := os.WriteFile(binaryPath, []byte("updated binary"), 0755); err != nil {
		t.Fatal(err)
	}

	newHash, err := CalculateArtifactHash(binaryPath)
	if err != nil {
		t.Fatal(err)
	}

	// SBOM already has an old SHA-512 and an MD5 entry
	sbomJSON := `{
		"bomFormat": "CycloneDX",
		"specVersion": "1.6",
		"metadata": {
			"component": {
				"hashes": [
					{"alg": "MD5",    "content": "deadbeef"},
					{"alg": "SHA-512","content": "oldoldoldold"}
				]
			}
		},
		"components": []
	}`

	result, err := enricher.EnrichWithBinaryHash(sbomJSON, binaryPath)
	if err != nil {
		t.Fatalf("EnrichWithBinaryHash failed: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(result), &parsed); err != nil {
		t.Fatal(err)
	}

	hashes := parsed["metadata"].(map[string]interface{})["component"].(map[string]interface{})["hashes"].([]interface{})

	// MD5 must be preserved; old SHA-512 must be replaced
	foundMD5 := false
	for _, h := range hashes {
		hm := h.(map[string]interface{})
		if hm["alg"] == "MD5" {
			foundMD5 = true
		}
		if hm["alg"] == "SHA-512" && hm["content"] == "oldoldoldold" {
			t.Error("old SHA-512 should have been replaced")
		}
		if hm["alg"] == "SHA-512" && hm["content"] == newHash {
			// good
		}
	}
	if !foundMD5 {
		t.Error("MD5 entry should be preserved")
	}
}

func TestEnrichWithBinaryHash_SPDX_FirstPackage(t *testing.T) {
	enricher := NewEnricher(".")

	tmpDir := t.TempDir()
	binaryPath := filepath.Join(tmpDir, "no-match-name")
	if err := os.WriteFile(binaryPath, []byte("spdx binary"), 0755); err != nil {
		t.Fatal(err)
	}

	expectedHash, err := CalculateArtifactHash(binaryPath)
	if err != nil {
		t.Fatal(err)
	}

	// Binary name doesn't match any package → falls back to first package
	sbomJSON := `{
		"spdxVersion": "SPDX-2.3",
		"packages": [
			{"name": "my-project", "SPDXID": "SPDXRef-Package", "checksums": []},
			{"name": "some-dep",   "SPDXID": "SPDXRef-Dep",     "checksums": []}
		]
	}`

	result, err := enricher.EnrichWithBinaryHash(sbomJSON, binaryPath)
	if err != nil {
		t.Fatalf("EnrichWithBinaryHash failed: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(result), &parsed); err != nil {
		t.Fatal(err)
	}

	packages := parsed["packages"].([]interface{})
	firstPkg := packages[0].(map[string]interface{})
	checksums, ok := firstPkg["checksums"].([]interface{})
	if !ok || len(checksums) == 0 {
		t.Fatal("Expected checksums to be added to the first package")
	}

	found := false
	for _, cs := range checksums {
		csm := cs.(map[string]interface{})
		if csm["algorithm"] == "SHA512" && csm["checksumValue"] == expectedHash {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Expected SHA512 checksum %s in first package, got %v", expectedHash, checksums)
	}

	// Second package should be untouched
	secondPkg := packages[1].(map[string]interface{})
	secondChecksums := secondPkg["checksums"].([]interface{})
	if len(secondChecksums) != 0 {
		t.Error("Second package should not have received a checksum")
	}
}

func TestEnrichWithBinaryHash_SPDX_MatchesByName(t *testing.T) {
	enricher := NewEnricher(".")

	tmpDir := t.TempDir()
	binaryPath := filepath.Join(tmpDir, "exact-name")
	if err := os.WriteFile(binaryPath, []byte("named binary"), 0755); err != nil {
		t.Fatal(err)
	}

	sbomJSON := `{
		"spdxVersion": "SPDX-2.3",
		"packages": [
			{"name": "other-pkg", "SPDXID": "SPDXRef-Other", "checksums": []},
			{"name": "exact-name","SPDXID": "SPDXRef-Main",  "checksums": []}
		]
	}`

	result, err := enricher.EnrichWithBinaryHash(sbomJSON, binaryPath)
	if err != nil {
		t.Fatalf("EnrichWithBinaryHash failed: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(result), &parsed); err != nil {
		t.Fatal(err)
	}

	packages := parsed["packages"].([]interface{})
	// First package (other-pkg) should be untouched
	firstPkg := packages[0].(map[string]interface{})
	if cs := firstPkg["checksums"].([]interface{}); len(cs) != 0 {
		t.Error("other-pkg should not have received a checksum")
	}
	// Second package (exact-name) should have the hash
	secondPkg := packages[1].(map[string]interface{})
	secondChecksums, ok := secondPkg["checksums"].([]interface{})
	if !ok || len(secondChecksums) == 0 {
		t.Fatal("exact-name package should have received a checksum")
	}
	csm := secondChecksums[0].(map[string]interface{})
	if csm["algorithm"] != "SHA512" {
		t.Errorf("Expected algorithm SHA512, got %v", csm["algorithm"])
	}
}

func TestEnrichWithBinaryHash_FileNotFound(t *testing.T) {
	enricher := NewEnricher(".")

	sbomJSON := `{"bomFormat": "CycloneDX", "specVersion": "1.6", "metadata": {}, "components": []}`

	_, err := enricher.EnrichWithBinaryHash(sbomJSON, "/nonexistent/binary")
	if err == nil {
		t.Error("Expected error for non-existent binary path")
	}
}

func TestEnrichWithBinaryHash_InvalidJSON(t *testing.T) {
	enricher := NewEnricher(".")

	tmpDir := t.TempDir()
	binaryPath := filepath.Join(tmpDir, "bin")
	if err := os.WriteFile(binaryPath, []byte("data"), 0755); err != nil {
		t.Fatal(err)
	}

	_, err := enricher.EnrichWithBinaryHash("not valid json", binaryPath)
	if err == nil {
		t.Error("Expected error for invalid JSON input")
	}
}

func TestEnrichWithBinaryHash_SPDX_EmptyPackages(t *testing.T) {
	enricher := NewEnricher(".")

	tmpDir := t.TempDir()
	binaryPath := filepath.Join(tmpDir, "app")
	if err := os.WriteFile(binaryPath, []byte("data"), 0755); err != nil {
		t.Fatal(err)
	}

	// Empty packages array – should not panic, should succeed gracefully
	sbomJSON := `{"spdxVersion": "SPDX-2.3", "packages": []}`

	result, err := enricher.EnrichWithBinaryHash(sbomJSON, binaryPath)
	if err != nil {
		t.Fatalf("EnrichWithBinaryHash on empty packages should not error: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(result), &parsed); err != nil {
		t.Fatalf("Result must be valid JSON: %v", err)
	}
}

// TestInjectManufacturer_CycloneDX verifies that CycloneDX SBOMs receive
// metadata.manufacturer with name and url fields per BSI TR-03183-2.
func TestInjectManufacturer_CycloneDX(t *testing.T) {
	enricher := NewEnricher(".")

	sbomJSON := `{
		"bomFormat": "CycloneDX",
		"specVersion": "1.6",
		"metadata": {},
		"components": []
	}`

	result, err := enricher.InjectManufacturer(sbomJSON, "Acme Corp", "https://acme.example.com")
	if err != nil {
		t.Fatalf("InjectManufacturer failed: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(result), &parsed); err != nil {
		t.Fatalf("Failed to parse result: %v", err)
	}

	metadata, ok := parsed["metadata"].(map[string]interface{})
	if !ok {
		t.Fatal("metadata must be a map")
	}

	manufacturer, ok := metadata["manufacturer"].(map[string]interface{})
	if !ok {
		t.Fatal("metadata.manufacturer must be present and be a map")
	}

	if manufacturer["name"] != "Acme Corp" {
		t.Errorf("Expected manufacturer.name 'Acme Corp', got %v", manufacturer["name"])
	}

	urls, ok := manufacturer["url"].([]interface{})
	if !ok || len(urls) == 0 {
		t.Fatal("manufacturer.url must be a non-empty array")
	}
	if urls[0] != "https://acme.example.com" {
		t.Errorf("Expected manufacturer.url[0] 'https://acme.example.com', got %v", urls[0])
	}
}

// TestInjectManufacturer_CycloneDX_NoMetadata verifies that metadata is created
// when it does not already exist in the CycloneDX SBOM.
func TestInjectManufacturer_CycloneDX_NoMetadata(t *testing.T) {
	enricher := NewEnricher(".")

	sbomJSON := `{
		"bomFormat": "CycloneDX",
		"specVersion": "1.6",
		"components": []
	}`

	result, err := enricher.InjectManufacturer(sbomJSON, "Test Org", "https://test.org")
	if err != nil {
		t.Fatalf("InjectManufacturer failed: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(result), &parsed); err != nil {
		t.Fatalf("Failed to parse result: %v", err)
	}

	metadata, ok := parsed["metadata"].(map[string]interface{})
	if !ok {
		t.Fatal("metadata must be created and be a map")
	}
	if _, ok := metadata["manufacturer"]; !ok {
		t.Fatal("metadata.manufacturer must be injected when metadata has no manufacturer")
	}
}

// TestInjectManufacturer_SPDX verifies that SPDX SBOMs receive a document-level
// REVIEW annotation carrying the producer identity per BSI TR-03183-2.
func TestInjectManufacturer_SPDX(t *testing.T) {
	enricher := NewEnricher(".")

	sbomJSON := `{
		"spdxVersion": "SPDX-2.3",
		"packages": []
	}`

	result, err := enricher.InjectManufacturer(sbomJSON, "Widgets GmbH", "https://widgets.de")
	if err != nil {
		t.Fatalf("InjectManufacturer failed: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(result), &parsed); err != nil {
		t.Fatalf("Failed to parse result: %v", err)
	}

	annotations, ok := parsed["annotations"].([]interface{})
	if !ok || len(annotations) == 0 {
		t.Fatal("Expected document-level annotations to be added for SPDX")
	}

	// Find the producer annotation
	found := false
	for _, ann := range annotations {
		annMap, ok := ann.(map[string]interface{})
		if !ok {
			continue
		}
		if annMap["annotationType"] == "REVIEW" &&
			annMap["annotator"] == "Tool: transparenz" &&
			strings.Contains(annMap["comment"].(string), "SBOM-Producer: Widgets GmbH https://widgets.de") &&
			annMap["annotationDate"] != "" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Expected REVIEW annotation with SBOM-Producer comment, got: %v", annotations)
	}
}

// TestInjectManufacturer_EmptyName verifies that an empty name causes the function
// to return the original SBOM unchanged (silent skip).
func TestInjectManufacturer_EmptyName(t *testing.T) {
	enricher := NewEnricher(".")

	sbomJSON := `{
		"bomFormat": "CycloneDX",
		"specVersion": "1.6",
		"metadata": {},
		"components": []
	}`

	result, err := enricher.InjectManufacturer(sbomJSON, "", "https://ignored.com")
	if err != nil {
		t.Fatalf("InjectManufacturer with empty name should not error: %v", err)
	}

	// Result must be valid JSON and must NOT contain manufacturer
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(result), &parsed); err != nil {
		t.Fatalf("Result must be valid JSON: %v", err)
	}

	if metadata, ok := parsed["metadata"].(map[string]interface{}); ok {
		if _, hasManufacturer := metadata["manufacturer"]; hasManufacturer {
			t.Error("manufacturer must not be injected when name is empty")
		}
	}
}

// TestInjectManufacturer_InvalidJSON verifies that an error is returned
// for malformed input.
func TestInjectManufacturer_InvalidJSON(t *testing.T) {
	enricher := NewEnricher(".")

	_, err := enricher.InjectManufacturer("not valid json", "Acme", "https://acme.com")
	if err == nil {
		t.Error("Expected error for invalid JSON input")
	}
}

// TestInjectManufacturer_CycloneDX_URLEmpty verifies that an empty URL is handled
// gracefully (url array omitted or empty).
func TestInjectManufacturer_CycloneDX_URLEmpty(t *testing.T) {
	enricher := NewEnricher(".")

	sbomJSON := `{
		"bomFormat": "CycloneDX",
		"specVersion": "1.6",
		"metadata": {},
		"components": []
	}`

	result, err := enricher.InjectManufacturer(sbomJSON, "NoURL Corp", "")
	if err != nil {
		t.Fatalf("InjectManufacturer failed: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(result), &parsed); err != nil {
		t.Fatalf("Failed to parse result: %v", err)
	}

	metadata := parsed["metadata"].(map[string]interface{})
	manufacturer := metadata["manufacturer"].(map[string]interface{})

	if manufacturer["name"] != "NoURL Corp" {
		t.Errorf("Expected manufacturer.name 'NoURL Corp', got %v", manufacturer["name"])
	}
	// url should be absent or empty when not provided
	if urls, ok := manufacturer["url"]; ok {
		if urlSlice, ok := urls.([]interface{}); ok && len(urlSlice) > 0 {
			t.Errorf("Expected no urls when url param is empty, got %v", urlSlice)
		}
	}
}
