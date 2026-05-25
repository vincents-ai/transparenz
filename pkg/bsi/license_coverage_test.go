package bsi

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/licenseclassifier/v2/assets"
)

// TestLicenseCoverageDiagnostic measures the actual license identification rate
// against the transparenz repo's own dependencies. This test exists to diagnose
// the reported 67% coverage issue.
func TestLicenseCoverageDiagnostic(t *testing.T) {
	// Step 1: Parse go.mod to get all dependencies
	goModPath := filepath.Join("..", "..", "go.mod")
	data, err := os.ReadFile(goModPath)
	if err != nil {
		t.Skipf("go.mod not found: %v", err)
	}

	var deps []string
	inRequire := false
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "require (" {
			inRequire = true
			continue
		}
		if trimmed == ")" && inRequire {
			inRequire = false
			continue
		}
		if inRequire && trimmed != "" && !strings.HasPrefix(trimmed, "//") {
			parts := strings.Fields(trimmed)
			if len(parts) >= 1 {
				deps = append(deps, parts[0])
			}
		}
		// Single-line require
		if strings.HasPrefix(trimmed, "require ") && !strings.HasPrefix(trimmed, "require (") {
			parts := strings.Fields(trimmed)
			if len(parts) >= 2 {
				deps = append(deps, parts[1])
			}
		}
	}

	t.Logf("Total dependencies in go.mod: %d", len(deps))

	// Step 2: Initialize the license classifier
	classifier, err := assets.DefaultClassifier()
	if err != nil {
		t.Fatalf("Failed to initialize licenseclassifier: %v", err)
	}

	// Step 3: Create enricher and test license detection
	// Use the concrete *enricher type since getKnownLicense/parseLicenseFile are unexported
	sourceDir := filepath.Join("..", "..")
	e := &enricher{sourcePath: sourceDir}

	var identified, failed []string
	for _, dep := range deps {
		// Method 1: getKnownLicense (hardcoded map of ~20 packages)
		if license := e.getKnownLicense(dep); license != "" {
			identified = append(identified, dep)
			continue
		}

		// Method 2: parseLicenseFile (reads LICENSE from module cache)
		if license := e.parseLicenseFile(dep); license != "" {
			identified = append(identified, dep)
			continue
		}

		failed = append(failed, dep)
	}

	total := len(deps)
	coverage := float64(len(identified)) / float64(total) * 100

	t.Logf("")
	t.Logf("━━━ License Coverage Diagnostic ━━━")
	t.Logf("Total dependencies:    %d", total)
	t.Logf("Identified licenses:   %d", len(identified))
	t.Logf("Unidentified:          %d", len(failed))
	t.Logf("Coverage:              %.1f%%", coverage)
	t.Logf("")

	if len(failed) > 0 {
		t.Logf("── Unidentified packages (first 80) ──")
		limit := len(failed)
		if limit > 80 {
			limit = 80
		}
		for i := 0; i < limit; i++ {
			t.Logf("  %s", failed[i])
		}
		if len(failed) > 80 {
			t.Logf("  ... and %d more", len(failed)-80)
		}
	}

	// Step 4: Diagnose WHY each fails
	t.Logf("")
	t.Logf("── Failure Root Cause Analysis ──")

	noCache := 0
	noLicenseFile := 0
	classifierLowConf := 0
	classifierNoMatch := 0
	classifierSuccess := 0

	gopath := os.Getenv("GOPATH")
	if gopath == "" {
		homeDir, _ := os.UserHomeDir()
		gopath = filepath.Join(homeDir, "go")
	}
	modCache := filepath.Join(gopath, "pkg", "mod")

	for _, dep := range failed {
		// Check if module is in cache at all
		matches, _ := filepath.Glob(filepath.Join(modCache, dep+"@*"))
		if len(matches) == 0 {
			noCache++
			continue
		}

		// Check if LICENSE file exists in any cached version
		licenseFiles := []string{"LICENSE", "LICENSE.txt", "LICENSE.md", "COPYING", "LICENSE-MIT", "LICENSE-APACHE"}
		foundLicense := false
		for _, lf := range licenseFiles {
			for _, modDir := range matches {
				content, err := os.ReadFile(filepath.Join(modDir, lf))
				if err != nil {
					continue
				}
				foundLicense = true

				// Try classifier on it
				results := classifier.Match(content)
				if len(results.Matches) > 0 {
					best := results.Matches[0]
					if best.Confidence > 0.8 {
						classifierSuccess++
						t.Logf("  %s: classifier FOUND %s (%.2f conf) but parseLicenseFile MISSED it — BUG",
							dep, best.Name, best.Confidence)
					} else {
						classifierLowConf++
						t.Logf("  %s: classifier found %s but confidence %.2f < 0.8 threshold",
							dep, best.Name, best.Confidence)
					}
				} else {
					classifierNoMatch++
					t.Logf("  %s: classifier returned NO matches (content len=%d)",
						dep, len(content))
				}
				break
			}
			if foundLicense {
				break
			}
		}
		if !foundLicense {
			noLicenseFile++
		}
	}

	t.Logf("")
	t.Logf("Root causes of %d failures:", len(failed))
	t.Logf("  Module not in cache (run 'go mod download'):  %d", noCache)
	t.Logf("  No LICENSE file in module:                     %d", noLicenseFile)
	t.Logf("  Classifier confidence < 0.8:                   %d", classifierLowConf)
	t.Logf("  Classifier no match:                           %d", classifierNoMatch)
	t.Logf("  Classifier matched but parseLicenseFile MISS:  %d", classifierSuccess)

	// Always pass — this is a diagnostic, not a gate.
	if coverage < 90.0 {
		t.Logf("")
		t.Logf("⚠ Coverage is %.1f%% (target: 90%%+)", coverage)
	}
}

// TestSHA512HashDiagnostic verifies that SHA-512 hashes are correctly
// injected into both SPDX and CycloneDX SBOMs.
func TestSHA512HashDiagnostic(t *testing.T) {
	tmpDir := t.TempDir()
	binaryPath := filepath.Join(tmpDir, "test-binary")
	binaryContent := []byte("fake binary content for SHA-512 diagnostic test")
	if err := os.WriteFile(binaryPath, binaryContent, 0755); err != nil {
		t.Fatalf("Failed to create test binary: %v", err)
	}

	e := &enricher{sourcePath: filepath.Join("..", "..")}

	t.Run("SPDX_binary_hash", func(t *testing.T) {
		spdxSBOM := `{
			"spdxVersion": "SPDX-2.3",
			"dataLicense": "CC0-1.0",
			"SPDXID": "SPDXRef-DOCUMENT",
			"name": "test-sbom",
			"documentNamespace": "https://example.com/test",
			"packages": [{
				"SPDXID": "SPDXRef-Package-test",
				"name": "test-binary",
				"versionInfo": "1.0.0",
				"filesAnalyzed": false,
				"checksums": []
			}]
		}`

		result, err := e.EnrichWithBinaryHash(spdxSBOM, binaryPath)
		if err != nil {
			t.Fatalf("EnrichWithBinaryHash failed for SPDX: %v", err)
		}

		var sbom map[string]interface{}
		if err := json.Unmarshal([]byte(result), &sbom); err != nil {
			t.Fatalf("Failed to parse result: %v", err)
		}

		packages, ok := sbom["packages"].([]interface{})
		if !ok || len(packages) == 0 {
			t.Fatal("No packages in result")
		}

		foundSHA512 := false
		for _, pkg := range packages {
			pkgMap, ok := pkg.(map[string]interface{})
			if !ok {
				continue
			}
			name, _ := pkgMap["name"].(string)
			if name != "test-binary" {
				continue
			}
			checksums, ok := pkgMap["checksums"].([]interface{})
			if !ok {
				t.Errorf("Package %s has no checksums array", name)
				continue
			}
			t.Logf("Package %s has %d checksums", name, len(checksums))
			for _, cs := range checksums {
				csMap, ok := cs.(map[string]interface{})
				if !ok {
					continue
				}
				alg, _ := csMap["algorithm"].(string)
				val, _ := csMap["checksumValue"].(string)
				t.Logf("  checksum: algorithm=%s value=%s", alg, val[:32]+"...")
				if alg == "SHA512" {
					foundSHA512 = true
				}
			}
		}

		if !foundSHA512 {
			t.Error("❌ SHA-512 hash NOT found in SPDX SBOM")
		} else {
			t.Log("✓ SHA-512 hash found in SPDX SBOM")
		}
	})

	t.Run("CycloneDX_binary_hash", func(t *testing.T) {
		cycloneDXSBOM := `{
			"bomFormat": "CycloneDX",
			"specVersion": "1.5",
			"version": 1,
			"metadata": {
				"component": {
					"type": "application",
					"name": "test-app",
					"version": "1.0.0"
				}
			},
			"components": []
		}`

		result, err := e.EnrichWithBinaryHash(cycloneDXSBOM, binaryPath)
		if err != nil {
			t.Fatalf("EnrichWithBinaryHash failed for CycloneDX: %v", err)
		}

		var sbom map[string]interface{}
		if err := json.Unmarshal([]byte(result), &sbom); err != nil {
			t.Fatalf("Failed to parse result: %v", err)
		}

		metadata, ok := sbom["metadata"].(map[string]interface{})
		if !ok {
			t.Fatal("No metadata in CycloneDX result")
		}
		component, ok := metadata["component"].(map[string]interface{})
		if !ok {
			t.Fatal("No metadata.component in CycloneDX result")
		}

		extRefs, ok := component["externalReferences"].([]interface{})
		if !ok {
			t.Log("No externalReferences — checking raw JSON for SHA-512...")
			raw, _ := json.MarshalIndent(sbom, "", "  ")
			t.Logf("Full output:\n%s", string(raw))
			t.Fatal("❌ No externalReferences on metadata.component")
		}

		foundSHA512 := false
		for _, ref := range extRefs {
			refMap, ok := ref.(map[string]interface{})
			if !ok {
				continue
			}
			refType, _ := refMap["type"].(string)
			if refType == "distribution" {
				hashes, ok := refMap["hashes"].([]interface{})
				if !ok {
					continue
				}
				for _, h := range hashes {
					hMap, ok := h.(map[string]interface{})
					if !ok {
						continue
					}
					alg, _ := hMap["alg"].(string)
					content, _ := hMap["content"].(string)
					t.Logf("  hash: alg=%s content=%s", alg, content[:32]+"...")
					if alg == "SHA-512" {
						foundSHA512 = true
					}
				}
			}
		}

		if !foundSHA512 {
			t.Error("❌ SHA-512 hash NOT found in CycloneDX SBOM")
		} else {
			t.Log("✓ SHA-512 hash found in CycloneDX SBOM")
		}
	})

	t.Run("ArtifactHashes_directory", func(t *testing.T) {
		artifactDir := filepath.Join(tmpDir, "artifacts")
		if err := os.MkdirAll(artifactDir, 0755); err != nil {
			t.Fatal(err)
		}
		os.WriteFile(filepath.Join(artifactDir, "app-server"), []byte("binary content 1"), 0755)
		os.WriteFile(filepath.Join(artifactDir, "app-worker"), []byte("binary content 2"), 0755)
		os.WriteFile(filepath.Join(artifactDir, "readme.txt"), []byte("not a binary"), 0644)

		sbomData := map[string]interface{}{
			"spdxVersion": "SPDX-2.3",
			"packages": []interface{}{
				map[string]interface{}{
					"SPDXID":        "SPDXRef-Package-server",
					"name":          "app-server",
					"versionInfo":   "1.0.0",
					"filesAnalyzed": false,
				},
				map[string]interface{}{
					"SPDXID":        "SPDXRef-Package-worker",
					"name":          "app-worker",
					"versionInfo":   "1.0.0",
					"filesAnalyzed": false,
				},
			},
		}

		err := e.EnrichWithArtifactHashes(sbomData, artifactDir)
		if err != nil {
			t.Fatalf("EnrichWithArtifactHashes failed: %v", err)
		}

		packages, ok := sbomData["packages"].([]interface{})
		if !ok {
			t.Fatal("No packages after enrichment")
		}

		shaCount := 0
		for _, pkg := range packages {
			pkgMap, ok := pkg.(map[string]interface{})
			if !ok {
				continue
			}
			name, _ := pkgMap["name"].(string)
			checksums, ok := pkgMap["checksums"].([]interface{})
			if !ok {
				t.Logf("Package %s: no checksums", name)
				continue
			}
			for _, cs := range checksums {
				csMap, ok := cs.(map[string]interface{})
				if !ok {
					continue
				}
				alg, _ := csMap["algorithm"].(string)
				val, _ := csMap["checksumValue"].(string)
				if alg == "SHA512" {
					shaCount++
					t.Logf("✓ Package %s: SHA-512 = %s...", name, val[:32])
				}
			}
		}

		if shaCount == 0 {
			t.Error("❌ No SHA-512 hashes injected from artifact directory")
		} else {
			t.Logf("SHA-512 hashes injected: %d artifacts", shaCount)
		}
	})
}
