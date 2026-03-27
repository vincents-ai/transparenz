package bsi

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/anchore/syft/syft/license"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
)

// Enricher provides BSI TR-03183-2 compliance enrichment for SBOMs
type Enricher struct {
	sourcePath string
}

// NewEnricher creates a new BSI enricher
func NewEnricher(sourcePath string) *Enricher {
	return &Enricher{sourcePath: sourcePath}
}

// EnrichSBOM enriches an SBOM with hashes, licenses, and suppliers
func (e *Enricher) EnrichSBOM(sbomJSON string) (string, error) {
	var sbomData map[string]interface{}
	if err := json.Unmarshal([]byte(sbomJSON), &sbomData); err != nil {
		return "", fmt.Errorf("failed to parse SBOM: %w", err)
	}

	// Determine format
	format := "SPDX"
	if bomFormat, ok := sbomData["bomFormat"].(string); ok && bomFormat == "CycloneDX" {
		format = "CycloneDX"
	}

	// Enrich based on format
	if format == "SPDX" {
		if err := e.enrichSPDX(sbomData); err != nil {
			return "", err
		}
	} else {
		if err := e.enrichCycloneDX(sbomData); err != nil {
			return "", err
		}
	}

	// Marshal back to JSON
	enriched, err := json.MarshalIndent(sbomData, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal enriched SBOM: %w", err)
	}

	return string(enriched), nil
}

// EnrichSBOMModel enriches an SBOM model with hashes, licenses, and suppliers
// This method works directly with Syft's native SBOM structures for better performance
func (e *Enricher) EnrichSBOMModel(sbomModel *sbom.SBOM) (*sbom.SBOM, error) {
	if sbomModel == nil {
		return nil, fmt.Errorf("sbomModel cannot be nil")
	}

	// Load go.sum for hash enrichment
	goSumHashes := e.loadGoSum()

	// Iterate through all packages in the SBOM
	packages := sbomModel.Artifacts.Packages.Sorted()

	// Create new package collection for enriched packages
	enrichedPackages := pkg.NewCollection()

	for _, p := range packages {
		// Hash enrichment for Go modules
		if p.Type == pkg.GoModulePkg {
			key := p.Name + "@" + p.Version
			if hash, ok := goSumHashes[key]; ok {
				// Check if metadata is GolangModuleEntry
				switch meta := p.Metadata.(type) {
				case pkg.GolangModuleEntry:
					// Update H1Digest if not already set
					if meta.H1Digest == "" {
						meta.H1Digest = hash
						p.Metadata = meta
					}
				default:
					// Create new GolangModuleEntry with hash
					p.Metadata = pkg.GolangModuleEntry{
						H1Digest: hash,
					}
				}
			}
		}

		// License enrichment - add license if not present or empty
		if p.Licenses.Empty() {
			if licenseValue := e.detectLicense(p.Name); licenseValue != "" {
				// Create new license and add to package
				newLicense := pkg.NewLicenseFromType(licenseValue, license.Declared)
				p.Licenses.Add(newLicense)
			}
		}

		// Supplier enrichment - store in PURL qualifiers or CPE vendor
		// Note: Syft doesn't have a direct "Supplier" field in Package struct
		// We'll add it as metadata comment or skip for native model
		// The supplier info is better suited for format-specific encoding

		// Add enriched package to new collection
		enrichedPackages.Add(p)
	}

	// Replace packages in SBOM
	sbomModel.Artifacts.Packages = enrichedPackages

	return sbomModel, nil
}

// enrichSPDX enriches SPDX format SBOMs
func (e *Enricher) enrichSPDX(sbomData map[string]interface{}) error {
	packages, ok := sbomData["packages"].([]interface{})
	if !ok {
		return fmt.Errorf("invalid SPDX format: missing packages")
	}

	// Load go.sum for hash enrichment
	goSumHashes := e.loadGoSum()

	for i, pkgData := range packages {
		pkg, ok := pkgData.(map[string]interface{})
		if !ok {
			continue
		}

		name := getString(pkg, "name")
		version := getString(pkg, "versionInfo")

		// Hash enrichment
		if checksums, ok := pkg["checksums"].([]interface{}); !ok || len(checksums) == 0 {
			// Try to find hash from go.sum
			if hash, ok := goSumHashes[name+"@"+version]; ok {
				pkg["checksums"] = []interface{}{
					map[string]interface{}{
						"algorithm":     "SHA256",
						"checksumValue": hash,
					},
				}
			}
		}

		// License enrichment
		if licenseConcluded := getString(pkg, "licenseConcluded"); licenseConcluded == "" || licenseConcluded == "NOASSERTION" {
			if license := e.detectLicense(name); license != "" {
				pkg["licenseConcluded"] = license
			}
		}

		// Supplier enrichment
		if supplier := getString(pkg, "supplier"); supplier == "" || supplier == "NOASSERTION" {
			if sup := e.detectSupplier(name); sup != "" {
				pkg["supplier"] = fmt.Sprintf("Organization: %s", sup)
			}
		}

		packages[i] = pkg
	}

	sbomData["packages"] = packages
	return nil
}

// enrichCycloneDX enriches CycloneDX format SBOMs
func (e *Enricher) enrichCycloneDX(sbomData map[string]interface{}) error {
	components, ok := sbomData["components"].([]interface{})
	if !ok {
		return fmt.Errorf("invalid CycloneDX format: missing components")
	}

	goSumHashes := e.loadGoSum()

	for i, compData := range components {
		comp, ok := compData.(map[string]interface{})
		if !ok {
			continue
		}

		name := getString(comp, "name")
		version := getString(comp, "version")

		// Hash enrichment
		if hashes, ok := comp["hashes"].([]interface{}); !ok || len(hashes) == 0 {
			if hash, ok := goSumHashes[name+"@"+version]; ok {
				comp["hashes"] = []interface{}{
					map[string]interface{}{
						"alg":     "SHA-256",
						"content": hash,
					},
				}
			}
		}

		// License enrichment
		if licenses, ok := comp["licenses"].([]interface{}); !ok || len(licenses) == 0 {
			if license := e.detectLicense(name); license != "" {
				comp["licenses"] = []interface{}{
					map[string]interface{}{
						"license": map[string]interface{}{
							"id": license,
						},
					},
				}
			}
		}

		// Supplier enrichment
		if supplier := getString(comp, "supplier"); supplier == "" {
			if sup := e.detectSupplier(name); sup != "" {
				comp["supplier"] = map[string]interface{}{
					"name": sup,
				}
			}
		}

		components[i] = comp
	}

	sbomData["components"] = components
	return nil
}

// loadGoSum loads hashes from go.sum file
func (e *Enricher) loadGoSum() map[string]string {
	hashes := make(map[string]string)

	goSumPath := filepath.Join(e.sourcePath, "go.sum")
	file, err := os.Open(goSumPath)
	if err != nil {
		return hashes
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Fields(line)
		if len(parts) >= 3 {
			// Format: module version hash
			module := parts[0]
			version := parts[1]
			hash := strings.TrimPrefix(parts[2], "h1:")

			key := module + "@" + version
			hashes[key] = hash
		}
	}

	return hashes
}

// detectLicense attempts to detect license from well-known patterns
func (e *Enricher) detectLicense(packageName string) string {
	// Well-known Go packages
	knownLicenses := map[string]string{
		"github.com/spf13/cobra":   "Apache-2.0",
		"github.com/google/uuid":   "BSD-3-Clause",
		"gorm.io/gorm":             "MIT",
		"gorm.io/driver/postgres":  "MIT",
		"github.com/jackc/pgx":     "MIT",
		"golang.org/x/crypto":      "BSD-3-Clause",
		"golang.org/x/text":        "BSD-3-Clause",
		"golang.org/x/sync":        "BSD-3-Clause",
		"github.com/anchore/syft":  "Apache-2.0",
		"github.com/anchore/grype": "Apache-2.0",
	}

	// Check for exact match
	if license, ok := knownLicenses[packageName]; ok {
		return license
	}

	// Check for prefix match (handles subpackages)
	for pkg, license := range knownLicenses {
		if strings.HasPrefix(packageName, pkg) {
			return license
		}
	}

	return ""
}

// detectSupplier attempts to detect supplier from package name
func (e *Enricher) detectSupplier(packageName string) string {
	suppliers := map[string]string{
		"github.com/spf13":       "Steve Francia",
		"github.com/google":      "Google LLC",
		"gorm.io":                "GORM Team",
		"github.com/jackc":       "Jack Christensen",
		"golang.org/x":           "The Go Authors",
		"github.com/anchore":     "Anchore Inc",
		"github.com/deutschland": "Deutschland-Stack",
	}

	for prefix, supplier := range suppliers {
		if strings.HasPrefix(packageName, prefix) {
			return supplier
		}
	}

	return ""
}

// calculateFileHash calculates SHA-256 hash of a file
func calculateFileHash(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", err
	}

	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// getString safely extracts string value from map
func getString(m map[string]interface{}, key string) string {
	if val, ok := m[key].(string); ok {
		return val
	}
	return ""
}
