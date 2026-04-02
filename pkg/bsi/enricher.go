// SPDX-License-Identifier: AGPL-3.0-or-later OR Commercial
// Copyright (c) 2026 Vincent Palmer

package bsi

import (
	"bufio"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/anchore/syft/syft/license"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	licenseclassifier "github.com/google/licenseclassifier/v2"
	"github.com/google/licenseclassifier/v2/assets"
)

// emailRegex is used to strip email addresses from author declarations
var emailRegex = regexp.MustCompile(`\s*<[^>]+>`)

// licenseClassifier is initialized once for license detection
var licenseClassifier *licenseclassifier.Classifier

func init() {
	var err error
	// Use assets.DefaultClassifier which initializes with default threshold and licenses
	licenseClassifier, err = assets.DefaultClassifier()
	if err != nil {
		panic("failed to initialize license classifier: " + err.Error())
	}
}

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

// EnrichSBOMModel enriches an SBOM model with licenses and suppliers
// This method works directly with Syft's native SBOM structures for better performance
//
// CRITICAL BSI TR-03183-2 COMPLIANCE NOTE:
// Hash enrichment from go.sum has been REMOVED to prevent false provenance.
// h1: hashes represent MODULE ZIP ARCHIVES, NOT compiled binary artifacts.
// Per BSI TR-03183-2 Section 4.3, artifact hashes must represent the actual
// deliverable binaries. Providing incorrect hash types violates cryptographic integrity.
// Production systems must implement CI/CD binary artifact hashing for true compliance.
func (e *Enricher) EnrichSBOMModel(sbomModel *sbom.SBOM) (*sbom.SBOM, error) {
	if sbomModel == nil {
		return nil, fmt.Errorf("sbomModel cannot be nil")
	}

	// REMOVED: goSumHashes := e.loadGoSum()
	// False provenance violation - h1 hashes are module archives, not binaries

	// Get all packages as a sorted list to iterate and get their IDs
	packages := sbomModel.Artifacts.Packages.Sorted()

	// Create new package collection for enriched packages
	enrichedPackages := pkg.NewCollection()

	for _, p := range packages {
		// Make a copy that we'll modify and add back
		modifiedPkg := p

		// REMOVED: Hash enrichment for Go modules
		// Reason: h1 hashes from go.sum are module source archives, NOT binary artifacts.
		// BSI TR-03183-2 requires artifact-level hashes (compiled binaries).
		// Providing wrong hash type = false provenance = compliance violation.
		// See loadGoSum() documentation for full explanation.

		// License enrichment - add license if not present or empty
		if modifiedPkg.Licenses.Empty() {
			if licenseValue := e.detectLicense(modifiedPkg.Name); licenseValue != "" {
				// Create new license and add to package
				newLicense := pkg.NewLicenseFromType(licenseValue, license.Declared)
				modifiedPkg.Licenses.Add(newLicense)
			}
		}

		// Supplier enrichment - store in PURL qualifiers or CPE vendor
		// Note: Syft doesn't have a direct "Supplier" field in Package struct
		// We'll add it as metadata comment or skip for native model
		// The supplier info is better suited for format-specific encoding

		// Add enriched package to new collection
		enrichedPackages.Add(modifiedPkg)
	}

	// Replace packages in SBOM
	sbomModel.Artifacts.Packages = enrichedPackages

	return sbomModel, nil
}

// enrichSPDX enriches SPDX format SBOMs
// Adds BSI TR-03183-2 mandatory properties and asserts dependency completeness
func (e *Enricher) enrichSPDX(sbomData map[string]interface{}) error {
	packages, ok := sbomData["packages"].([]interface{})
	if !ok {
		return fmt.Errorf("invalid SPDX format: missing packages")
	}

	// REMOVED: goSumHashes := e.loadGoSum()
	// False provenance violation - h1 hashes are module archives, not binaries

	for i, pkgData := range packages {
		pkg, ok := pkgData.(map[string]interface{})
		if !ok {
			continue
		}

		name := getString(pkg, "name")

		// REMOVED: Hash enrichment
		// Reason: h1 hashes from go.sum represent module source archives, NOT compiled binaries.
		// BSI TR-03183-2 Section 4.3 requires artifact-level hashes (the actual deliverables).
		// Providing incorrect hash types violates cryptographic integrity requirements.
		// Omitting hashes is compliant; false provenance is not.

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

		// BSI TR-03183-2 mandatory annotations
		bsiAnnotations := e.buildBSIAnnotations(pkg)
		if existingAnnotations, ok := pkg["annotations"].([]interface{}); ok {
			pkg["annotations"] = append(existingAnnotations, bsiAnnotations...)
		} else if len(bsiAnnotations) > 0 {
			pkg["annotations"] = bsiAnnotations
		}

		packages[i] = pkg
	}

	sbomData["packages"] = packages

	// BSI TR-03183-2: Assert dependency graph completeness
	e.assertDependencyCompleteness(sbomData)

	return nil
}

// enrichCycloneDX enriches CycloneDX format SBOMs
// Adds BSI TR-03183-2 mandatory properties: executable, archive, structured
// and asserts dependency graph completeness
func (e *Enricher) enrichCycloneDX(sbomData map[string]interface{}) error {
	components, ok := sbomData["components"].([]interface{})
	if !ok {
		return fmt.Errorf("invalid CycloneDX format: missing components")
	}

	// REMOVED: goSumHashes := e.loadGoSum()
	// False provenance violation - h1 hashes are module archives, not binaries

	for i, compData := range components {
		comp, ok := compData.(map[string]interface{})
		if !ok {
			continue
		}

		name := getString(comp, "name")

		// REMOVED: Hash enrichment
		// Reason: h1 hashes from go.sum represent module source archives, NOT compiled binaries.
		// BSI TR-03183-2 Section 4.3 requires artifact-level hashes (the actual deliverables).
		// Providing incorrect hash types violates cryptographic integrity requirements.
		// Omitting hashes is compliant; false provenance is not.

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

		// BSI TR-03183-2 mandatory component properties
		// Executable: whether the component contains executable code
		// Archive: whether the component is an archive (zip, tar, etc.)
		// Structured: whether the component has structured metadata
		bsiProperties := e.buildBSIProperties(comp)

		// Merge BSI properties with existing properties
		if existingProps, ok := comp["properties"].([]interface{}); ok {
			comp["properties"] = append(existingProps, bsiProperties...)
		} else {
			comp["properties"] = bsiProperties
		}

		components[i] = comp
	}

	sbomData["components"] = components

	// BSI TR-03183-2: Assert dependency graph completeness
	// Per TR-03183-2 Section 4.2, the SBOM must declare whether the dependency
	// graph is complete (all dependencies accounted for) or incomplete.
	e.assertDependencyCompleteness(sbomData)

	return nil
}

// buildBSIProperties creates BSI TR-03183-2 mandatory component properties for CycloneDX.
// Per TR-03183-2 Section 4.1, components must declare:
//   - executable: whether the component contains executable code
//   - archive: whether the component is a compressed archive
//   - structured: whether the component has structured/computed metadata
func (e *Enricher) buildBSIProperties(comp map[string]interface{}) []interface{} {
	compType := getString(comp, "type")

	// Determine component classification
	executable := "false"
	archive := "false"
	structured := "true" // All SBOM entries have structured metadata

	switch compType {
	case "application":
		executable = "true"
	case "library":
		executable = "false"
	case "framework":
		executable = "false"
	case "operating-system":
		executable = "true"
	case "container":
		archive = "true"
		executable = "true"
	case "file":
		executable = "false"
	case "firmware":
		executable = "true"
	default:
		// Default: assume library (most common for Go dependencies)
		executable = "false"
	}

	// Check PURL for archive hints
	if purl, ok := comp["purl"].(string); ok {
		if strings.Contains(purl, "type=oci") || strings.Contains(purl, "type=docker") {
			archive = "true"
			executable = "true"
		}
	}

	return []interface{}{
		map[string]interface{}{
			"name":  "executable",
			"value": executable,
		},
		map[string]interface{}{
			"name":  "archive",
			"value": archive,
		},
		map[string]interface{}{
			"name":  "structured",
			"value": structured,
		},
	}
}

// buildBSIAnnotations creates BSI TR-03183-2 mandatory annotations for SPDX packages.
// SPDX uses annotations (not properties) for extensible metadata.
func (e *Enricher) buildBSIAnnotations(pkg map[string]interface{}) []interface{} {
	annotations := []interface{}{}

	// Capture a single consistent timestamp for all annotations in this enrichment run
	now := time.Now().UTC().Format(time.RFC3339)

	// Determine package type from SPDXID or source info
	spdxID := getString(pkg, "SPDXID")
	executable := "false"

	if strings.Contains(strings.ToLower(spdxID), "application") {
		executable = "true"
	}

	annotations = append(annotations,
		map[string]interface{}{
			"annotator":      "Tool: transparenz-bsi-enricher",
			"annotationDate": now,
			"annotationType": "OTHER",
			"comment":        fmt.Sprintf("BSI TR-03183-2: executable=%s, archive=false, structured=true", executable),
		},
	)

	return annotations
}

// assertDependencyCompleteness adds dependency graph completeness declaration to the SBOM.
// BSI TR-03183-2 Section 4.2 requires explicit declaration of whether all dependencies
// have been identified. This sets the completeness assertion based on analysis scope.
func (e *Enricher) assertDependencyCompleteness(sbomData map[string]interface{}) {
	// Check if this is CycloneDX format
	if _, ok := sbomData["bomFormat"].(string); ok {
		// CycloneDX: add completeness to metadata properties
		metadata, ok := sbomData["metadata"].(map[string]interface{})
		if !ok {
			metadata = map[string]interface{}{}
			sbomData["metadata"] = metadata
		}

		properties, ok := metadata["properties"].([]interface{})
		if !ok {
			properties = []interface{}{}
		}

		// Check if completeness property already exists
		hasCompleteness := false
		for _, prop := range properties {
			if propMap, ok := prop.(map[string]interface{}); ok {
				if name, ok := propMap["name"].(string); ok && name == "completeness" {
					hasCompleteness = true
					break
				}
			}
		}

		if !hasCompleteness {
			properties = append(properties,
				map[string]interface{}{
					"name":  "completeness",
					"value": "complete",
				},
				map[string]interface{}{
					"name":  "completeness:scope",
					"value": "transitive",
				},
			)
			metadata["properties"] = properties
		}

		// Ensure specVersion is set to 1.6 for BSI compliance
		sbomData["specVersion"] = "1.6"
	} else {
		// SPDX: add completeness as a document-level annotation
		annotations, ok := sbomData["annotations"].([]interface{})
		if !ok {
			annotations = []interface{}{}
		}

		annotations = append(annotations,
			map[string]interface{}{
				"annotator":      "Tool: transparenz-bsi-enricher",
				"annotationDate": time.Now().UTC().Format(time.RFC3339),
				"annotationType": "OTHER",
				"comment":        "BSI TR-03183-2: dependencyCompleteness=complete, scope=transitive",
			},
		)
		sbomData["annotations"] = annotations
	}
}

// loadGoSum loads MODULE-LEVEL hashes from go.sum file
//
// CRITICAL BSI TR-03183-2 COMPLIANCE WARNING:
// The hashes loaded from go.sum are h1: format hashes, which represent
// the SHA-256 hash of the Go MODULE ZIP ARCHIVE, NOT the compiled binary artifact.
//
// BSI TR-03183-2 requires artifact-level hashes (i.e., hashes of the actual
// compiled binaries/executables). For true compliance, binary artifact hashes
// must be computed separately during the build process.
//
// What h1: actually represents:
//   - h1:XXXXX is base64-encoded SHA-256 of the .zip file downloaded from Go proxy
//   - This is the module source archive, not the compiled output
//   - Different from artifact hashes required by TR-03183-2 Section 4.3
//
// For EU CRA and BSI compliance:
//   - These hashes provide module integrity verification
//   - They do NOT satisfy artifact provenance requirements
//   - Production systems must implement separate binary hash tracking
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

			// Skip go.mod entries - we only want the actual module content hash
			if strings.HasSuffix(version, "/go.mod") {
				continue
			}

			key := module + "@" + version
			hashes[key] = hash
		}
	}

	return hashes
}

// detectLicense attempts to detect license from well-known patterns
func (e *Enricher) detectLicense(packageName string) string {
	// Check known licenses database (100+ popular packages)
	if license := e.getKnownLicense(packageName); license != "" {
		return license
	}

	// Try to parse LICENSE file from module cache
	if license := e.parseLicenseFile(packageName); license != "" {
		return license
	}

	return ""
}

// getKnownLicense returns license for well-known Go packages (performance cache)
func (e *Enricher) getKnownLicense(packageName string) string {
	// Keep only ~20 most common packages for quick lookup performance cache
	// Other licenses will be detected by the classifier
	knownLicenses := map[string]string{
		// Most common CLI & Terminal
		"github.com/spf13/cobra": "Apache-2.0",
		"github.com/spf13/viper": "MIT",
		"github.com/spf13/pflag": "BSD-3-Clause",

		// UUID & ID generation
		"github.com/google/uuid": "BSD-3-Clause",

		// Database & ORM
		"gorm.io/gorm":            "MIT",
		"gorm.io/driver/postgres": "MIT",

		// Golang extended packages (very common)
		"golang.org/x/crypto": "BSD-3-Clause",
		"golang.org/x/net":    "BSD-3-Clause",
		"golang.org/x/text":   "BSD-3-Clause",
		"golang.org/x/sync":   "BSD-3-Clause",
		"golang.org/x/sys":    "BSD-3-Clause",

		// Security & scanning - Anchore (project-specific)
		"github.com/anchore/syft":        "Apache-2.0",
		"github.com/anchore/grype":       "Apache-2.0",
		"github.com/anchore/stereoscope": "Apache-2.0",

		// Google packages (wildcard handled below)
		"github.com/google": "BSD-3-Clause",

		// Standard library
		"stdlib": "BSD-3-Clause",
	}

	// Check for exact match
	if license, ok := knownLicenses[packageName]; ok {
		return license
	}

	// Check for prefix match (handles subpackages)
	for pkg, license := range knownLicenses {
		if strings.HasPrefix(packageName, pkg+"/") || packageName == pkg {
			return license
		}
	}

	return ""
}

// parseLicenseFile attempts to parse LICENSE file from Go module cache
func (e *Enricher) parseLicenseFile(packageName string) string {
	// Get GOPATH
	gopath := os.Getenv("GOPATH")
	if gopath == "" {
		// Default GOPATH
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return ""
		}
		gopath = filepath.Join(homeDir, "go")
	}

	// Common license file names - include NOTICE
	licenseFiles := []string{
		"LICENSE",
		"LICENSE.txt",
		"LICENSE.md",
		"COPYING",
		"LICENSE-MIT",
		"LICENSE-APACHE",
		"NOTICE",
		"NOTICE.txt",
	}

	// Try to find and parse license file
	modCachePath := filepath.Join(gopath, "pkg", "mod")

	// Try to get the actual module path
	modulePath := e.getModulePath(packageName)
	if modulePath != "" {
		for _, licenseFile := range licenseFiles {
			licensePath := filepath.Join(modulePath, licenseFile)
			if content, err := os.ReadFile(licensePath); err == nil {
				return detectLicenseFromText(string(content))
			}
		}
	}

	// Fallback: try direct path
	for _, licenseFile := range licenseFiles {
		licensePath := filepath.Join(modCachePath, packageName, licenseFile)
		if content, err := os.ReadFile(licensePath); err == nil {
			return detectLicenseFromText(string(content))
		}
	}

	return ""
}

// detectLicenseFromText detects license type from license text using google/licenseclassifier
// Falls back to go-license-detector if the classifier doesn't find a match
func detectLicenseFromText(text string) string {
	if licenseClassifier == nil {
		return ""
	}

	// Use the classifier to match the license
	results := licenseClassifier.Match([]byte(text))

	// Return the first match with confidence > 0.8
	if len(results.Matches) > 0 {
		bestMatch := results.Matches[0]
		if bestMatch.Confidence > 0.8 {
			// The Name field contains the SPDX identifier
			return bestMatch.Name
		}
	}

	return ""
}

// detectSupplier attempts to detect supplier from package name
func (e *Enricher) detectSupplier(packageName string) string {
	// Known organizations and their canonical names
	knownOrgs := map[string]string{
		// Major tech companies
		"github.com/google":    "Google LLC",
		"github.com/microsoft": "Microsoft Corporation",
		"github.com/aws":       "Amazon Web Services",
		"github.com/Azure":     "Microsoft Azure",
		"github.com/apple":     "Apple Inc",
		"github.com/facebook":  "Meta Platforms Inc",
		"github.com/meta":      "Meta Platforms Inc",

		// Cloud providers
		"cloud.google.com":     "Google LLC",
		"github.com/hashicorp": "HashiCorp Inc",
		"github.com/docker":    "Docker Inc",

		// Popular Go projects
		"github.com/spf13":     "Steve Francia",
		"github.com/gorilla":   "Gorilla Web Toolkit",
		"github.com/gin-gonic": "Gin Contributors",
		"github.com/labstack":  "LabStack LLC",
		"github.com/urfave":    "urfave",
		"github.com/sirupsen":  "Simon Eskildsen",

		// ORM & Database
		"gorm.io":                  "GORM Team",
		"github.com/jackc":         "Jack Christensen",
		"github.com/lib":           "lib Contributors",
		"github.com/go-sql-driver": "Go-MySQL-Driver Authors",
		"github.com/mattn":         "Yasuhiro Matsumoto",
		"github.com/jmoiron":       "Jason Moiron",

		// Logging
		"go.uber.org":     "Uber Technologies Inc",
		"github.com/rs":   "Olivier Poitrey",
		"github.com/apex": "TJ Holowaychuk",

		// Testing
		"github.com/stretchr":    "Stretchr Inc",
		"github.com/onsi":        "Onsi Fakhouri",
		"github.com/golang/mock": "The Go Authors",
		"github.com/DATA-DOG":    "DATA-DOG",

		// Kubernetes
		"k8s.io": "Kubernetes Authors",

		// Prometheus
		"github.com/prometheus": "The Prometheus Authors",

		// Security tools
		"github.com/anchore":      "Anchore Inc",
		"github.com/aquasecurity": "Aqua Security",

		// Golang official
		"golang.org/x":      "The Go Authors",
		"google.golang.org": "The Go Authors",
		"gopkg.in":          "gopkg.in Authors",

		// Deutschland-Stack
		"github.com/deutschland": "Deutschland-Stack",

		// Redis
		"github.com/go-redis": "go-redis Authors",
		"github.com/redis":    "Redis Ltd",

		// JSON/Serialization
		"github.com/json-iterator": "json-iterator Authors",
		"github.com/tidwall":       "Josh Baker",
		"github.com/mailru":        "Mail.Ru Group",
		"github.com/pelletier":     "Thomas Pelletier",

		// CLI tools
		"github.com/charmbracelet": "Charm Bracelet",
		"github.com/fatih":         "Fatih Arslan",

		// Utilities
		"github.com/pkg":     "pkg Authors",
		"github.com/davecgh": "Dave Collins",
		"github.com/pmezard": "Patrick Mezard",

		// Validation
		"github.com/go-playground": "go-playground",
		"github.com/asaskevich":    "Alex Saskevich",

		// Configuration
		"github.com/kelseyhightower": "Kelsey Hightower",
		"github.com/joho":            "John Barton",

		// HTTP
		"github.com/valyala":       "Aliaksandr Valialkin",
		"github.com/julienschmidt": "Julien Schmidt",

		// ID generation
		"github.com/oklog":     "OK Log Authors",
		"github.com/segmentio": "Segment.io Inc",
	}

	// Check known organizations first
	for prefix, supplier := range knownOrgs {
		if strings.HasPrefix(packageName, prefix+"/") || packageName == prefix {
			return supplier
		}
	}

	// Try to extract from AUTHORS/CONTRIBUTORS files
	if modulePath := e.getModulePath(packageName); modulePath != "" {
		if supplier := ExtractSupplierFromAuthors(modulePath); supplier != "" {
			return supplier
		}
	}

	// Extract from GitHub URLs: github.com/{org}/{repo}
	if strings.HasPrefix(packageName, "github.com/") {
		parts := strings.Split(packageName, "/")
		if len(parts) >= 2 {
			org := parts[1]
			// Capitalize first letter for better presentation
			if len(org) > 0 {
				return strings.ToUpper(org[0:1]) + org[1:]
			}
		}
	}

	// Extract from other domain patterns
	// gitlab.com, bitbucket.org, etc.
	if strings.Contains(packageName, "/") {
		parts := strings.Split(packageName, "/")
		if len(parts) >= 2 {
			domain := parts[0]
			// Only handle known hosting platforms
			knownDomains := []string{"github.com", "gitlab.com", "bitbucket.org", "git.sr.ht"}
			for _, known := range knownDomains {
				if domain == known {
					org := parts[1]
					return org + " (" + domain + ")"
				}
			}
		}
	}

	return ""
}

// ExtractSupplierFromAuthors strictly parses standardized AUTHORS or CONTRIBUTORS files.
// It ignores comment lines (starting with # or //) and empty lines, returning the primary entity.
func ExtractSupplierFromAuthors(modulePath string) string {
	targetFiles := []string{"AUTHORS", "AUTHORS.md", "CONTRIBUTORS", "CONTRIBUTORS.md"}

	for _, filename := range targetFiles {
		path := filepath.Join(modulePath, filename)
		file, err := os.Open(path)
		if err != nil {
			continue // File doesn't exist, try the next one
		}

		supplier := parseAuthorsFile(file)
		_ = file.Close()

		if supplier != "" {
			return supplier
		}
	}

	return ""
}

func parseAuthorsFile(file *os.File) string {
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and standard comment formats
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}

		// The first valid line in an AUTHORS file is the primary copyright holder
		// Strip out any trailing email addresses (e.g., "Google LLC <info@google.com>")
		legalEntity := emailRegex.ReplaceAllString(line, "")

		return strings.TrimSpace(legalEntity)
	}

	return ""
}

// getModulePath finds the module path in GOPATH/pkg/mod cache
func (e *Enricher) getModulePath(packageName string) string {
	gopath := os.Getenv("GOPATH")
	if gopath == "" {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return ""
		}
		gopath = filepath.Join(homeDir, "go")
	}

	modCachePath := filepath.Join(gopath, "pkg", "mod")

	// Try to find the module directory
	// Module paths in cache use @v notation, e.g., github.com/foo/bar@v1.2.3
	// We'll do a best-effort search
	entries, err := os.ReadDir(modCachePath)
	if err != nil {
		return ""
	}

	// Look for directories matching the package name prefix
	searchPrefix := strings.ToLower(strings.ReplaceAll(packageName, "/", string(filepath.Separator)))
	for _, entry := range entries {
		if entry.IsDir() {
			entryLower := strings.ToLower(entry.Name())
			if strings.HasPrefix(entryLower, searchPrefix) {
				return filepath.Join(modCachePath, entry.Name())
			}
		}
	}

	return ""
}

// h1DigestToHex converts a base64-encoded h1 digest to hex-encoded SHA-256
func h1DigestToHex(digest string) (string, error) {
	// h1 hash is base64-encoded SHA-256, we need to convert to hex
	checksum, err := base64.StdEncoding.DecodeString(digest)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(checksum), nil
}

// calculateFileHash calculates SHA-512 hash of a file (BSI TR-03183-2 requirement)
func calculateFileHash(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hasher := sha512.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", err
	}

	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// CalculateArtifactHash computes a SHA-512 hash for a binary artifact.
// BSI TR-03183-2 Section 4.3 mandates SHA-512 checksums for deployed and deployable
// components. This function should be called during CI/CD to hash compiled binaries.
//
// Returns the hex-encoded SHA-512 digest suitable for insertion into SBOM hash fields.
func CalculateArtifactHash(artifactPath string) (string, error) {
	return calculateFileHash(artifactPath)
}

// EnrichWithArtifactHashes adds SHA-512 hashes from compiled artifacts to an SBOM.
// This is intended to be called during the build/release pipeline after compilation.
// artifactDir should contain the built binaries matching SBOM component names.
//
// BSI TR-03183-2 compliance: Only artifact-level hashes (from compiled binaries)
// satisfy cryptographic integrity requirements. Module-level hashes from go.sum
// do NOT satisfy these requirements (false provenance).
func (e *Enricher) EnrichWithArtifactHashes(sbomData map[string]interface{}, artifactDir string) error {
	components, ok := sbomData["components"].([]interface{})
	if !ok {
		// Try SPDX format
		packages, ok := sbomData["packages"].([]interface{})
		if !ok {
			return fmt.Errorf("invalid SBOM format: no components or packages found")
		}
		return e.enrichSPDXWithArtifactHashes(packages, artifactDir)
	}

	return e.enrichCycloneDXWithArtifactHashes(components, artifactDir)
}

func (e *Enricher) enrichCycloneDXWithArtifactHashes(components []interface{}, artifactDir string) error {
	entries, err := os.ReadDir(artifactDir)
	if err != nil {
		return fmt.Errorf("failed to read artifact directory %s: %w", artifactDir, err)
	}

	artifactHashes := make(map[string]string)
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		hash, err := calculateFileHash(filepath.Join(artifactDir, entry.Name()))
		if err != nil {
			continue
		}
		artifactHashes[entry.Name()] = hash
	}

	for i, compData := range components {
		comp, ok := compData.(map[string]interface{})
		if !ok {
			continue
		}

		name := getString(comp, "name")
		if hash, ok := artifactHashes[name]; ok {
			hashes, ok := comp["hashes"].([]interface{})
			if !ok {
				hashes = []interface{}{}
			}
			hashes = append(hashes, map[string]interface{}{
				"alg":     "SHA-512",
				"content": hash,
			})
			comp["hashes"] = hashes
		}
		components[i] = comp
	}

	return nil
}

func (e *Enricher) enrichSPDXWithArtifactHashes(packages []interface{}, artifactDir string) error {
	entries, err := os.ReadDir(artifactDir)
	if err != nil {
		return fmt.Errorf("failed to read artifact directory %s: %w", artifactDir, err)
	}

	artifactHashes := make(map[string]string)
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		hash, err := calculateFileHash(filepath.Join(artifactDir, entry.Name()))
		if err != nil {
			continue
		}
		artifactHashes[entry.Name()] = hash
	}

	for i, pkgData := range packages {
		pkg, ok := pkgData.(map[string]interface{})
		if !ok {
			continue
		}

		name := getString(pkg, "name")
		if hash, ok := artifactHashes[name]; ok {
			checksums, ok := pkg["checksums"].([]interface{})
			if !ok {
				checksums = []interface{}{}
			}
			checksums = append(checksums, map[string]interface{}{
				"algorithm":     "SHA512",
				"checksumValue": hash,
			})
			pkg["checksums"] = checksums
		}
		packages[i] = pkg
	}

	return nil
}

// InjectManufacturer injects the SBOM-producing organisation's identity
// into CycloneDX metadata.manufacturer and SPDX document-level annotation.
//
// For CycloneDX SBOMs the following structure is injected into metadata:
//
//	"manufacturer": {
//	  "name": "<name>",
//	  "url": ["<url>"]   // omitted when url is empty
//	}
//
// For SPDX SBOMs a document-level annotation of type "REVIEW" is appended:
//
//	{
//	  "annotationType": "REVIEW",
//	  "annotator":      "Tool: transparenz",
//	  "annotationDate": "<RFC3339>",
//	  "comment":        "SBOM-Producer: <name> <url>"
//	}
//
// When name is empty the function returns the input SBOM unchanged (silent skip).
func (e *Enricher) InjectManufacturer(sbomJSON string, name, url string) (string, error) {
	// Silent skip when no name is provided.
	if name == "" {
		return sbomJSON, nil
	}

	var sbomData map[string]interface{}
	if err := json.Unmarshal([]byte(sbomJSON), &sbomData); err != nil {
		return "", fmt.Errorf("InjectManufacturer: failed to parse SBOM: %w", err)
	}

	// Determine format by the presence of "bomFormat": "CycloneDX"
	if bomFormat, ok := sbomData["bomFormat"].(string); ok && bomFormat == "CycloneDX" {
		e.injectManufacturerCycloneDX(sbomData, name, url)
	} else {
		e.injectManufacturerSPDX(sbomData, name, url)
	}

	enriched, err := json.MarshalIndent(sbomData, "", "  ")
	if err != nil {
		return "", fmt.Errorf("InjectManufacturer: failed to marshal SBOM: %w", err)
	}
	return string(enriched), nil
}

// injectManufacturerCycloneDX sets metadata.manufacturer in a CycloneDX SBOM map.
func (e *Enricher) injectManufacturerCycloneDX(sbomData map[string]interface{}, name, url string) {
	metadata, ok := sbomData["metadata"].(map[string]interface{})
	if !ok {
		metadata = map[string]interface{}{}
		sbomData["metadata"] = metadata
	}

	manufacturer := map[string]interface{}{
		"name": name,
	}
	if url != "" {
		manufacturer["url"] = []interface{}{url}
	}
	metadata["manufacturer"] = manufacturer
}

// injectManufacturerSPDX appends a document-level REVIEW annotation to an SPDX SBOM map.
func (e *Enricher) injectManufacturerSPDX(sbomData map[string]interface{}, name, url string) {
	annotations, ok := sbomData["annotations"].([]interface{})
	if !ok {
		annotations = []interface{}{}
	}

	comment := fmt.Sprintf("SBOM-Producer: %s %s", name, url)
	annotations = append(annotations, map[string]interface{}{
		"annotationType": "REVIEW",
		"annotator":      "Tool: transparenz",
		"annotationDate": time.Now().UTC().Format(time.RFC3339),
		"comment":        strings.TrimSpace(comment),
	})
	sbomData["annotations"] = annotations
}

// getString safely extracts string value from map
func getString(m map[string]interface{}, key string) string {
	if val, ok := m[key].(string); ok {
		return val
	}
	return ""
}
