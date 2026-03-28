package cmd

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
)

var (
	bsiOutput string
)

var bsiCmd = &cobra.Command{
	Use:   "bsi-check [sbom-path]",
	Short: "Validate SBOM compliance with BSI TR-03183-2 standard",
	Long: `Check SBOM compliance with BSI TR-03183-2 (Federal Office for Information Security) requirements.

Validates:
  - Hash algorithm (SHA-512 mandatory per BSI TR-03183-2, SHA-256 alone is non-compliant)
  - License coverage (SPDX identifiers for all components)
  - Supplier coverage (supplier/author information for all components)
  - Component properties (executable, archive, structured per TR-03183-2 Section 4.1)
  - Dependency completeness (explicit completeness assertion per TR-03183-2 Section 4.2)
  - Format version (CycloneDX 1.6+ or SPDX 3.0.1+ required for CRA/BSI extensions)

Outputs a compliance report with:
  - Overall compliance percentage
  - Detailed findings by category
  - Remediation suggestions

Example usage:
  transparenz bsi-check sbom.json
  transparenz bsi-check sbom.json --output report.json`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		sbomPath := args[0]

		if verbose {
			fmt.Fprintf(os.Stderr, "Validating BSI TR-03183-2 compliance for: %s\n", sbomPath)
		}

		// Check if SBOM file exists
		if _, err := os.Stat(sbomPath); os.IsNotExist(err) {
			return fmt.Errorf("SBOM file not found: %s", sbomPath)
		}

		// Load SBOM
		data, err := os.ReadFile(sbomPath)
		if err != nil {
			return fmt.Errorf("failed to read SBOM: %w", err)
		}

		// Parse SBOM (assume SPDX JSON for now)
		var sbomData map[string]interface{}
		if err := json.Unmarshal(data, &sbomData); err != nil {
			return fmt.Errorf("failed to parse SBOM JSON: %w", err)
		}

		// Run BSI validation
		report := validateBSICompliance(sbomData)

		// Output report
		outputData, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to format report: %w", err)
		}

		if bsiOutput != "" {
			err = os.WriteFile(bsiOutput, outputData, 0644)
			if err != nil {
				return fmt.Errorf("failed to write output: %w", err)
			}
			if verbose {
				fmt.Fprintf(os.Stderr, "BSI compliance report written to: %s\n", bsiOutput)
			}
		} else {
			fmt.Println(string(outputData))
		}

		// Also print summary to stderr
		fmt.Fprintf(os.Stderr, "\n=== BSI TR-03183-2 Compliance Summary ===\n")
		fmt.Fprintf(os.Stderr, "Overall Compliance: %.1f%%\n", report["overall_score"].(float64))
		fmt.Fprintf(os.Stderr, "Hash Coverage (SHA-512): %.1f%%\n", report["hash_coverage"].(float64))
		fmt.Fprintf(os.Stderr, "License Coverage: %.1f%%\n", report["license_coverage"].(float64))
		fmt.Fprintf(os.Stderr, "Supplier Coverage: %.1f%%\n", report["supplier_coverage"].(float64))
		fmt.Fprintf(os.Stderr, "Component Properties: %.1f%%\n", report["property_coverage"].(float64))
		fmt.Fprintf(os.Stderr, "Dependency Completeness: %v\n", report["dependency_complete"])

		if formatVer, ok := report["format_version"].(string); ok {
			fmt.Fprintf(os.Stderr, "Format Version: %s\n", formatVer)
			if compliant, ok := report["format_compliant"].(bool); ok && !compliant {
				fmt.Fprintf(os.Stderr, "  WARNING: Format version does not meet minimum requirements (CycloneDX 1.6+ or SPDX 3.0.1+)\n")
			}
		}

		if report["compliant"].(bool) {
			fmt.Fprintf(os.Stderr, "Status: ✓ COMPLIANT\n")
		} else {
			fmt.Fprintf(os.Stderr, "Status: ✗ NON-COMPLIANT\n")
		}

		return nil
	},
}

type BSIFinding struct {
	Severity    string `json:"severity"`
	Category    string `json:"category"`
	Message     string `json:"message"`
	Component   string `json:"component"`
	Remediation string `json:"remediation"`
}

func validateBSICompliance(sbomData map[string]interface{}) map[string]interface{} {
	findings := []BSIFinding{}

	// Detect SBOM format and extract components/packages
	var components []interface{}
	var format string

	if packages, ok := sbomData["packages"].([]interface{}); ok {
		// SPDX format
		format = "SPDX"
		components = packages
	} else if comps, ok := sbomData["components"].([]interface{}); ok {
		// CycloneDX format
		format = "CycloneDX"
		components = comps
	} else {
		return map[string]interface{}{
			"error":               "Invalid SBOM format - no packages or components found",
			"compliant":           false,
			"overall_score":       0.0,
			"hash_coverage":       0.0,
			"license_coverage":    0.0,
			"supplier_coverage":   0.0,
			"property_coverage":   0.0,
			"dependency_complete": false,
		}
	}

	totalPackages := len(components)
	hashCount := 0    // Components with SHA-512 (mandatory)
	hashAnyCount := 0 // Components with any hash (SHA-256 or SHA-512)
	licenseCount := 0
	supplierCount := 0
	propertyCount := 0

	// SHA-512 is mandatory per BSI TR-03183-2
	sha512Regex := regexp.MustCompile(`^[a-fA-F0-9]{128}$`)
	sha256Regex := regexp.MustCompile(`^[a-fA-F0-9]{64}$`)

	// Validate format version
	formatCompliant := true
	formatVersion := "unknown"

	if format == "CycloneDX" {
		if specVer, ok := sbomData["specVersion"].(string); ok {
			formatVersion = "CycloneDX " + specVer
			// Check if version is 1.6 or higher
			if !isVersionGTE(specVer, "1.6") {
				formatCompliant = false
				findings = append(findings, BSIFinding{
					Severity:    "CRITICAL",
					Category:    "Format Version",
					Message:     fmt.Sprintf("CycloneDX version %s is below minimum required 1.6", specVer),
					Component:   "SBOM Document",
					Remediation: "Regenerate SBOM with CycloneDX 1.6+ format",
				})
			}
		}
	} else if format == "SPDX" {
		if spdxVer, ok := sbomData["spdxVersion"].(string); ok {
			formatVersion = spdxVer
			// Check if version is 3.0.1 or higher
			verStr := strings.TrimPrefix(spdxVer, "SPDX-")
			if !isVersionGTE(verStr, "3.0.1") {
				formatCompliant = false
				findings = append(findings, BSIFinding{
					Severity:    "CRITICAL",
					Category:    "Format Version",
					Message:     fmt.Sprintf("SPDX version %s is below minimum required 3.0.1 for CRA/BSI extensions", spdxVer),
					Component:   "SBOM Document",
					Remediation: "Regenerate SBOM with SPDX 3.0.1+ format",
				})
			}
		}
	}

	for _, pkg := range components {
		pkgMap, ok := pkg.(map[string]interface{})
		if !ok {
			continue
		}

		// Extract name and version (different field names in SPDX vs CycloneDX)
		pkgName := ""
		pkgVersion := ""

		if format == "SPDX" {
			if name, ok := pkgMap["name"].(string); ok {
				pkgName = name
			}
			if v, ok := pkgMap["versionInfo"].(string); ok {
				pkgVersion = v
			}
		} else {
			// CycloneDX
			if name, ok := pkgMap["name"].(string); ok {
				pkgName = name
			}
			if v, ok := pkgMap["version"].(string); ok {
				pkgVersion = v
			}
		}

		pkgID := fmt.Sprintf("%s@%s", pkgName, pkgVersion)

		// Check SHA-512 hashes (mandatory per BSI TR-03183-2)
		hasSha512 := false
		hasAnyHash := false

		if format == "SPDX" {
			if checksums, ok := pkgMap["checksums"].([]interface{}); ok && len(checksums) > 0 {
				for _, cs := range checksums {
					if csMap, ok := cs.(map[string]interface{}); ok {
						if algorithm, ok := csMap["algorithm"].(string); ok {
							if value, ok := csMap["checksumValue"].(string); ok {
								if algorithm == "SHA512" && sha512Regex.MatchString(value) {
									hasSha512 = true
									hasAnyHash = true
								}
								if algorithm == "SHA256" && sha256Regex.MatchString(value) {
									hasAnyHash = true
								}
							}
						}
					}
				}
			}
		} else {
			// CycloneDX format: "hashes": [{"alg": "SHA-512", "content": "..."}]
			if hashes, ok := pkgMap["hashes"].([]interface{}); ok && len(hashes) > 0 {
				for _, h := range hashes {
					if hMap, ok := h.(map[string]interface{}); ok {
						if alg, ok := hMap["alg"].(string); ok {
							if content, ok := hMap["content"].(string); ok {
								// Check SHA-512
								if alg == "SHA-512" {
									decoded, err := base64.StdEncoding.DecodeString(content)
									if err == nil && sha512Regex.MatchString(hex.EncodeToString(decoded)) {
										hasSha512 = true
										hasAnyHash = true
									}
								}
								// Check SHA-256
								if alg == "SHA-256" {
									decoded, err := base64.StdEncoding.DecodeString(content)
									if err == nil && sha256Regex.MatchString(hex.EncodeToString(decoded)) {
										hasAnyHash = true
									}
								}
							}
						}
					}
				}
			}
		}

		if hasSha512 {
			hashCount++
		} else if hasAnyHash {
			// Has hash but not SHA-512 - still count as having hash but flag issue
			hashAnyCount++
			findings = append(findings, BSIFinding{
				Severity:    "CRITICAL",
				Category:    "Hashes",
				Message:     "Component has hash but lacks SHA-512 (BSI TR-03183-2 mandates SHA-512)",
				Component:   pkgID,
				Remediation: "Compute SHA-512 hash of the artifact and add to SBOM",
			})
		} else {
			findings = append(findings, BSIFinding{
				Severity:    "CRITICAL",
				Category:    "Hashes",
				Message:     "No cryptographic hash found (SHA-512 required per BSI TR-03183-2)",
				Component:   pkgID,
				Remediation: "Run 'transparenz generate --bsi-compliant' to add SHA-512 hashes",
			})
		}

		// Check license
		hasValidLicense := false

		if format == "SPDX" {
			if license, ok := pkgMap["licenseConcluded"].(string); ok && license != "" && license != "NOASSERTION" {
				hasValidLicense = true
			} else if license, ok := pkgMap["licenseDeclared"].(string); ok && license != "" && license != "NOASSERTION" {
				hasValidLicense = true
			}
		} else {
			// CycloneDX: "licenses": [{"license": {"id": "MIT"}}]
			if licenses, ok := pkgMap["licenses"].([]interface{}); ok && len(licenses) > 0 {
				for _, lic := range licenses {
					if licMap, ok := lic.(map[string]interface{}); ok {
						if licData, ok := licMap["license"].(map[string]interface{}); ok {
							if id, ok := licData["id"].(string); ok && id != "" {
								hasValidLicense = true
								break
							}
						}
					}
				}
			}
		}

		if hasValidLicense {
			licenseCount++
		} else {
			findings = append(findings, BSIFinding{
				Severity:    "MEDIUM",
				Category:    "Licenses",
				Message:     "No SPDX license identifier found",
				Component:   pkgID,
				Remediation: "Run 'transparenz generate --bsi-compliant' to detect and normalize licenses",
			})
		}

		// Check supplier/originator
		hasSupplier := false

		if format == "SPDX" {
			if supplier, ok := pkgMap["supplier"].(string); ok && supplier != "" && supplier != "NOASSERTION" {
				hasSupplier = true
			} else if originator, ok := pkgMap["originator"].(string); ok && originator != "" && originator != "NOASSERTION" {
				hasSupplier = true
			}
		} else {
			// CycloneDX: "supplier": {"name": "Acme Corp"}
			if supplier, ok := pkgMap["supplier"].(map[string]interface{}); ok {
				if name, ok := supplier["name"].(string); ok && name != "" {
					hasSupplier = true
				}
			}
		}

		if hasSupplier {
			supplierCount++
		} else {
			findings = append(findings, BSIFinding{
				Severity:    "MEDIUM",
				Category:    "Suppliers",
				Message:     "No supplier/originator information found",
				Component:   pkgID,
				Remediation: "Supplier information may need to be manually added or fetched from registries",
			})
		}

		// Check BSI TR-03183-2 mandatory component properties (CycloneDX) or annotations (SPDX)
		hasRequiredProperties := true
		if format == "CycloneDX" {
			requiredProps := []string{"executable", "archive", "structured"}
			if props, ok := pkgMap["properties"].([]interface{}); ok && len(props) > 0 {
				foundProps := make(map[string]bool)
				for _, prop := range props {
					if propMap, ok := prop.(map[string]interface{}); ok {
						if name, ok := propMap["name"].(string); ok {
							foundProps[name] = true
						}
					}
				}
				for _, req := range requiredProps {
					if !foundProps[req] {
						hasRequiredProperties = false
						break
					}
				}
			} else {
				hasRequiredProperties = false
			}
		} else {
			// SPDX: check for BSI-related annotations
			if annotations, ok := pkgMap["annotations"].([]interface{}); ok && len(annotations) > 0 {
				hasBSIAnnotation := false
				for _, ann := range annotations {
					if annMap, ok := ann.(map[string]interface{}); ok {
						if comment, ok := annMap["comment"].(string); ok {
							if strings.Contains(comment, "BSI TR-03183-2") || strings.Contains(comment, "executable=") {
								hasBSIAnnotation = true
								break
							}
						}
					}
				}
				if !hasBSIAnnotation {
					hasRequiredProperties = false
				}
			} else {
				hasRequiredProperties = false
			}
		}

		if hasRequiredProperties {
			propertyCount++
		} else {
			findings = append(findings, BSIFinding{
				Severity:    "MEDIUM",
				Category:    "Properties",
				Message:     "Missing BSI TR-03183-2 mandatory properties (executable, archive, structured)",
				Component:   pkgID,
				Remediation: "Run 'transparenz generate --bsi-compliant' to add component properties",
			})
		}
	}

	// Check dependency completeness assertion
	dependencyComplete := false
	if format == "CycloneDX" {
		if metadata, ok := sbomData["metadata"].(map[string]interface{}); ok {
			if props, ok := metadata["properties"].([]interface{}); ok {
				for _, prop := range props {
					if propMap, ok := prop.(map[string]interface{}); ok {
						if name, ok := propMap["name"].(string); ok && name == "completeness" {
							if value, ok := propMap["value"].(string); ok && value == "complete" {
								dependencyComplete = true
							}
							break
						}
					}
				}
			}
		}
	} else {
		// SPDX: check annotations
		if annotations, ok := sbomData["annotations"].([]interface{}); ok {
			for _, ann := range annotations {
				if annMap, ok := ann.(map[string]interface{}); ok {
					if comment, ok := annMap["comment"].(string); ok {
						if strings.Contains(comment, "dependencyCompleteness=complete") {
							dependencyComplete = true
							break
						}
					}
				}
			}
		}
	}

	if !dependencyComplete {
		findings = append(findings, BSIFinding{
			Severity:    "CRITICAL",
			Category:    "Dependency Completeness",
			Message:     "No dependency graph completeness assertion found (required per BSI TR-03183-2 Section 4.2)",
			Component:   "SBOM Document",
			Remediation: "Run 'transparenz generate --bsi-compliant' to add completeness assertion",
		})
	}

	// Calculate coverage percentages
	hashCoverage := 0.0
	licenseCoverage := 0.0
	supplierCoverage := 0.0
	propertyCoverage := 0.0

	if totalPackages > 0 {
		hashCoverage = (float64(hashCount) / float64(totalPackages)) * 100
		licenseCoverage = (float64(licenseCount) / float64(totalPackages)) * 100
		supplierCoverage = (float64(supplierCount) / float64(totalPackages)) * 100
		propertyCoverage = (float64(propertyCount) / float64(totalPackages)) * 100
	}

	// Overall score (weighted average)
	// Weights: hashes (30%), licenses (25%), suppliers (15%), properties (15%), completeness (10%), format (5%)
	completenessScore := 0.0
	if dependencyComplete {
		completenessScore = 100.0
	}
	formatScore := 0.0
	if formatCompliant {
		formatScore = 100.0
	}
	overallScore := (hashCoverage * 0.30) + (licenseCoverage * 0.25) + (supplierCoverage * 0.15) +
		(propertyCoverage * 0.15) + (completenessScore * 0.10) + (formatScore * 0.05)

	// Determine compliance (BSI TR-03183-2 recommends >80% coverage in core categories)
	compliant := hashCoverage >= 80.0 && licenseCoverage >= 80.0 &&
		supplierCoverage >= 80.0 && propertyCoverage >= 80.0 &&
		dependencyComplete && formatCompliant

	return map[string]interface{}{
		"compliant":           compliant,
		"overall_score":       overallScore,
		"total_components":    totalPackages,
		"hash_coverage":       hashCoverage,
		"hash_sha512_count":   hashCount,
		"hash_sha256_only":    hashAnyCount,
		"license_coverage":    licenseCoverage,
		"license_count":       licenseCount,
		"supplier_coverage":   supplierCoverage,
		"supplier_count":      supplierCount,
		"property_coverage":   propertyCoverage,
		"property_count":      propertyCount,
		"dependency_complete": dependencyComplete,
		"format_version":      formatVersion,
		"format_compliant":    formatCompliant,
		"findings":            findings,
		"findings_count":      len(findings),
		"metadata": map[string]interface{}{
			"standard": "BSI TR-03183-2",
			"version":  "2.0",
			"format":   format,
			"threshold": map[string]interface{}{
				"hash":         80.0,
				"license":      80.0,
				"supplier":     80.0,
				"properties":   80.0,
				"completeness": true,
			},
		},
	}
}

// isVersionGTE checks if version string a >= version string b
// Supports simple numeric version comparison (e.g., "1.6" >= "1.5")
func isVersionGTE(a, b string) bool {
	aParts := strings.Split(a, ".")
	bParts := strings.Split(b, ".")

	maxLen := len(aParts)
	if len(bParts) > maxLen {
		maxLen = len(bParts)
	}

	for i := 0; i < maxLen; i++ {
		var aVal, bVal int

		if i < len(aParts) {
			aVal, _ = strconv.Atoi(aParts[i])
		}
		if i < len(bParts) {
			bVal, _ = strconv.Atoi(bParts[i])
		}

		if aVal > bVal {
			return true
		}
		if aVal < bVal {
			return false
		}
	}

	return true // equal
}

func init() {
	rootCmd.AddCommand(bsiCmd)

	bsiCmd.Flags().StringVarP(&bsiOutput, "output", "o", "", "Output file path (default: stdout)")
}
