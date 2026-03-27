package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"

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
  - Hash coverage (SHA-256 or SHA-512 for all components)
  - License coverage (SPDX identifiers for all components)
  - Supplier coverage (supplier/author information for all components)

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
		fmt.Fprintf(os.Stderr, "Hash Coverage: %.1f%%\n", report["hash_coverage"].(float64))
		fmt.Fprintf(os.Stderr, "License Coverage: %.1f%%\n", report["license_coverage"].(float64))
		fmt.Fprintf(os.Stderr, "Supplier Coverage: %.1f%%\n", report["supplier_coverage"].(float64))

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

	// Extract packages from SPDX SBOM
	packages, ok := sbomData["packages"].([]interface{})
	if !ok {
		return map[string]interface{}{
			"error": "Invalid SBOM format - no packages found",
		}
	}

	totalPackages := len(packages)
	hashCount := 0
	licenseCount := 0
	supplierCount := 0

	// SHA-256 and SHA-512 regex patterns
	sha256Regex := regexp.MustCompile(`^[a-fA-F0-9]{64}$`)
	sha512Regex := regexp.MustCompile(`^[a-fA-F0-9]{128}$`)

	for _, pkg := range packages {
		pkgMap, ok := pkg.(map[string]interface{})
		if !ok {
			continue
		}

		pkgName := pkgMap["name"].(string)
		pkgVersion := ""
		if v, ok := pkgMap["versionInfo"]; ok {
			pkgVersion = v.(string)
		}
		pkgID := fmt.Sprintf("%s@%s", pkgName, pkgVersion)

		// Check hashes (checksums field in SPDX)
		hasValidHash := false
		if checksums, ok := pkgMap["checksums"].([]interface{}); ok && len(checksums) > 0 {
			for _, cs := range checksums {
				if csMap, ok := cs.(map[string]interface{}); ok {
					algorithm := csMap["algorithm"].(string)
					value := csMap["checksumValue"].(string)

					if algorithm == "SHA256" && sha256Regex.MatchString(value) {
						hasValidHash = true
						break
					}
					if algorithm == "SHA512" && sha512Regex.MatchString(value) {
						hasValidHash = true
						break
					}
				}
			}
		}

		if hasValidHash {
			hashCount++
		} else {
			findings = append(findings, BSIFinding{
				Severity:    "CRITICAL",
				Category:    "Hashes",
				Message:     "No SHA-256 or SHA-512 hash found",
				Component:   pkgID,
				Remediation: "Run 'transparenz generate --bsi-compliant' to add cryptographic hashes",
			})
		}

		// Check license (licenseConcluded or licenseDeclared)
		hasValidLicense := false
		if license, ok := pkgMap["licenseConcluded"].(string); ok && license != "" && license != "NOASSERTION" {
			hasValidLicense = true
		} else if license, ok := pkgMap["licenseDeclared"].(string); ok && license != "" && license != "NOASSERTION" {
			hasValidLicense = true
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
		if supplier, ok := pkgMap["supplier"].(string); ok && supplier != "" && supplier != "NOASSERTION" {
			hasSupplier = true
		} else if originator, ok := pkgMap["originator"].(string); ok && originator != "" && originator != "NOASSERTION" {
			hasSupplier = true
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
	}

	// Calculate coverage percentages
	hashCoverage := 0.0
	licenseCoverage := 0.0
	supplierCoverage := 0.0

	if totalPackages > 0 {
		hashCoverage = (float64(hashCount) / float64(totalPackages)) * 100
		licenseCoverage = (float64(licenseCount) / float64(totalPackages)) * 100
		supplierCoverage = (float64(supplierCount) / float64(totalPackages)) * 100
	}

	// Overall score (weighted average)
	overallScore := (hashCoverage*0.4 + licenseCoverage*0.4 + supplierCoverage*0.2)

	// Determine compliance (BSI TR-03183-2 recommends >80% coverage)
	compliant := hashCoverage >= 80.0 && licenseCoverage >= 80.0 && supplierCoverage >= 80.0

	return map[string]interface{}{
		"compliant":         compliant,
		"overall_score":     overallScore,
		"total_components":  totalPackages,
		"hash_coverage":     hashCoverage,
		"hash_count":        hashCount,
		"license_coverage":  licenseCoverage,
		"license_count":     licenseCount,
		"supplier_coverage": supplierCoverage,
		"supplier_count":    supplierCount,
		"findings":          findings,
		"findings_count":    len(findings),
		"metadata": map[string]interface{}{
			"standard": "BSI TR-03183-2",
			"version":  "1.0",
			"threshold": map[string]interface{}{
				"hash":     80.0,
				"license":  80.0,
				"supplier": 80.0,
			},
		},
	}
}

func init() {
	rootCmd.AddCommand(bsiCmd)

	bsiCmd.Flags().StringVarP(&bsiOutput, "output", "o", "", "Output file path (default: stdout)")
}
