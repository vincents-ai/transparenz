package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/vincents-ai/transparenz/pkg/bsi"
	"github.com/spf13/cobra"
)

var (
	bsiOutput string
)

// RunBSICheck runs BSI compliance validation on an SBOM JSON string and returns
// (compliant bool, score float64 0.0-1.0, err error).
// This allows programmatic use from other commands without spawning a subprocess.
func RunBSICheck(sbomJSON string) (compliant bool, score float64, err error) {
	if strings.TrimSpace(sbomJSON) == "" {
		return false, 0.0, fmt.Errorf("empty SBOM JSON")
	}
	var sbomData map[string]interface{}
	if err := json.Unmarshal([]byte(sbomJSON), &sbomData); err != nil {
		return false, 0.0, fmt.Errorf("failed to parse SBOM JSON: %w", err)
	}
	report := bsi.CheckConformance(sbomData)

	compliantVal, _ := report["compliant"].(bool)
	scoreVal, _ := report["overall_score"].(float64)

	return compliantVal, scoreVal / 100.0, nil
}

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
  - Format version (CycloneDX 1.6+ or SPDX 2.3+ required for CRA/BSI extensions)

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
		report := bsi.CheckConformance(sbomData)

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
				fmt.Fprintf(os.Stderr, "  WARNING: Format version does not meet minimum requirements (CycloneDX 1.6+ or SPDX 2.3+)\n")
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



func init() {
	rootCmd.AddCommand(bsiCmd)

	bsiCmd.Flags().StringVarP(&bsiOutput, "output", "o", "", "Output file path (default: stdout)")
}
