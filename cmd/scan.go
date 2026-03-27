package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	scanOutputFormat string
	scanSave         bool
	scanSeverity     string
	scanOutput       string
)

var scanCmd = &cobra.Command{
	Use:   "scan [sbom-path]",
	Short: "Scan SBOM for vulnerabilities using native Grype",
	Long: `Scan a Software Bill of Materials for known vulnerabilities using native Grype library.

Supports SPDX JSON and CycloneDX JSON input formats.
Outputs vulnerability results in JSON or table format.

Example usage:
  transparenz scan sbom.json
  transparenz scan sbom.json --output-format table
  transparenz scan sbom.json --severity Critical --save
  transparenz scan sbom.json -o json --output results.json

NOTE: Full Grype integration requires complex setup. For Week 1-2, this is a
simplified version that demonstrates the command structure. Full implementation
with native Grype library integration will be completed in subsequent phases.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		sbomPath := args[0]

		if verbose {
			fmt.Fprintf(os.Stderr, "Scanning SBOM: %s\n", sbomPath)
			fmt.Fprintf(os.Stderr, "Output format: %s\n", scanOutputFormat)
			if scanSeverity != "" {
				fmt.Fprintf(os.Stderr, "Filtering by severity: %s\n", scanSeverity)
			}
		}

		// Check if SBOM file exists
		if _, err := os.Stat(sbomPath); os.IsNotExist(err) {
			return fmt.Errorf("SBOM file not found: %s", sbomPath)
		}

		// TODO: Full Grype integration
		// For now, return a stub message
		if scanOutputFormat == "json" {
			result := map[string]interface{}{
				"status":  "stub",
				"message": "Full Grype integration will be implemented with proper vulnerability database setup",
				"sbom":    sbomPath,
				"note":    "This demonstrates the command structure for Week 1-2 deliverable",
			}
			data, _ := json.MarshalIndent(result, "", "  ")

			if scanOutput != "" {
				err := os.WriteFile(scanOutput, data, 0644)
				if err != nil {
					return fmt.Errorf("failed to write output: %w", err)
				}
				fmt.Fprintf(os.Stderr, "Stub results written to: %s\n", scanOutput)
			} else {
				fmt.Println(string(data))
			}
		} else {
			output := fmt.Sprintf("%-20s %-15s %-40s %-15s\n", "VULNERABILITY", "SEVERITY", "PACKAGE", "VERSION")
			output += fmt.Sprintf("%s\n", string(bytes.Repeat([]byte("-"), 90)))
			output += "\n[STUB] Full Grype integration pending\n"
			output += "SBOM file: " + sbomPath + "\n"

			if scanOutput != "" {
				err := os.WriteFile(scanOutput, []byte(output), 0644)
				if err != nil {
					return fmt.Errorf("failed to write output: %w", err)
				}
				fmt.Fprintf(os.Stderr, "Stub results written to: %s\n", scanOutput)
			} else {
				fmt.Println(output)
			}
		}

		// Save to database if requested
		if scanSave {
			return fmt.Errorf("database save requires Week 3-4 implementation")
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(scanCmd)

	scanCmd.Flags().StringVarP(&scanOutputFormat, "output-format", "f", "json", "Output format (json, table)")
	scanCmd.Flags().BoolVar(&scanSave, "save", false, "Save scan results to database")
	scanCmd.Flags().StringVar(&scanSeverity, "severity", "", "Filter by minimum severity (Critical, High, Medium, Low)")
	scanCmd.Flags().StringVarP(&scanOutput, "output", "o", "", "Output file path (default: stdout)")
}
