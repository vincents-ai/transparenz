package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/deutschland-stack/transparenz/internal/repository"
	"github.com/deutschland-stack/transparenz/pkg/database"
	"github.com/deutschland-stack/transparenz/pkg/sbom"
	"github.com/deutschland-stack/transparenz/pkg/scan"
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

Native Go Implementation: This version uses the Grype Go library directly for
optimal performance and eliminates subprocess overhead.

Supports SPDX JSON and CycloneDX JSON input formats.
Outputs vulnerability results in JSON or table format.

Example usage:
  transparenz scan sbom.json
  transparenz scan sbom.json --output-format table
  transparenz scan sbom.json --severity Critical --save
  transparenz scan sbom.json -f json --output results.json`,
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

		// Read SBOM file data
		sbomData, err := os.ReadFile(sbomPath)
		if err != nil {
			return fmt.Errorf("failed to read SBOM file: %w", err)
		}

		// Parse existing SBOM file using the parser
		parser := sbom.NewParser(verbose)
		sbomModel, err := parser.ParseFile(sbomData)
		if err != nil {
			return fmt.Errorf("failed to parse SBOM file: %w", err)
		}

		// Create scanner with native Grype
		scanner := scan.NewScanner(verbose)

		// Create context for scanning
		ctx := context.Background()

		// Perform vulnerability scan
		result, err := scanner.Scan(ctx, sbomModel)
		if err != nil {
			return fmt.Errorf("failed to scan SBOM: %w", err)
		}

		// Filter by severity if requested
		if scanSeverity != "" {
			result.Matches = scanner.FilterBySeverity(result.Matches, scanSeverity)
		}

		// Format and output results
		var output string
		if scanOutputFormat == "json" {
			output, err = scanner.FormatJSON(result)
			if err != nil {
				return fmt.Errorf("failed to format JSON: %w", err)
			}
		} else {
			output = scanner.FormatTable(result)
		}

		// Write to file or stdout
		if scanOutput != "" {
			err := os.WriteFile(scanOutput, []byte(output), 0644)
			if err != nil {
				return fmt.Errorf("failed to write output: %w", err)
			}
			fmt.Fprintf(os.Stderr, "Scan results written to: %s\n", scanOutput)
		} else {
			fmt.Println(output)
		}

		// Save to database if requested
		if scanSave {
			if verbose {
				fmt.Fprintf(os.Stderr, "Saving scan results to database...\n")
			}

			db, err := database.Connect()
			if err != nil {
				return fmt.Errorf("failed to connect to database: %w", err)
			}
			defer database.Close(db)

			// TODO: Implement SaveScanResults method
			_ = repository.NewSBOMRepository(db)
			fmt.Fprintf(os.Stderr, "Warning: Database save not yet implemented for scan results\n")
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
