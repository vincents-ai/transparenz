package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/deutschland-stack/transparenz/internal/repository"
	"github.com/deutschland-stack/transparenz/pkg/bsi"
	"github.com/deutschland-stack/transparenz/pkg/database"
	"github.com/deutschland-stack/transparenz/pkg/sbom"
)

var (
	generateFormat       string
	generateOutput       string
	generateSave         bool
	generateBSICompliant bool
)

var generateCmd = &cobra.Command{
	Use:   "generate [source]",
	Short: "Generate SBOM for a source directory or container image",
	Long: `Generate a Software Bill of Materials (SBOM) using native Syft library.

Native Go Implementation: This version uses the Syft Go library directly for 
optimal performance and eliminates subprocess overhead.

Supports multiple formats:
  - SPDX JSON (default)
  - CycloneDX JSON

Example usage:
  transparenz generate .
  transparenz generate . --format cyclonedx --output sbom.json
  transparenz generate . --bsi-compliant --save
  transparenz generate docker:nginx:latest --format spdx`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		sourcePath := args[0]

		if verbose {
			fmt.Fprintf(os.Stderr, "Generating SBOM for: %s\n", sourcePath)
			fmt.Fprintf(os.Stderr, "Format: %s\n", generateFormat)
		}

		startTime := time.Now()

		// Normalize format string
		var format string
		switch generateFormat {
		case "spdx", "spdx-json":
			format = "spdx"
		case "cyclonedx", "cyclonedx-json":
			format = "cyclonedx"
		default:
			return fmt.Errorf("unsupported format: %s (use 'spdx' or 'cyclonedx')", generateFormat)
		}

		// Create SBOM generator with native Syft library
		generator := sbom.NewGenerator(verbose)

		ctx := context.Background()
		var output string

		// If BSI compliance is requested, generate SBOM then enrich JSON
		if generateBSICompliant {
			if verbose {
				fmt.Fprintf(os.Stderr, "Generating SBOM...\n")
			}

			// Generate SBOM using standard path
			var err error
			output, err = generator.Generate(ctx, sourcePath, format)
			if err != nil {
				return fmt.Errorf("failed to generate SBOM: %w", err)
			}

			if verbose {
				fmt.Fprintf(os.Stderr, "Applying BSI TR-03183-2 enrichment...\n")
			}

			// Enrich the JSON output
			enricher := bsi.NewEnricher(sourcePath)
			output, err = enricher.EnrichSBOM(output)
			if err != nil {
				return fmt.Errorf("failed to enrich SBOM: %w", err)
			}

			if verbose {
				fmt.Fprintf(os.Stderr, "BSI enrichment complete\n")
			}
		} else {
			// Standard generation without enrichment
			var err error
			output, err = generator.Generate(ctx, sourcePath, format)
			if err != nil {
				return fmt.Errorf("failed to generate SBOM: %w", err)
			}
		}

		if verbose {
			fmt.Fprintf(os.Stderr, "SBOM generated in %.2f seconds\n",
				time.Since(startTime).Seconds())
		}

		// Write to file or stdout
		if generateOutput != "" {
			absPath, err := filepath.Abs(generateOutput)
			if err != nil {
				return fmt.Errorf("failed to resolve output path: %w", err)
			}

			err = os.WriteFile(absPath, []byte(output), 0644)
			if err != nil {
				return fmt.Errorf("failed to write output file: %w", err)
			}

			if verbose {
				fmt.Fprintf(os.Stderr, "SBOM written to: %s\n", absPath)
			}

			fmt.Printf("SBOM successfully written to %s\n", absPath)
		} else {
			fmt.Println(output)
		}

		// Save to database if requested
		if generateSave {
			if verbose {
				fmt.Fprintf(os.Stderr, "Saving to database...\n")
			}

			db, err := database.Connect()
			if err != nil {
				return fmt.Errorf("failed to connect to database: %w", err)
			}
			defer database.Close(db)

			repo := repository.NewSBOMRepository(db)
			sbomID, err := repo.SaveSBOM(context.Background(), output, sourcePath)
			if err != nil {
				return fmt.Errorf("failed to save SBOM to database: %w", err)
			}

			fmt.Fprintf(os.Stderr, "SBOM saved to database with ID: %s\n", sbomID)
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(generateCmd)

	generateCmd.Flags().StringVarP(&generateFormat, "format", "f", "spdx", "Output format (spdx, cyclonedx)")
	generateCmd.Flags().StringVarP(&generateOutput, "output", "o", "", "Output file path (default: stdout)")
	generateCmd.Flags().BoolVar(&generateSave, "save", false, "Save SBOM to database")
	generateCmd.Flags().BoolVarP(&generateBSICompliant, "bsi-compliant", "b", false, "Generate BSI TR-03183 compliant SBOM (adds hashes, licenses, suppliers)")
}
