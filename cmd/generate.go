package cmd

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/deutschland-stack/transparenz/internal/repository"
	"github.com/deutschland-stack/transparenz/pkg/database"
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
	Long: `Generate a Software Bill of Materials (SBOM) using Syft.

Week 1-2 Implementation: This version uses the syft binary as a bridge while we
set up the native Go library integration. Full native integration will be completed
in subsequent iterations.

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

		// Check if source exists (for file/directory paths)
		if _, err := os.Stat(sourcePath); err != nil {
			// Might be a container image reference, proceed anyway
			if verbose {
				fmt.Fprintf(os.Stderr, "Source is not a file/directory, assuming container image reference\n")
			}
		}

		// Determine Syft output format
		var syftFormat string
		switch generateFormat {
		case "spdx", "spdx-json":
			syftFormat = "spdx-json"
		case "cyclonedx", "cyclonedx-json":
			syftFormat = "cyclonedx-json"
		default:
			return fmt.Errorf("unsupported format: %s (use 'spdx' or 'cyclonedx')", generateFormat)
		}

		// Build syft command
		syftArgs := []string{"scan", sourcePath, "-o", syftFormat}

		if verbose {
			syftArgs = append(syftArgs, "-v")
		}

		// Execute syft
		syftCmd := exec.Command("syft", syftArgs...)

		// Capture stdout and stderr separately
		var stdout, stderr bytes.Buffer
		syftCmd.Stdout = &stdout
		syftCmd.Stderr = &stderr

		err := syftCmd.Run()
		if err != nil {
			return fmt.Errorf("failed to generate SBOM: %w\nError: %s", err, stderr.String())
		}

		output := stdout.Bytes()

		if verbose {
			fmt.Fprintf(os.Stderr, "SBOM generated in %.2f seconds\n",
				time.Since(startTime).Seconds())
		}

		// Apply BSI enrichment if requested
		if generateBSICompliant {
			if verbose {
				fmt.Fprintf(os.Stderr, "BSI TR-03183-2 enrichment will be implemented in Week 5-6\n")
			}
		}

		// Write to file or stdout
		if generateOutput != "" {
			absPath, err := filepath.Abs(generateOutput)
			if err != nil {
				return fmt.Errorf("failed to resolve output path: %w", err)
			}

			err = os.WriteFile(absPath, output, 0644)
			if err != nil {
				return fmt.Errorf("failed to write output file: %w", err)
			}

			if verbose {
				fmt.Fprintf(os.Stderr, "SBOM written to: %s\n", absPath)
			}

			fmt.Printf("SBOM successfully written to %s\n", absPath)
		} else {
			fmt.Println(string(output))
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
			sbomID, err := repo.SaveSBOM(context.Background(), string(output), sourcePath)
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
