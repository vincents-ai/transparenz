package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/shift/transparenz/pkg/bsi"
)

var (
	enrichOutput    string
	enrichArtifacts string
)

var enrichCmd = &cobra.Command{
	Use:   "enrich [sbom-path]",
	Short: "Enrich an existing SBOM with BSI TR-03183-2 compliance metadata",
	Long: `Enrich an existing SBOM file with BSI TR-03183-2 mandatory metadata.

Adds to all components:
  - BSI properties: executable, archive, structured (Section 4.1)
  - Dependency completeness assertion (Section 4.2)
  - CycloneDX specVersion bumped to 1.6

When --artifacts is provided, also computes SHA-512 hashes (Section 4.3)
from compiled binaries in the specified directory.

This is a single-binary tool - no external dependencies required.

Example usage:
  transparenz enrich sbom.json -o sbom-enriched.json
  transparenz enrich sbom.json --artifacts ./build/ -o sbom-final.json`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		sbomPath := args[0]

		if verbose {
			fmt.Fprintf(os.Stderr, "Enriching SBOM: %s\n", sbomPath)
		}

		// Read input SBOM
		data, err := os.ReadFile(sbomPath)
		if err != nil {
			return fmt.Errorf("failed to read SBOM: %w", err)
		}

		// Parse SBOM
		var sbomData map[string]interface{}
		if err := json.Unmarshal(data, &sbomData); err != nil {
			return fmt.Errorf("failed to parse SBOM JSON: %w", err)
		}

		// Determine format
		format := "SPDX"
		if _, ok := sbomData["bomFormat"].(string); ok {
			format = "CycloneDX"
		}

		if verbose {
			fmt.Fprintf(os.Stderr, "Detected format: %s\n", format)
		}

		// Apply BSI TR-03183-2 enrichment via JSON-level manipulation
		enricher := bsi.NewEnricher(".")
		enrichedJSON, err := enricher.EnrichSBOM(string(data))
		if err != nil {
			return fmt.Errorf("failed to enrich SBOM: %w", err)
		}

		// Parse enriched result
		if err := json.Unmarshal([]byte(enrichedJSON), &sbomData); err != nil {
			return fmt.Errorf("failed to parse enriched SBOM: %w", err)
		}

		if verbose {
			fmt.Fprintf(os.Stderr, "BSI properties and completeness added\n")
		}

		// Add SHA-512 artifact hashes if artifacts directory provided
		if enrichArtifacts != "" {
			absDir, err := filepath.Abs(enrichArtifacts)
			if err != nil {
				return fmt.Errorf("failed to resolve artifacts path: %w", err)
			}

			if _, err := os.Stat(absDir); os.IsNotExist(err) {
				return fmt.Errorf("artifacts directory not found: %s", absDir)
			}

			if verbose {
				fmt.Fprintf(os.Stderr, "Computing SHA-512 hashes from: %s\n", absDir)
			}

			if err := enricher.EnrichWithArtifactHashes(sbomData, absDir); err != nil {
				return fmt.Errorf("failed to add artifact hashes: %w", err)
			}

			if verbose {
				fmt.Fprintf(os.Stderr, "SHA-512 artifact hashes added\n")
			}
		}

		// Marshal enriched SBOM
		output, err := json.MarshalIndent(sbomData, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal enriched SBOM: %w", err)
		}

		// Write output
		if enrichOutput != "" {
			absPath, err := filepath.Abs(enrichOutput)
			if err != nil {
				return fmt.Errorf("failed to resolve output path: %w", err)
			}

			if err := os.WriteFile(absPath, output, 0644); err != nil {
				return fmt.Errorf("failed to write output: %w", err)
			}

			fmt.Printf("Enriched SBOM written to %s\n", absPath)
		} else {
			fmt.Println(string(output))
		}

		// Print summary
		fmt.Fprintf(os.Stderr, "\n=== BSI TR-03183-2 Enrichment Summary ===\n")
		fmt.Fprintf(os.Stderr, "Format: %s\n", format)
		fmt.Fprintf(os.Stderr, "Properties added: executable, archive, structured\n")
		fmt.Fprintf(os.Stderr, "Dependency completeness: asserted (complete, transitive)\n")
		if enrichArtifacts != "" {
			fmt.Fprintf(os.Stderr, "SHA-512 artifact hashes: computed from %s\n", enrichArtifacts)
		}
		fmt.Fprintf(os.Stderr, "Spec version: CycloneDX 1.6\n")

		return nil
	},
}

func init() {
	rootCmd.AddCommand(enrichCmd)

	enrichCmd.Flags().StringVarP(&enrichOutput, "output", "o", "", "Output file path (default: stdout)")
	enrichCmd.Flags().StringVar(&enrichArtifacts, "artifacts", "", "Directory containing compiled binaries for SHA-512 hash computation")
}
