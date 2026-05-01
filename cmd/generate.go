package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/vincents-ai/transparenz/internal/repository"
	"github.com/vincents-ai/transparenz/pkg/bsi"
	"github.com/vincents-ai/transparenz/pkg/database"
	"github.com/vincents-ai/transparenz/pkg/depfetch"
	"github.com/vincents-ai/transparenz/pkg/sbom"
)

var (
	generateFormat          string
	generateOutput          string
	generateSave            bool
	generateBSICompliant    bool
	generateManufacturer    string
	generateManufacturerURL string
	generateBinary          string
	generateScope           string

	// dep-fetch flags
	generateNoFetch bool

	// submit shortcut flags
	generateSubmit    bool
	generateServerURL string
	generateToken     string
	generateInsecure  bool
	generateTimeout   int
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

		// Validate --scope
		scope := generateScope
		if scope == "" {
			scope = "source"
		}
		if !sbom.IsValidScope(scope) {
			return fmt.Errorf("invalid --scope %q: must be one of: source, binary", scope)
		}
		if verbose {
			fmt.Fprintf(os.Stderr, "Scope: %s\n", scope)
		}

		// Pre-fetch dependencies so the license classifier can find license files
		// in the local module/package cache.  Only runs for source-scope scans and
		// when --no-fetch has not been requested.
		ctx := context.Background()
		if scope == "source" && !generateNoFetch {
			depfetch.Fetch(ctx, sourcePath, verbose)
		}

		// Create SBOM generator with native Syft library
		generator := sbom.NewGenerator(verbose)

		var output string

		// Warn if --binary is set without --bsi-compliant (flag would be silently ignored)
		if generateBinary != "" && !generateBSICompliant {
			fmt.Fprintf(os.Stderr, "warning: --binary requires --bsi-compliant, binary hash will not be applied\n")
		}

		// If BSI compliance is requested, generate SBOM then enrich JSON
		if generateBSICompliant {
			if verbose {
				fmt.Fprintf(os.Stderr, "Generating SBOM...\n")
			}

			// Generate SBOM using standard path
			var err error
			output, err = generator.GenerateWithScope(ctx, sourcePath, format, scope)
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

			// Inject SBOM producer identity (BSI TR-03183-2: metadata.manufacturer)
			mfr := generateManufacturer
			if mfr == "" {
				mfr = os.Getenv("TRANSPARENZ_MANUFACTURER")
			}
			mfrURL := generateManufacturerURL
			if mfrURL == "" {
				mfrURL = os.Getenv("TRANSPARENZ_MANUFACTURER_URL")
			}
			if mfr != "" {
				output, err = enricher.InjectManufacturer(output, mfr, mfrURL)
				if err != nil {
					return fmt.Errorf("failed to inject manufacturer: %w", err)
				}
				if verbose {
					fmt.Fprintf(os.Stderr, "Manufacturer identity injected: %s\n", mfr)
				}
			}

			if verbose {
				fmt.Fprintf(os.Stderr, "BSI enrichment complete\n")
			}

			// Inject binary hash if --binary path provided (BSI TR-03183-2 §4.3)
			if generateBinary != "" {
				absBinary, err := filepath.Abs(generateBinary)
				if err != nil {
					return fmt.Errorf("failed to resolve binary path: %w", err)
				}
				if _, statErr := os.Stat(absBinary); os.IsNotExist(statErr) {
					return fmt.Errorf("binary not found: %s", absBinary)
				}
				output, err = enricher.EnrichWithBinaryHash(output, absBinary)
				if err != nil {
					return fmt.Errorf("failed to inject binary hash: %w", err)
				}
				fmt.Fprintf(os.Stderr, "Binary SHA-512 hash injected: %s\n", absBinary)
			}
		} else {
			// Standard generation: generate SBOM then inject supplier metadata.
			// Supplier injection is a lightweight post-process that does not
			// require full BSI TR-03183-2 compliance mode; it significantly
			// improves SBOM quality for all users by default.
			var err error
			output, err = generator.GenerateWithScope(ctx, sourcePath, format, scope)
			if err != nil {
				return fmt.Errorf("failed to generate SBOM: %w", err)
			}

			enricher := bsi.NewEnricher(sourcePath)
			output, err = enricher.InjectSuppliers(output)
			if err != nil {
				// Non-fatal: supplier injection failure should not abort generation
				if verbose {
					fmt.Fprintf(os.Stderr, "warning: supplier injection failed: %v\n", err)
				}
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

			// When BSI-compliant generation was requested, record compliance status in DB
			if generateBSICompliant {
				compliant, score, checkErr := RunBSICheck(output)
				if checkErr != nil {
					fmt.Fprintf(os.Stderr, "warning: could not compute BSI score: %v\n", checkErr)
					compliant, score = false, 0.0
				}
				if err := repo.UpdateBSICompliance(sbomID, compliant, score); err != nil {
					// Non-fatal: log but don't fail the overall command
					fmt.Fprintf(os.Stderr, "warning: could not update BSI compliance in DB: %v\n", err)
				} else if verbose {
					fmt.Fprintf(os.Stderr, "BSI compliance recorded in database (score: %.1f%%)\n", score*100)
				}
			}
		}

		// Submit to remote server if requested
		if generateSubmit {
			serverURL := generateServerURL
			if serverURL == "" {
				serverURL = os.Getenv("TRANSPARENZ_SERVER_URL")
			}
			if serverURL == "" {
				return fmt.Errorf("server URL is required for --submit (use --server-url or TRANSPARENZ_SERVER_URL)")
			}

			token := generateToken
			if token == "" {
				token = os.Getenv("TRANSPARENZ_TOKEN")
			}
			if token == "" {
				return fmt.Errorf("bearer token is required for --submit (use --token or TRANSPARENZ_TOKEN)")
			}

			insecure := generateInsecure
			if !insecure && os.Getenv("TRANSPARENZ_INSECURE") == "true" {
				insecure = true
			}

			sbomBytes := []byte(output)
			ct := detectContentType(sbomBytes)
			if err := postSBOM(serverURL, token, ct, sbomBytes, generateTimeout, insecure); err != nil {
				return fmt.Errorf("failed to submit SBOM: %w", err)
			}
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
	generateCmd.Flags().StringVar(&generateManufacturer, "manufacturer", "", "SBOM producer organisation name (BSI TR-03183-2, also env: TRANSPARENZ_MANUFACTURER)")
	generateCmd.Flags().StringVar(&generateManufacturerURL, "manufacturer-url", "", "SBOM producer organisation URL (also env: TRANSPARENZ_MANUFACTURER_URL)")
	generateCmd.Flags().StringVar(&generateBinary, "binary", "", "Path to compiled binary for SHA-512 hash injection (BSI TR-03183-2 §4.3, requires --bsi-compliant)")
	generateCmd.Flags().StringVar(&generateScope, "scope", "source", "SBOM scope: source (scan dependency manifests: go.mod, package.json, etc) or binary (scan a compiled binary or container image)")
	generateCmd.Flags().BoolVar(&generateNoFetch, "no-fetch", false, "Skip pre-scan dependency fetching (disables go mod download, npm ci, etc. before SBOM generation)")
	generateCmd.Flags().BoolVar(&generateSubmit, "submit", false, "Submit generated SBOM to a remote server after generation")
	generateCmd.Flags().StringVar(&generateServerURL, "server-url", "", "Remote server endpoint for SBOM submission (also env: TRANSPARENZ_SERVER_URL)")
	generateCmd.Flags().StringVar(&generateToken, "token", "", "Bearer token for SBOM submission (also env: TRANSPARENZ_TOKEN)")
	generateCmd.Flags().BoolVar(&generateInsecure, "insecure", false, "Skip TLS certificate verification for submission (also env: TRANSPARENZ_INSECURE=true)")
	generateCmd.Flags().IntVar(&generateTimeout, "timeout", 30, "HTTP timeout in seconds for SBOM submission")
}
