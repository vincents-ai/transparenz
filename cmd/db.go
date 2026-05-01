package cmd

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"github.com/vincents-ai/transparenz/internal/models"
	"github.com/vincents-ai/transparenz/internal/repository"
	"github.com/vincents-ai/transparenz/pkg/database"
)

var dbCmd = &cobra.Command{
	Use:   "db",
	Short: "Database operations for SBOM storage",
	Long:  `Manage SBOM database operations including migrations, listing, searching, and deleting SBOMs.`,
}

var dbMigrateCmd = &cobra.Command{
	Use:   "migrate",
	Short: "Run database migrations",
	Long:  `Run automatic GORM migrations to create or update database schema.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		db, err := database.Connect()
		if err != nil {
			return fmt.Errorf("failed to connect to database: %w", err)
		}
		defer database.Close(db)

		if verbose {
			fmt.Fprintln(os.Stderr, "Running database migrations...")
		}

		if err := database.Migrate(db); err != nil {
			return fmt.Errorf("failed to run migrations: %w", err)
		}

		fmt.Println("Database migrations completed successfully")
		return nil
	},
}

// sbomWithCount extends SBOM with a package count from a COUNT subquery,
// avoiding the N+1 problem of Preload("Packages").
type sbomWithCount struct {
	models.SBOM
	PackageCount int64
}

// sbomJSON is the JSON serialisation shape for db list --format json.
type sbomJSON struct {
	ID            string     `json:"id"`
	Name          string     `json:"name"`
	Version       string     `json:"version"`
	Format        string     `json:"format"`
	FormatVersion string     `json:"format_version"`
	BSICompliant  bool       `json:"bsi_compliant"`
	BSIScore      float64    `json:"bsi_score"`
	PackageCount  int64      `json:"package_count"`
	CreatedAt     time.Time  `json:"created_at"`
	GeneratedAt   *time.Time `json:"generated_at"`
}

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List all SBOMs from database",
	Long:  `List all Software Bill of Materials stored in the database.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		db, err := database.Connect()
		if err != nil {
			return fmt.Errorf("failed to connect to database: %w", err)
		}
		defer database.Close(db)

		limit, _ := cmd.Flags().GetInt("limit")
		offset, _ := cmd.Flags().GetInt("offset")
		format, _ := cmd.Flags().GetString("format")

		// Fix 3: replace Preload("Packages") with a COUNT subquery to avoid N+1.
		var results []sbomWithCount
		if err := db.Model(&models.SBOM{}).
			Select("sboms.*, COUNT(packages.id) as package_count").
			Joins("LEFT JOIN packages ON packages.sbom_id = sboms.id AND packages.deleted_at IS NULL").
			Where("sboms.deleted_at IS NULL").
			Group("sboms.id").
			Order("sboms.created_at DESC").
			Limit(limit).Offset(offset).
			Scan(&results).Error; err != nil {
			return fmt.Errorf("failed to list SBOMs: %w", err)
		}

		if len(results) == 0 {
			fmt.Println("No SBOMs found in database")
			return nil
		}

		// Fix 1: honour --format flag.
		switch strings.ToLower(format) {
		case "json":
			out := make([]sbomJSON, 0, len(results))
			for _, r := range results {
				out = append(out, sbomJSON{
					ID:            r.ID.String(),
					Name:          r.Name,
					Version:       r.Version,
					Format:        r.Format,
					FormatVersion: r.FormatVersion,
					BSICompliant:  r.BSICompliant,
					BSIScore:      r.BSIScore,
					PackageCount:  r.PackageCount,
					CreatedAt:     r.CreatedAt,
					GeneratedAt:   r.GeneratedAt,
				})
			}
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(out)

		default: // "table" or empty string
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "ID\tNAME\tVERSION\tFORMAT\tPACKAGES\tGENERATED\tBSI\tCREATED")
			fmt.Fprintln(w, "--\t----\t-------\t------\t--------\t---------\t---\t-------")
			for _, r := range results {
				generated := "N/A"
				if r.GeneratedAt != nil {
					generated = r.GeneratedAt.Format("2006-01-02")
				}
				bsiStatus := "-"
				if r.BSICheckedAt != nil {
					if r.BSICompliant {
						bsiStatus = fmt.Sprintf("✓ (%.0f%%)", r.BSIScore*100)
					} else {
						bsiStatus = fmt.Sprintf("✗ (%.0f%%)", r.BSIScore*100)
					}
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\t%s\t%s\t%s\n",
					r.ID.String()[:8],
					r.Name,
					r.Version,
					r.Format,
					r.PackageCount,
					generated,
					bsiStatus,
					r.CreatedAt.Format("2006-01-02 15:04"),
				)
			}
			w.Flush()
		}

		return nil
	},
}

var showCmd = &cobra.Command{
	Use:   "show [sbom-id]",
	Short: "Show detailed information for a specific SBOM",
	Long:  `Display detailed information for a specific SBOM from the database.`,
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		db, err := database.Connect()
		if err != nil {
			return fmt.Errorf("failed to connect to database: %w", err)
		}
		defer database.Close(db)

		sbomID, err := uuid.Parse(args[0])
		if err != nil {
			return fmt.Errorf("invalid SBOM ID: %w", err)
		}

		repo := repository.NewSBOMRepository(db)
		sbom, err := repo.GetSBOM(context.Background(), sbomID)
		if err != nil {
			return fmt.Errorf("failed to get SBOM: %w", err)
		}

		// Print SBOM details
		fmt.Printf("ID:                %s\n", sbom.ID)
		fmt.Printf("Name:              %s\n", sbom.Name)
		fmt.Printf("Version:           %s\n", sbom.Version)
		fmt.Printf("Format:            %s %s\n", sbom.Format, sbom.FormatVersion)
		fmt.Printf("Document Namespace:%s\n", sbom.DocumentNamespace)
		if sbom.SourcePath != nil {
			fmt.Printf("Source Path:       %s\n", *sbom.SourcePath)
		}
		fmt.Printf("Created:           %s\n", sbom.CreatedAt.Format("2006-01-02 15:04:05"))
		fmt.Printf("Updated:           %s\n", sbom.UpdatedAt.Format("2006-01-02 15:04:05"))
		fmt.Printf("Packages:          %d\n", len(sbom.Packages))
		fmt.Printf("Scans:             %d\n", len(sbom.Scans))

		if len(sbom.Packages) > 0 {
			fmt.Println("\nPackages:")
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "  NAME\tVERSION\tLICENSE")
			for _, pkg := range sbom.Packages {
				version := "N/A"
				if pkg.Version != nil {
					version = *pkg.Version
				}
				license := "N/A"
				if pkg.License != nil {
					license = *pkg.License
				}
				fmt.Fprintf(w, "  %s\t%s\t%s\n", pkg.Name, version, license)
			}
			w.Flush()
		}

		return nil
	},
}

var searchCmd = &cobra.Command{
	Use:   "search [package-name]",
	Short: "Search for packages across all SBOMs",
	Long:  `Search for a specific package name across all SBOMs in the database.`,
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		db, err := database.Connect()
		if err != nil {
			return fmt.Errorf("failed to connect to database: %w", err)
		}
		defer database.Close(db)

		repo := repository.NewSBOMRepository(db)
		packages, err := repo.SearchByPackage(context.Background(), args[0])
		if err != nil {
			return fmt.Errorf("failed to search packages: %w", err)
		}

		if len(packages) == 0 {
			fmt.Printf("No packages found matching '%s'\n", args[0])
			return nil
		}

		fmt.Printf("Found %d package(s) matching '%s':\n\n", len(packages), args[0])
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "SBOM\tPACKAGE\tVERSION\tLICENSE")
		fmt.Fprintln(w, "----\t-------\t-------\t-------")
		for _, pkg := range packages {
			version := "N/A"
			if pkg.Version != nil {
				version = *pkg.Version
			}
			license := "N/A"
			if pkg.License != nil {
				license = *pkg.License
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\n",
				pkg.SBOM.Name,
				pkg.Name,
				version,
				license,
			)
		}
		w.Flush()

		return nil
	},
}

var deleteCmd = &cobra.Command{
	Use:   "delete [sbom-id]",
	Short: "Delete an SBOM from the database",
	Long:  `Delete a specific SBOM and all associated data from the database.`,
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		db, err := database.Connect()
		if err != nil {
			return fmt.Errorf("failed to connect to database: %w", err)
		}
		defer database.Close(db)

		sbomID, err := uuid.Parse(args[0])
		if err != nil {
			return fmt.Errorf("invalid SBOM ID: %w", err)
		}

		// Fix 2: require confirmation unless --force is set.
		force, _ := cmd.Flags().GetBool("force")
		if !force {
			fmt.Printf("Delete SBOM %s? [y/N]: ", sbomID.String())
			scanner := bufio.NewScanner(os.Stdin)
			scanner.Scan()
			answer := strings.TrimSpace(scanner.Text())
			if answer != "y" && answer != "Y" {
				fmt.Println("Aborted.")
				return nil
			}
		}

		repo := repository.NewSBOMRepository(db)
		if err := repo.DeleteSBOM(context.Background(), sbomID); err != nil {
			return fmt.Errorf("failed to delete SBOM: %w", err)
		}

		fmt.Printf("SBOM %s deleted successfully\n", sbomID)
		return nil
	},
}

var exportCmd = &cobra.Command{
	Use:   "export <id>",
	Short: "Export stored SBOM JSON from the database",
	Long:  "Retrieve a stored SBOM's raw JSON from the database by full UUID or 8-character prefix.",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		db, err := database.Connect()
		if err != nil {
			return fmt.Errorf("failed to connect to database: %w", err)
		}
		defer database.Close(db)

		repo := repository.NewSBOMRepository(db)

		var sbomID uuid.UUID
		if parsed, parseErr := uuid.Parse(args[0]); parseErr == nil {
			sbomID = parsed
		} else {
			sbom, findErr := repo.GetSBOMByPrefix(args[0])
			if findErr != nil {
				return fmt.Errorf("failed to resolve SBOM ID: %w", findErr)
			}
			sbomID = sbom.ID
		}

		jsonStr, err := repo.GetSBOMJSON(sbomID)
		if err != nil {
			return fmt.Errorf("failed to get SBOM JSON: %w", err)
		}

		outputPath, _ := cmd.Flags().GetString("output")
		if outputPath != "" {
			if err := os.WriteFile(outputPath, []byte(jsonStr), 0644); err != nil {
				return fmt.Errorf("failed to write output file: %w", err)
			}
		} else {
			fmt.Print(jsonStr)
		}

		fmt.Fprintf(os.Stderr, "Exported SBOM %s\n", sbomID)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(dbCmd)
	dbCmd.AddCommand(dbMigrateCmd)
	dbCmd.AddCommand(exportCmd)

	rootCmd.AddCommand(listCmd)
	rootCmd.AddCommand(showCmd)
	rootCmd.AddCommand(searchCmd)
	rootCmd.AddCommand(deleteCmd)

	// Add flags for list command
	listCmd.Flags().IntP("limit", "l", 50, "Maximum number of SBOMs to display")
	listCmd.Flags().IntP("offset", "s", 0, "Offset for pagination")
	listCmd.Flags().String("format", "table", "Output format: table (default) or json")

	// Add flags for delete command
	deleteCmd.Flags().BoolP("force", "f", false, "Force deletion without confirmation")

	// Add flags for export command
	exportCmd.Flags().StringP("output", "o", "", "Output file path (stdout if unset)")
}
