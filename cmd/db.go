package cmd

import (
	"context"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"github.com/shift/transparenz/internal/repository"
	"github.com/shift/transparenz/pkg/database"
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

		repo := repository.NewSBOMRepository(db)
		sboms, err := repo.ListSBOMs(context.Background(), limit, offset)
		if err != nil {
			return fmt.Errorf("failed to list SBOMs: %w", err)
		}

		if len(sboms) == 0 {
			fmt.Println("No SBOMs found in database")
			return nil
		}

		// Print table
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "ID\tNAME\tVERSION\tFORMAT\tPACKAGES\tCREATED")
		fmt.Fprintln(w, "--\t----\t-------\t------\t--------\t-------")
		for _, sbom := range sboms {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\t%s\n",
				sbom.ID.String()[:8],
				sbom.Name,
				sbom.Version,
				sbom.Format,
				len(sbom.Packages),
				sbom.CreatedAt.Format("2006-01-02 15:04"),
			)
		}
		w.Flush()

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

		repo := repository.NewSBOMRepository(db)
		if err := repo.DeleteSBOM(context.Background(), sbomID); err != nil {
			return fmt.Errorf("failed to delete SBOM: %w", err)
		}

		fmt.Printf("SBOM %s deleted successfully\n", sbomID)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(dbCmd)
	dbCmd.AddCommand(dbMigrateCmd)

	rootCmd.AddCommand(listCmd)
	rootCmd.AddCommand(showCmd)
	rootCmd.AddCommand(searchCmd)
	rootCmd.AddCommand(deleteCmd)

	// Add flags for list command
	listCmd.Flags().IntP("limit", "l", 50, "Maximum number of SBOMs to display")
	listCmd.Flags().IntP("offset", "s", 0, "Offset for pagination")
	listCmd.Flags().String("format", "", "Filter by SBOM format (spdx, cyclonedx)")

	// Add flags for delete command
	deleteCmd.Flags().BoolP("force", "f", false, "Force deletion without confirmation")
}
