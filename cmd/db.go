package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"github.com/shift/transparenz/internal/repository"
	"github.com/shift/transparenz/pkg/database"
	"github.com/shift/transparenz/pkg/vulnz"
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

var dbSyncCmd = &cobra.Command{
	Use:   "sync",
	Short: "Sync vulnerability database from vulnz",
	Long:  `Download and merge the latest vulnerability database from the vulnz service.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		token, _ := cmd.Flags().GetString("token")
		projectID, _ := cmd.Flags().GetString("project-id")
		apiURL, _ := cmd.Flags().GetString("api-url")
		outputPath, _ := cmd.Flags().GetString("output")

		if token == "" {
			token = os.Getenv("VULNZ_TOKEN")
		}
		if projectID == "" {
			projectID = os.Getenv("VULNZ_PROJECT_ID")
		}
		if apiURL == "" {
			apiURL = "https://gitlab.opencode.de"
		}
		if outputPath == "" {
			outputPath = "vulnerabilities.db"
		}

		if token == "" || projectID == "" {
			return fmt.Errorf("token and project-id are required (or set VULNZ_TOKEN and VULNZ_PROJECT_ID env vars)")
		}

		ctx := context.Background()

		config := vulnz.Config{
			ProjectID:  projectID,
			APIURL:     apiURL,
			Token:      token,
			OutputPath: outputPath,
		}

		client := vulnz.NewClient(config)

		if verbose {
			fmt.Fprintf(os.Stderr, "Downloading vulnerability database from %s...\n", client.DownloadURL())
		}

		meta, err := client.DownloadAndExtract(ctx, filepath.Dir(outputPath))
		if err != nil {
			return fmt.Errorf("failed to download database: %w", err)
		}

		if err := client.Verify(outputPath); err != nil {
			return fmt.Errorf("database verification failed: %w", err)
		}

		fmt.Printf("Synced vulnerability database:\n")
		fmt.Printf("  Path:     %s\n", outputPath)
		fmt.Printf("  Providers: %s\n", strings.Join(meta.Providers, ", "))
		fmt.Printf("  Count:    %d vulnerabilities\n", meta.VulnCount)
		if !meta.LastUpdate.IsZero() {
			fmt.Printf("  Updated:  %s\n", meta.LastUpdate.Format(time.RFC3339))
		}

		return nil
	},
}

var dbCheckVulnzCmd = &cobra.Command{
	Use:   "check",
	Short: "Check vulnz connectivity and database status",
	Long:  `Verify connectivity to the vulnz service and check database status.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		token, _ := cmd.Flags().GetString("token")
		projectID, _ := cmd.Flags().GetString("project-id")
		apiURL, _ := cmd.Flags().GetString("api-url")

		if token == "" {
			token = os.Getenv("VULNZ_TOKEN")
		}
		if projectID == "" {
			projectID = os.Getenv("VULNZ_PROJECT_ID")
		}
		if apiURL == "" {
			apiURL = "https://gitlab.opencode.de"
		}

		if token == "" || projectID == "" {
			return fmt.Errorf("token and project-id are required")
		}

		config := vulnz.Config{
			ProjectID: projectID,
			APIURL:    apiURL,
			Token:     token,
		}

		client := vulnz.NewClient(config)

		fmt.Printf("Checking vulnz at %s...\n", client.DownloadURL())

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		file, err := client.Download(ctx)
		if err != nil {
			return fmt.Errorf("connection failed: %w", err)
		}
		defer os.Remove(file.Name())
		defer file.Close()

		if vulnz.IsSQLite(file.Name()) {
			fmt.Println("✓ Database is valid SQLite format")
		} else {
			return fmt.Errorf("downloaded file is not a valid SQLite database")
		}

		meta, err := client.GetMetadata(file.Name())
		if err == nil {
			fmt.Printf("✓ Database contains %d vulnerabilities\n", meta.VulnCount)
			fmt.Printf("  Providers: %s\n", strings.Join(meta.Providers, ", "))
			if !meta.LastUpdate.IsZero() {
				fmt.Printf("  Last updated: %s\n", meta.LastUpdate.Format(time.RFC3339))
			}
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(dbCmd)
	dbCmd.AddCommand(dbMigrateCmd)
	dbCmd.AddCommand(dbSyncCmd)
	dbCmd.AddCommand(dbCheckVulnzCmd)

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

	// Add flags for sync and check commands
	dbSyncCmd.Flags().String("token", "", "GitLab API token (or set VULNZ_TOKEN env var)")
	dbSyncCmd.Flags().String("project-id", "", "GitLab project ID (or set VULNZ_PROJECT_ID env var)")
	dbSyncCmd.Flags().String("api-url", "https://gitlab.opencode.de", "GitLab API URL")
	dbSyncCmd.Flags().StringP("output", "o", "vulnerabilities.db", "Output path for the database")

	dbCheckVulnzCmd.Flags().String("token", "", "GitLab API token (or set VULNZ_TOKEN env var)")
	dbCheckVulnzCmd.Flags().String("project-id", "", "GitLab project ID (or set VULNZ_PROJECT_ID env var)")
	dbCheckVulnzCmd.Flags().String("api-url", "https://gitlab.opencode.de", "GitLab API URL")
}
