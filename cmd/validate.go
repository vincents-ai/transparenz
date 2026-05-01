package cmd

import (
	"github.com/spf13/cobra"
)

var validateCmd = &cobra.Command{
	Use:   "validate [sbom-path]",
	Short: "Validate SBOM against BSI TR-03183-2 requirements",
	Long: `Validate a Software Bill of Materials against the BSI TR-03183-2 standard.

Checks:
  - Hash algorithm (SHA-512 mandatory per BSI TR-03183-2)
  - License coverage (SPDX identifiers for all components)
  - Supplier coverage (supplier/author information for all components)
  - Component properties (executable, archive, structured)
  - Dependency completeness assertion
  - Format version (CycloneDX 1.6+ or SPDX 2.3+)

Example usage:
  transparenz validate sbom.json
  transparenz validate sbom.json --enrich`,
	SilenceUsage:  true,
	SilenceErrors: true,
}
