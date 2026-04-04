package sbom

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/cataloging"
	"github.com/anchore/syft/syft/format/cyclonedxjson"
	"github.com/anchore/syft/syft/format/spdxjson"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

// Generator wraps native Syft library for SBOM generation
type Generator struct {
	verbose bool
}

// NewGenerator creates a new SBOM generator
func NewGenerator(verbose bool) *Generator {
	return &Generator{
		verbose: verbose,
	}
}

// buildSBOMConfig returns a Syft CreateSBOMConfig that excludes catalogers which
// produce non-dependency noise:
//   - github-actions-usage-cataloger: emits GitHub Action pins from workflow files
//   - file (tag): file-digest, file-metadata, file-content catalogers
func buildSBOMConfig() *syft.CreateSBOMConfig {
	selection := cataloging.NewSelectionRequest().
		WithRemovals("github-actions-usage-cataloger", "file")

	return syft.DefaultCreateSBOMConfig().
		WithoutFiles().
		WithCatalogerSelection(selection)
}

// Generate creates an SBOM from a source path using native Syft library.
// sourcePath can be:
//   - Directory path (e.g., ".")
//   - File path
//   - Container image reference (e.g., "docker:nginx:latest")
//
// format can be: "spdx" or "cyclonedx"
func (g *Generator) Generate(ctx context.Context, sourcePath string, format string) (string, error) {
	src, err := syft.GetSource(ctx, sourcePath, nil)
	if err != nil {
		return "", fmt.Errorf("failed to detect source: %w", err)
	}
	defer src.Close()

	if g.verbose {
		desc := src.Describe()
		fmt.Fprintf(os.Stderr, "Source detected: %s (ID: %s)\n", sourcePath, desc.ID)
	}

	cfg := buildSBOMConfig()

	sbomModel, err := syft.CreateSBOM(ctx, src, cfg)
	if err != nil {
		return "", fmt.Errorf("failed to create SBOM: %w", err)
	}

	// Deduplicate packages by PURL (multiple go.mod files can emit the same module)
	deduplicateByPURL(sbomModel)

	if g.verbose {
		fmt.Fprintf(os.Stderr, "Cataloged %d packages\n", sbomModel.Artifacts.Packages.PackageCount())
	}

	output, err := g.formatSBOM(sbomModel, format)
	if err != nil {
		return "", fmt.Errorf("failed to format SBOM: %w", err)
	}

	result := string(output)

	// Strip absolute source path from output to keep SBOMs reproducible.
	// Always resolve to absolute first: Syft internally resolves "." and
	// relative paths, embedding the absolute path in the SBOM name/namespace.
	// Without this, relative inputs like "." leak the machine's working
	// directory into the generated SBOM.
	if absSource, err := filepath.Abs(sourcePath); err == nil && absSource != "." {
		result = strings.ReplaceAll(result, absSource, ".")
	}

	return result, nil
}

// FormatSBOM converts SBOM model to specified format.
// This is exported to allow formatting of enriched SBOM models.
func (g *Generator) FormatSBOM(sbomModel *sbom.SBOM, format string) ([]byte, error) {
	var buf bytes.Buffer

	switch format {
	case "spdx", "spdx-json":
		encoder, err := spdxjson.NewFormatEncoderWithConfig(spdxjson.DefaultEncoderConfig())
		if err != nil {
			return nil, fmt.Errorf("failed to create SPDX encoder: %w", err)
		}
		if err := encoder.Encode(&buf, *sbomModel); err != nil {
			return nil, fmt.Errorf("failed to encode SPDX: %w", err)
		}
		return buf.Bytes(), nil

	case "cyclonedx", "cyclonedx-json":
		encoder, err := cyclonedxjson.NewFormatEncoderWithConfig(cyclonedxjson.DefaultEncoderConfig())
		if err != nil {
			return nil, fmt.Errorf("failed to create CycloneDX encoder: %w", err)
		}
		if err := encoder.Encode(&buf, *sbomModel); err != nil {
			return nil, fmt.Errorf("failed to encode CycloneDX: %w", err)
		}
		return buf.Bytes(), nil

	default:
		return nil, fmt.Errorf("unsupported format: %s (use 'spdx' or 'cyclonedx')", format)
	}
}

// formatSBOM is the internal version that calls FormatSBOM
func (g *Generator) formatSBOM(sbomModel *sbom.SBOM, format string) ([]byte, error) {
	return g.FormatSBOM(sbomModel, format)
}

// GetSBOMModel generates the raw SBOM model for further processing.
// This is useful for BSI enrichment that needs access to internal structures.
func (g *Generator) GetSBOMModel(ctx context.Context, sourcePath string) (*sbom.SBOM, *source.Description, error) {
	src, err := syft.GetSource(ctx, sourcePath, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to detect source: %w", err)
	}
	defer src.Close()

	desc := src.Describe()

	cfg := buildSBOMConfig()

	sbomModel, err := syft.CreateSBOM(ctx, src, cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create SBOM: %w", err)
	}

	// Deduplicate packages by PURL
	deduplicateByPURL(sbomModel)

	return sbomModel, &desc, nil
}

// deduplicateByPURL removes packages with duplicate PURLs from an SBOM model,
// keeping the first occurrence. Packages with no PURL are left untouched.
// This prevents inflation when multiple go.mod files in a monorepo reference
// the same upstream module.
func deduplicateByPURL(sbomModel *sbom.SBOM) {
	seen := make(map[string]struct{})
	var toRemove []artifact.ID

	for p := range sbomModel.Artifacts.Packages.Enumerate() {
		purl := p.PURL
		if purl == "" {
			continue
		}
		if _, exists := seen[purl]; exists {
			toRemove = append(toRemove, p.ID())
		} else {
			seen[purl] = struct{}{}
		}
	}

	for _, id := range toRemove {
		sbomModel.Artifacts.Packages.Delete(id)
	}
}
