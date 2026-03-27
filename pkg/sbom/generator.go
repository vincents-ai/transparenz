package sbom

import (
	"bytes"
	"context"
	"fmt"

	"github.com/anchore/syft/syft"
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

// Generate creates an SBOM from a source path using native Syft library
// sourcePath can be:
//   - Directory path (e.g., ".")
//   - File path
//   - Container image reference (e.g., "docker:nginx:latest")
//
// format can be: "spdx" or "cyclonedx"
func (g *Generator) Generate(ctx context.Context, sourcePath string, format string) (string, error) {
	// Determine source detection
	src, err := syft.GetSource(ctx, sourcePath, nil)
	if err != nil {
		return "", fmt.Errorf("failed to detect source: %w", err)
	}
	defer src.Close()

	if g.verbose {
		desc := src.Describe()
		fmt.Printf("Source detected: %s (ID: %s)\n", sourcePath, desc.ID)
	}

	// Create SBOM using native Syft
	cfg := syft.DefaultCreateSBOMConfig()
	// Use default catalogers (don't call WithCatalogers to use all defaults)

	sbomModel, err := syft.CreateSBOM(ctx, src, cfg)
	if err != nil {
		return "", fmt.Errorf("failed to create SBOM: %w", err)
	}

	if g.verbose {
		fmt.Printf("Cataloged %d packages\n", sbomModel.Artifacts.Packages.PackageCount())
	}

	// Convert to requested format
	output, err := g.formatSBOM(sbomModel, format)
	if err != nil {
		return "", fmt.Errorf("failed to format SBOM: %w", err)
	}

	return string(output), nil
}

// FormatSBOM converts SBOM model to specified format
// This is exported to allow formatting of enriched SBOM models
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

// GetSBOMModel generates the raw SBOM model for further processing
// This is useful for BSI enrichment that needs access to internal structures
func (g *Generator) GetSBOMModel(ctx context.Context, sourcePath string) (*sbom.SBOM, *source.Description, error) {
	src, err := syft.GetSource(ctx, sourcePath, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to detect source: %w", err)
	}
	defer src.Close()

	desc := src.Describe()

	cfg := syft.DefaultCreateSBOMConfig()
	// Use default catalogers (don't call WithCatalogers to use all defaults)

	sbomModel, err := syft.CreateSBOM(ctx, src, cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create SBOM: %w", err)
	}

	return sbomModel, &desc, nil
}
