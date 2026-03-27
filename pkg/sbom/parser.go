package sbom

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/anchore/syft/syft/format/cyclonedxjson"
	"github.com/anchore/syft/syft/format/spdxjson"
	"github.com/anchore/syft/syft/sbom"
)

// Parser handles parsing of existing SBOM files
type Parser struct {
	verbose bool
}

// NewParser creates a new SBOM parser
func NewParser(verbose bool) *Parser {
	return &Parser{
		verbose: verbose,
	}
}

// ParseFile parses an SBOM file and returns a Syft SBOM model
// Automatically detects format (SPDX or CycloneDX)
func (p *Parser) ParseFile(sbomData []byte) (*sbom.SBOM, error) {
	// Detect format by checking for format-specific fields
	format, err := p.detectFormat(sbomData)
	if err != nil {
		return nil, fmt.Errorf("failed to detect SBOM format: %w", err)
	}

	if p.verbose {
		fmt.Printf("Detected SBOM format: %s\n", format)
	}

	// Parse based on detected format
	switch format {
	case "spdx":
		return p.parseSPDX(sbomData)
	case "cyclonedx":
		return p.parseCycloneDX(sbomData)
	default:
		return nil, fmt.Errorf("unsupported SBOM format: %s", format)
	}
}

// detectFormat detects the SBOM format by examining the JSON structure
func (p *Parser) detectFormat(data []byte) (string, error) {
	var doc map[string]interface{}
	if err := json.Unmarshal(data, &doc); err != nil {
		return "", fmt.Errorf("failed to parse JSON: %w", err)
	}

	// Check for SPDX
	if _, ok := doc["spdxVersion"]; ok {
		return "spdx", nil
	}

	// Check for CycloneDX
	if bomFormat, ok := doc["bomFormat"].(string); ok && bomFormat == "CycloneDX" {
		return "cyclonedx", nil
	}

	return "", fmt.Errorf("unknown SBOM format (missing spdxVersion or bomFormat fields)")
}

// parseSPDX parses an SPDX JSON file
func (p *Parser) parseSPDX(data []byte) (*sbom.SBOM, error) {
	decoder := spdxjson.NewFormatDecoder()

	reader := bytes.NewReader(data)
	sbomModel, _, _, err := decoder.Decode(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to decode SPDX JSON: %w", err)
	}

	if p.verbose {
		fmt.Printf("Parsed SPDX SBOM with %d packages\n", sbomModel.Artifacts.Packages.PackageCount())
	}

	return sbomModel, nil
}

// parseCycloneDX parses a CycloneDX JSON file
func (p *Parser) parseCycloneDX(data []byte) (*sbom.SBOM, error) {
	decoder := cyclonedxjson.NewFormatDecoder()

	reader := bytes.NewReader(data)
	sbomModel, _, _, err := decoder.Decode(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to decode CycloneDX JSON: %w", err)
	}

	if p.verbose {
		fmt.Printf("Parsed CycloneDX SBOM with %d packages\n", sbomModel.Artifacts.Packages.PackageCount())
	}

	return sbomModel, nil
}
