package scan

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/anchore/clio"
	"github.com/anchore/grype/grype"
	v6dist "github.com/anchore/grype/grype/db/v6/distribution"
	v6inst "github.com/anchore/grype/grype/db/v6/installation"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/matcher/stock"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/syft/syft/sbom"
)

// VulnerabilityProvider defines interface for vulnerability database operations
type VulnerabilityProvider interface {
	FindMatches(ctx context.Context, packages interface{}, context interface{}) (interface{}, interface{}, error)
}

// VulnerabilityScanner defines interface for scanning SBOMs
type VulnerabilityScanner interface {
	Scan(ctx context.Context, sbomModel *sbom.SBOM) (*ScanResult, error)
}

// GrypeAdapter wraps Grype's vulnerability matching
type GrypeAdapter struct {
	scanner VulnerabilityScanner
}

func NewGrypeAdapter() *GrypeAdapter {
	return &GrypeAdapter{
		scanner: nil,
	}
}

func NewGrypeAdapterWithScanner(scanner VulnerabilityScanner) *GrypeAdapter {
	return &GrypeAdapter{
		scanner: scanner,
	}
}

func (g *GrypeAdapter) FindMatches(ctx context.Context, sbomModel *sbom.SBOM, verbose bool) (*ScanResult, error) {
	if g.scanner != nil {
		return g.scanner.Scan(ctx, sbomModel)
	}
	scanner := NewScanner(verbose)
	return scanner.Scan(ctx, sbomModel)
}

// Scanner wraps native Grype library for vulnerability scanning
type Scanner struct {
	verbose          bool
	vulnProviderFunc func(ctx context.Context, sbomModel *sbom.SBOM) (*ScanResult, error)
}

// NewScanner creates a new vulnerability scanner
func NewScanner(verbose bool) *Scanner {
	return &Scanner{
		verbose:          verbose,
		vulnProviderFunc: nil,
	}
}

// NewScannerWithMock creates a scanner with a mock vulnerability provider for testing
func NewScannerWithMock(verbose bool, mockFunc func(ctx context.Context, sbomModel *sbom.SBOM) (*ScanResult, error)) *Scanner {
	return &Scanner{
		verbose:          verbose,
		vulnProviderFunc: mockFunc,
	}
}

// ScanResult represents the vulnerability scan results
type ScanResult struct {
	Matches        []VulnerabilityMatch `json:"matches"`
	IgnoredMatches []VulnerabilityMatch `json:"ignoredMatches,omitempty"`
	Source         *sbom.SBOM           `json:"source"`
}

// VulnerabilityMatch represents a single vulnerability match
type VulnerabilityMatch struct {
	Vulnerability Vulnerability `json:"vulnerability"`
	Package       Package       `json:"package"`
	MatchDetails  []MatchDetail `json:"matchDetails"`
}

// Vulnerability represents a CVE or security advisory
type Vulnerability struct {
	ID          string   `json:"id"`
	Severity    string   `json:"severity"`
	Description string   `json:"description,omitempty"`
	URLs        []string `json:"urls,omitempty"`
	CVSS        []CVSS   `json:"cvss,omitempty"`
}

// Package represents the affected package
type Package struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Type    string `json:"type"`
	PURL    string `json:"purl,omitempty"`
}

// MatchDetail provides information about how the vulnerability was matched
type MatchDetail struct {
	Type       string `json:"type"`
	Confidence string `json:"confidence"`
	Matcher    string `json:"matcher"`
}

// CVSS represents Common Vulnerability Scoring System metrics
type CVSS struct {
	Version string  `json:"version"`
	Vector  string  `json:"vector"`
	Score   float64 `json:"score"`
}

// Scan performs vulnerability scanning on an SBOM
func (s *Scanner) Scan(ctx context.Context, sbomModel *sbom.SBOM) (*ScanResult, error) {
	if s.vulnProviderFunc != nil {
		return s.vulnProviderFunc(ctx, sbomModel)
	}

	if s.verbose {
		fmt.Println("Loading vulnerability database...")
	}

	// Load vulnerability database using new v6 API
	distCfg := v6dist.Config{
		ID: clio.Identification{
			Name: "transparenz",
		},
		RequireUpdateCheck: false,
	}

	instCfg := v6inst.DefaultConfig(clio.Identification{
		Name: "transparenz",
	})

	vulnProvider, status, err := grype.LoadVulnerabilityDB(distCfg, instCfg, true)
	if err != nil {
		return nil, fmt.Errorf("failed to load vulnerability database: %w", err)
	}

	if s.verbose && status != nil {
		fmt.Printf("Vulnerability database loaded (version: %s)\n", status.SchemaVersion)
	}

	// Convert Syft packages to Grype package format
	packages := pkg.FromCollection(sbomModel.Artifacts.Packages, pkg.SynthesisConfig{})

	if s.verbose {
		fmt.Printf("Scanning %d packages for vulnerabilities...\n", len(packages))
	}

	// Create package context from SBOM
	pkgContext := pkg.Context{
		Source: &sbomModel.Source,
		Distro: nil, // Will be inferred from packages if available
	}

	// Create vulnerability matcher with stock matcher
	matcher := &grype.VulnerabilityMatcher{
		VulnerabilityProvider: vulnProvider,
		Matchers: []match.Matcher{
			stock.NewStockMatcher(stock.MatcherConfig{
				UseCPEs: true,
			}),
		},
	}

	// Perform vulnerability matching
	allMatches, ignoredMatches, err := matcher.FindMatchesContext(ctx, packages, pkgContext)
	if err != nil {
		return nil, fmt.Errorf("failed to find vulnerabilities: %w", err)
	}

	if s.verbose {
		fmt.Printf("Found %d vulnerabilities\n", len(allMatches.Sorted()))
	}

	// Convert matches to our result format
	result := &ScanResult{
		Matches:        make([]VulnerabilityMatch, 0),
		IgnoredMatches: make([]VulnerabilityMatch, 0),
		Source:         sbomModel,
	}

	for _, m := range allMatches.Sorted() {
		vulnMatch := s.convertMatch(m)
		result.Matches = append(result.Matches, vulnMatch)
	}

	// Convert ignored matches
	for _, im := range ignoredMatches {
		vulnMatch := s.convertMatch(im.Match)
		result.IgnoredMatches = append(result.IgnoredMatches, vulnMatch)
	}

	return result, nil
}

// convertMatch converts a Grype match to our VulnerabilityMatch format
func (s *Scanner) convertMatch(m match.Match) VulnerabilityMatch {
	// Extract metadata
	severity := "Unknown"
	description := ""
	var cvssScores []CVSS
	var urls []string

	if m.Vulnerability.Metadata != nil {
		if m.Vulnerability.Metadata.Severity != "" {
			severity = m.Vulnerability.Metadata.Severity
		}
		if m.Vulnerability.Metadata.Description != "" {
			description = m.Vulnerability.Metadata.Description
		}
		// Extract CVSS scores
		for _, cvssData := range m.Vulnerability.Metadata.Cvss {
			cvssScores = append(cvssScores, CVSS{
				Version: cvssData.Version,
				Vector:  cvssData.Vector,
				Score:   cvssData.Metrics.BaseScore,
			})
		}
	}

	// Convert related vulnerabilities to URLs
	for _, ref := range m.Vulnerability.RelatedVulnerabilities {
		urls = append(urls, ref.ID)
	}

	vuln := VulnerabilityMatch{
		Vulnerability: Vulnerability{
			ID:          m.Vulnerability.ID,
			Severity:    severity,
			Description: description,
			URLs:        urls,
			CVSS:        cvssScores,
		},
		Package: Package{
			Name:    m.Package.Name,
			Version: m.Package.Version,
			Type:    string(m.Package.Type),
			PURL:    m.Package.PURL,
		},
		MatchDetails: make([]MatchDetail, 0),
	}

	// Add match details
	for _, detail := range m.Details {
		vuln.MatchDetails = append(vuln.MatchDetails, MatchDetail{
			Type:       string(detail.Type),
			Confidence: fmt.Sprintf("%.2f", detail.Confidence),
			Matcher:    string(detail.Matcher),
		})
	}

	return vuln
}

// FilterBySeverity filters matches by minimum severity level
func (s *Scanner) FilterBySeverity(matches []VulnerabilityMatch, minSeverity string) []VulnerabilityMatch {
	severityOrder := map[string]int{
		"Critical":   4,
		"High":       3,
		"Medium":     2,
		"Low":        1,
		"Negligible": 0,
	}

	minLevel, ok := severityOrder[minSeverity]
	if !ok {
		return matches // Invalid severity, return all
	}

	filtered := make([]VulnerabilityMatch, 0)
	for _, m := range matches {
		if severityOrder[m.Vulnerability.Severity] >= minLevel {
			filtered = append(filtered, m)
		}
	}

	return filtered
}

// FormatJSON converts scan results to JSON
func (s *Scanner) FormatJSON(result *ScanResult) (string, error) {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal JSON: %w", err)
	}
	return string(data), nil
}

// FormatTable converts scan results to table format
func (s *Scanner) FormatTable(result *ScanResult) string {
	output := fmt.Sprintf("%-20s %-15s %-40s %-15s\n", "VULNERABILITY", "SEVERITY", "PACKAGE", "VERSION")
	output += fmt.Sprintf("%s\n", "----------------------------------------------------------------------------------------------------")

	for _, m := range result.Matches {
		pkg := fmt.Sprintf("%s:%s", m.Package.Name, m.Package.Version)
		if len(pkg) > 40 {
			pkg = pkg[:37] + "..."
		}
		output += fmt.Sprintf("%-20s %-15s %-40s %-15s\n",
			m.Vulnerability.ID,
			m.Vulnerability.Severity,
			pkg,
			m.Package.Version,
		)
	}

	output += fmt.Sprintf("\nTotal vulnerabilities: %d\n", len(result.Matches))
	return output
}
