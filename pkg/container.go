// SPDX-License-Identifier: AGPL-3.0-or-later OR Commercial
// Copyright (c) 2026 Vincent Palmer

package transparenz

import (
	"context"

	"github.com/vincents-ai/transparenz/pkg/bsi"
	"github.com/vincents-ai/transparenz/pkg/sbom"
)

// Container holds all dependencies for the transparenz application.
// It uses interfaces for better testability and loose coupling.
type Container struct {
	// SBOM generator
	Generator sbom.SBOMGenerator

	// BSI enricher for compliance
	Enricher bsi.BSIEnricher

	// Vulnerability matcher
	Matcher sbom.VulnerabilityMatcher

	// BSI validator
	Validator bsi.BSIValidator

	// Configuration
	Verbose bool
}

// ContainerOption configures the Container
type ContainerOption func(*Container)

// WithVerbose sets the verbose flag
func WithVerbose(verbose bool) ContainerOption {
	return func(c *Container) {
		c.Verbose = verbose
	}
}

// WithGenerator sets a custom SBOM generator
func WithGenerator(gen sbom.SBOMGenerator) ContainerOption {
	return func(c *Container) {
		c.Generator = gen
	}
}

// WithEnricher sets a custom BSI enricher
func WithEnricher(enricher bsi.BSIEnricher) ContainerOption {
	return func(c *Container) {
		c.Enricher = enricher
	}
}

// WithMatcher sets a custom vulnerability matcher
func WithMatcher(matcher sbom.VulnerabilityMatcher) ContainerOption {
	return func(c *Container) {
		c.Matcher = matcher
	}
}

// WithValidator sets a custom BSI validator
func WithValidator(validator bsi.BSIValidator) ContainerOption {
	return func(c *Container) {
		c.Validator = validator
	}
}

// NewContainer creates a new Container with the given options.
// If no options are provided, it creates default implementations.
func NewContainer(opts ...ContainerOption) *Container {
	c := &Container{}

	// Apply options
	for _, opt := range opts {
		opt(c)
	}

	// Set defaults if not provided
	if c.Generator == nil {
		c.Generator = sbom.NewGenerator(c.Verbose)
	}
	if c.Enricher == nil {
		c.Enricher = bsi.NewEnricher(".")
	}
	if c.Matcher == nil {
		c.Matcher = sbom.NewVulnzMatcher()
	}
	if c.Validator == nil {
		c.Validator = bsi.NewValidator()
	}

	return c
}

// GenerateSBOM generates an SBOM using the configured generator
func (c *Container) GenerateSBOM(ctx context.Context, sourcePath, format string) (string, error) {
	return c.Generator.Generate(ctx, sourcePath, format)
}

// EnrichSBOM enriches an SBOM using the configured enricher
func (c *Container) EnrichSBOM(sbomJSON string) (string, error) {
	return c.Enricher.EnrichSBOM(sbomJSON)
}

// MatchVulnerabilities matches SBOM components against vulnerabilities
func (c *Container) MatchVulnerabilities(components []sbom.SBOMComponent) []sbom.VulnerabilityMatch {
	return c.Matcher.MatchComponents(components)
}

// ValidateSBOM validates an SBOM against BSI TR-03183-2
func (c *Container) ValidateSBOM(sbomJSON string) (*bsi.ValidationResult, error) {
	return c.Validator.Validate(sbomJSON)
}
