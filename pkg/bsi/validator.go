// SPDX-License-Identifier: AGPL-3.0-or-later OR Commercial
// Copyright (c) 2026 Vincent Palmer

package bsi

import (
	"encoding/json"
)

// ValidationResult contains the result of BSI TR-03183-2 validation
type ValidationResult struct {
	Valid    bool
	Findings []ValidationFinding
}

// ValidationFinding represents a single validation finding
type ValidationFinding struct {
	Component string
	Issue     string
	Severity  string
}

// BSIValidator defines the interface for BSI TR-03183-2 validation
type BSIValidator interface {
	// Validate checks if an SBOM meets BSI TR-03183-2 requirements
	Validate(sbomJSON string) (*ValidationResult, error)
}

// validator implements BSIValidator
type validator struct{}

// NewValidator creates a new BSI validator
func NewValidator() BSIValidator {
	return &validator{}
}

// Validate checks if an SBOM meets BSI TR-03183-2 requirements.
// It delegates to the canonical conformance checker (CheckConformance, also
// used by the `transparenz bsi-check` CLI) so the library and the CLI enforce
// the same rules. Previously Validate() ran a weaker, divergent check that let
// SBOMs missing hashes/licenses/suppliers pass — see the regulatory review.
// The richer conformance report (coverage scores, per-component findings with
// remediation) is translated into this package's ValidationResult shape.
func (v *validator) Validate(sbomJSON string) (*ValidationResult, error) {
	var sbomData map[string]interface{}
	if err := json.Unmarshal([]byte(sbomJSON), &sbomData); err != nil {
		return nil, err
	}

	report := CheckConformance(sbomData)

	result := &ValidationResult{
		Valid:    true,
		Findings: []ValidationFinding{},
	}
	if compliant, ok := report["compliant"].(bool); ok {
		result.Valid = compliant
	}
	if findings, ok := report["findings"].([]ConformanceFinding); ok {
		for _, f := range findings {
			result.Findings = append(result.Findings, ValidationFinding{
				Component: f.Component,
				Issue:     f.Message,
				Severity:  f.Severity,
			})
		}
	}
	// Surface the top-level structural failure (no packages/components) which
	// CheckConformance reports as an "error" rather than a per-component finding.
	if errMsg, ok := report["error"].(string); ok {
		result.Valid = false
		result.Findings = append(result.Findings, ValidationFinding{
			Issue:    errMsg,
			Severity: "high",
		})
	}

	return result, nil
}
