// SPDX-License-Identifier: AGPL-3.0-or-later OR Commercial
// Copyright (c) 2026 Vincent Palmer

package bsi

import (
	"encoding/json"
	"fmt"
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
// It checks for mandatory properties and dependency completeness.
func (v *validator) Validate(sbomJSON string) (*ValidationResult, error) {
	var sbomData map[string]interface{}
	if err := json.Unmarshal([]byte(sbomJSON), &sbomData); err != nil {
		return nil, err
	}

	result := &ValidationResult{
		Valid:    true,
		Findings: []ValidationFinding{},
	}

	// Check for BSI TR-03183-2 mandatory properties
	if bomFormat, ok := sbomData["bomFormat"].(string); ok && bomFormat == "CycloneDX" {
		v.validateCycloneDX(sbomData, result)
	} else {
		v.validateSPDX(sbomData, result)
	}

	return result, nil
}

// validateCycloneDX validates CycloneDX format SBOMs
func (v *validator) validateCycloneDX(sbomData map[string]interface{}, result *ValidationResult) {
	components, ok := sbomData["components"].([]interface{})
	if !ok {
		result.Valid = false
		result.Findings = append(result.Findings, ValidationFinding{
			Issue:    "Missing components in CycloneDX SBOM",
			Severity:  "high",
		})
		return
	}

	// Check each component for BSI mandatory properties
	for i, compData := range components {
		comp, ok := compData.(map[string]interface{})
		if !ok {
			continue
		}

		// Check for BSI properties (executable, archive, structured)
		if props, ok := comp["properties"].([]interface{}); ok {
			hasExecutable := false
			hasArchive := false
			hasStructured := false

			for _, p := range props {
				if prop, ok := p.(map[string]interface{}); ok {
					name, _ := prop["name"].(string)
					if name == "executable" {
						hasExecutable = true
					}
					if name == "archive" {
						hasArchive = true
					}
					if name == "structured" {
						hasStructured = true
					}
				}
			}

			if !hasExecutable || !hasArchive || !hasStructured {
				result.Findings = append(result.Findings, ValidationFinding{
					Component: fmt.Sprintf("component[%d]", i),
					Issue:     "Missing BSI TR-03183-2 mandatory properties (executable, archive, structured)",
					Severity:  "medium",
				})
				result.Valid = false
			}
		}
	}

	// Check dependency completeness
	v.checkDependencyCompleteness(sbomData, result)
}

// validateSPDX validates SPDX format SBOMs
func (v *validator) validateSPDX(sbomData map[string]interface{}, result *ValidationResult) {
	packages, ok := sbomData["packages"].([]interface{})
	if !ok {
		result.Valid = false
		result.Findings = append(result.Findings, ValidationFinding{
			Issue:    "Missing packages in SPDX SBOM",
			Severity: "high",
		})
		return
	}

	// Check for BSI annotations
	for i, pkgData := range packages {
		pkg, ok := pkgData.(map[string]interface{})
		if !ok {
			continue
		}

		// Check for BSI annotations
		if annotations, ok := pkg["annotations"].([]interface{}); ok {
			hasBSI := false
			for _, a := range annotations {
				if ann, ok := a.(map[string]interface{}); ok {
					if comment, ok := ann["comment"].(string); ok && contains(comment, "BSI TR-03183-2") {
						hasBSI = true
						break
					}
				}
			}

			if !hasBSI {
				result.Findings = append(result.Findings, ValidationFinding{
					Component: fmt.Sprintf("package[%d]", i),
					Issue:     "Missing BSI TR-03183-2 annotations",
					Severity:  "medium",
				})
				result.Valid = false
			}
		}
	}

	// Check dependency completeness
	v.checkDependencyCompleteness(sbomData, result)
}

// checkDependencyCompleteness checks if the SBOM declares dependency completeness
func (v *validator) checkDependencyCompleteness(sbomData map[string]interface{}, result *ValidationResult) {
	if bomFormat, ok := sbomData["bomFormat"].(string); ok && bomFormat == "CycloneDX" {
		// CycloneDX: check metadata.properties for completeness
		if metadata, ok := sbomData["metadata"].(map[string]interface{}); ok {
			if props, ok := metadata["properties"].([]interface{}); ok {
				for _, p := range props {
					if prop, ok := p.(map[string]interface{}); ok {
						if name, _ := prop["name"].(string); name == "completeness" {
							return // Found completeness declaration
						}
					}
				}
			}
		}
	} else {
		// SPDX: check for completeness annotation
		if annotations, ok := sbomData["annotations"].([]interface{}); ok {
			for _, a := range annotations {
				if ann, ok := a.(map[string]interface{}); ok {
					if comment, ok := ann["comment"].(string); ok && contains(comment, "dependencyCompleteness") {
						return // Found completeness declaration
					}
				}
			}
		}
	}

	result.Valid = false
	result.Findings = append(result.Findings, ValidationFinding{
		Issue:    "Missing dependency completeness declaration (BSI TR-03183-2 Section 4.2)",
		Severity: "high",
	})
}

// contains checks if a string contains a substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && (s[0:len(substr)] == substr || contains(s[1:], substr)))
}
