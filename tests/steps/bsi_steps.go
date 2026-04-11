// SPDX-License-Identifier: AGPL-3.0-or-later OR Commercial
// Copyright (c) 2026 Vincent Palmer

package steps

import (
	"context"
	"fmt"

	"github.com/cucumber/godog"
)

// RegisterBSISteps registers BSI TR-03183-2 compliance report step definitions.
func RegisterBSISteps(s *godog.ScenarioContext) {
	s.Step(`^the JSON report has field "([^"]*)" with boolean$`, theJSONReportHasFieldWithBoolean)
	s.Step(`^the JSON report has field "([^"]*)" with number$`, theJSONReportHasFieldWithNumber)
	s.Step(`^the JSON report has field "([^"]*)" with string$`, theJSONReportHasFieldWithString)
	s.Step(`^the JSON report metadata has field "([^"]*)" equal to "([^"]*)"$`, theJSONReportMetadataHasFieldEqualTo)
	s.Step(`^the bsi-check report has "([^"]*)" at least (\d+)%$`, theBsiCheckReportHasFieldAtLeastPercent)
	s.Step(`^the JSON report has field "([^"]*)" equal to "([^"]*)"$`, theJSONReportHasFieldEqualTo)
	s.Step(`^the JSON report field "([^"]*)" is a non-empty array$`, theJSONReportFieldIsANonEmptyArray)
}

// ─── Step implementations ─────────────────────────────────────────────────────

func theJSONReportHasFieldWithBoolean(ctx context.Context, field string) error {
	m, ok := ctx.Value(KeyReportJSON).(map[string]interface{})
	if !ok {
		return fmt.Errorf("report JSON is not an object")
	}
	val, exists := m[field]
	if !exists {
		return fmt.Errorf("report field %q not found", field)
	}
	if _, ok := val.(bool); !ok {
		return fmt.Errorf("report field %q is not a boolean, got %T", field, val)
	}
	return nil
}

func theJSONReportHasFieldWithNumber(ctx context.Context, field string) error {
	m, ok := ctx.Value(KeyReportJSON).(map[string]interface{})
	if !ok {
		return fmt.Errorf("report JSON is not an object")
	}
	val, exists := m[field]
	if !exists {
		return fmt.Errorf("report field %q not found", field)
	}
	if _, ok := val.(float64); !ok {
		return fmt.Errorf("report field %q is not a number, got %T", field, val)
	}
	return nil
}

func theJSONReportHasFieldWithString(ctx context.Context, field string) error {
	m, ok := ctx.Value(KeyReportJSON).(map[string]interface{})
	if !ok {
		return fmt.Errorf("report JSON is not an object")
	}
	val, exists := m[field]
	if !exists {
		return fmt.Errorf("report field %q not found", field)
	}
	if _, ok := val.(string); !ok {
		return fmt.Errorf("report field %q is not a string, got %T", field, val)
	}
	return nil
}

func theJSONReportMetadataHasFieldEqualTo(ctx context.Context, field, expected string) error {
	m, ok := ctx.Value(KeyReportJSON).(map[string]interface{})
	if !ok {
		return fmt.Errorf("report JSON is not an object")
	}
	metadata, ok := m["metadata"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("report has no metadata")
	}
	val, exists := metadata[field]
	if !exists {
		return fmt.Errorf("metadata field %q not found", field)
	}
	if fmt.Sprintf("%v", val) != expected {
		return fmt.Errorf("metadata %q: expected %q, got %v", field, expected, val)
	}
	return nil
}

func theJSONReportHasFieldEqualTo(ctx context.Context, field, expected string) error {
	m, ok := ctx.Value(KeyReportJSON).(map[string]interface{})
	if !ok {
		return fmt.Errorf("report JSON is not an object")
	}
	val, exists := m[field]
	if !exists {
		return fmt.Errorf("report field %q not found", field)
	}
	if fmt.Sprintf("%v", val) != expected {
		return fmt.Errorf("report field %q: expected %q, got %v", field, expected, val)
	}
	return nil
}

func theJSONReportFieldIsANonEmptyArray(ctx context.Context, field string) error {
	m, ok := ctx.Value(KeyReportJSON).(map[string]interface{})
	if !ok {
		return fmt.Errorf("report JSON is not an object")
	}
	val, exists := m[field]
	if !exists {
		return fmt.Errorf("report field %q not found", field)
	}
	arr, ok := val.([]interface{})
	if !ok {
		return fmt.Errorf("report field %q is not an array", field)
	}
	if len(arr) == 0 {
		return fmt.Errorf("report field %q is empty", field)
	}
	return nil
}

func theBsiCheckReportHasFieldAtLeastPercent(ctx context.Context, field string, percent int) error {
	m, ok := ctx.Value(KeyReportJSON).(map[string]interface{})
	if !ok {
		return fmt.Errorf("report JSON not available")
	}
	val, exists := m[field]
	if !exists {
		return fmt.Errorf("report field %q not found", field)
	}
	valFloat, ok := val.(float64)
	if !ok {
		return fmt.Errorf("report field %q is not a number", field)
	}
	if valFloat < float64(percent) {
		return fmt.Errorf("report field %q is %.1f%%, need at least %d%%", field, valFloat, percent)
	}
	return nil
}
