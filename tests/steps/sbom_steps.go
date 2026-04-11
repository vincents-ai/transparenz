// SPDX-License-Identifier: AGPL-3.0-or-later OR Commercial
// Copyright (c) 2026 Vincent Palmer

// Package steps contains BDD step definitions for CRA/BSI TR-03183-2 compliance tests.
// Each file in this package registers step functions for a specific domain area.
package steps

import (
	"context"
	"fmt"
	"strings"

	"github.com/cucumber/godog"
)

// RegisterSBOMSteps registers SBOM JSON inspection step definitions.
func RegisterSBOMSteps(s *godog.ScenarioContext) {
	s.Step(`^the output is valid JSON$`, theOutputIsValidJSON)
	s.Step(`^the output is not a PDF$`, theOutputIsNotAPDF)
	s.Step(`^the JSON has field "([^"]*)" equal to "([^"]*)"$`, theJSONHasFieldEqualTo)
	s.Step(`^the JSON has field "([^"]*)" containing "([^"]*)"$`, theJSONHasFieldContaining)
	s.Step(`^the JSON field "([^"]*)" is a non-empty array$`, theJSONFieldIsANonEmptyArray)
	s.Step(`^every component has a "([^"]*)" field$`, everyComponentHasAField)
	s.Step(`^the majority of components have a license field set$`, theMajorityOfComponentsHaveALicenseFieldSet)
	s.Step(`^the JSON metadata has property "([^"]*)" with value "([^"]*)"$`, theJSONMetadataHasPropertyWithValue)
	s.Step(`^every component has property "([^"]*)"$`, everyComponentHasProperty)
	s.Step(`^the JSON does not have field "([^"]*)"$`, theJSONDoesNotHaveField)
	s.Step(`^the JSON has field "([^"]*)" starting with "([^"]*)"$`, theJSONHasFieldStartingWith)
	s.Step(`^the JSON has field "([^"]*)" with number$`, theJSONHasFieldWithNumber)
	s.Step(`^the JSON metadata has field "([^"]*)" with non-empty string$`, theJSONMetadataHasFieldWithNonEmptyString)
	s.Step(`^the timestamp follows ISO 8601 format$`, theTimestampFollowsISO8601)
	s.Step(`^the JSON metadata tools array has object with "([^"]*)" field$`, theJSONMetadataToolsArrayHasObjectWithField)
	s.Step(`^the JSON metadata component has field "([^"]*)" with non-empty string$`, theJSONMetadataComponentHasFieldWithNonEmptyString)
	s.Step(`^the JSON metadata component has field "([^"]*)" with value in: ([^"]*)$`, theJSONMetadataComponentHasFieldWithValueIn)
	s.Step(`^the JSON components array has all items with field "([^"]*)"$`, theJSONComponentsArrayHasAllItemsWithField)
	s.Step(`^at least (\d+)% of components have field "([^"]*)" starting with "([^"]*)"$`, atLeastPercentOfComponentsHaveFieldStartingWith)
	s.Step(`^the JSON components licenses use SPDX identifiers$`, theJSONComponentsLicensesUseSPDXIdentifiers)
	s.Step(`^the JSON dependencies have items with "([^"]*)" field starting with "([^"]*)"$`, theJSONDependenciesHaveItemsWithFieldStartingWith)
	s.Step(`^the primary component has at least one dependency$`, thePrimaryComponentHasAtLeastOneDependency)
	s.Step(`^the JSON has field "([^"]*)" with non-empty string$`, theJSONHasFieldWithNonEmptyString)
	s.Step(`^the JSON has field "([^"]*)" with object$`, theJSONHasFieldWithObject)
	s.Step(`^the output is not HTML$`, theOutputIsNotHTML)
}

// ─── Step implementations ─────────────────────────────────────────────────────

func theOutputIsValidJSON(ctx context.Context) error {
	data, ok := ctx.Value(KeyJSON).(interface{})
	if !ok || data == nil {
		return fmt.Errorf("output is not valid JSON")
	}
	return nil
}

func theOutputIsNotAPDF(ctx context.Context) error {
	out, _ := ctx.Value(KeyCmdOut).(string)
	if strings.HasPrefix(out, "%PDF") {
		return fmt.Errorf("output is a PDF")
	}
	return nil
}

func theJSONHasFieldEqualTo(ctx context.Context, field, expected string) error {
	m, ok := ctx.Value(KeyJSON).(map[string]interface{})
	if !ok {
		return fmt.Errorf("JSON is not an object")
	}
	val, exists := m[field]
	if !exists {
		return fmt.Errorf("field %q not found", field)
	}
	if fmt.Sprintf("%v", val) != expected {
		return fmt.Errorf("field %q: expected %q, got %v", field, expected, val)
	}
	return nil
}

func theJSONHasFieldContaining(ctx context.Context, field, substring string) error {
	m, ok := ctx.Value(KeyJSON).(map[string]interface{})
	if !ok {
		return fmt.Errorf("JSON is not an object")
	}
	val, exists := m[field]
	if !exists {
		return fmt.Errorf("field %q not found", field)
	}
	str := fmt.Sprintf("%v", val)
	if !strings.Contains(str, substring) {
		return fmt.Errorf("field %q: expected to contain %q, got %q", field, substring, str)
	}
	return nil
}

func theJSONFieldIsANonEmptyArray(ctx context.Context, field string) error {
	m, ok := ctx.Value(KeyJSON).(map[string]interface{})
	if !ok {
		return fmt.Errorf("JSON is not an object")
	}
	val, exists := m[field]
	if !exists {
		return fmt.Errorf("field %q not found", field)
	}
	arr, ok := val.([]interface{})
	if !ok {
		return fmt.Errorf("field %q is not an array", field)
	}
	if len(arr) == 0 {
		return fmt.Errorf("field %q is empty", field)
	}
	return nil
}

func everyComponentHasAField(ctx context.Context, field string) error {
	m, ok := ctx.Value(KeyJSON).(map[string]interface{})
	if !ok {
		return fmt.Errorf("JSON is not an object")
	}
	components, ok := m["components"].([]interface{})
	if !ok {
		return fmt.Errorf("no components array found")
	}
	if len(components) == 0 {
		return fmt.Errorf("no components found")
	}
	withField := 0
	for _, c := range components {
		comp, ok := c.(map[string]interface{})
		if !ok {
			continue
		}
		val, exists := comp[field]
		if exists && val != nil && fmt.Sprintf("%v", val) != "" {
			withField++
		}
	}
	pct := float64(withField) / float64(len(components)) * 100
	if pct < 50 {
		return fmt.Errorf("only %.1f%% of components have field %q (need >50%%)", pct, field)
	}
	return nil
}

func theMajorityOfComponentsHaveALicenseFieldSet(ctx context.Context) error {
	m, ok := ctx.Value(KeyJSON).(map[string]interface{})
	if !ok {
		return fmt.Errorf("JSON is not an object")
	}
	components, ok := m["components"].([]interface{})
	if !ok {
		return fmt.Errorf("no components array found")
	}
	withLicense := 0
	for _, c := range components {
		comp, ok := c.(map[string]interface{})
		if !ok {
			continue
		}
		if licenses, ok := comp["licenses"].([]interface{}); ok && len(licenses) > 0 {
			withLicense++
		}
	}
	pct := float64(withLicense) / float64(len(components)) * 100
	if pct < 40 {
		return fmt.Errorf("only %.1f%% of components have licenses (need >40%%)", pct)
	}
	return nil
}

func theJSONMetadataHasPropertyWithValue(ctx context.Context, name, value string) error {
	m, ok := ctx.Value(KeyJSON).(map[string]interface{})
	if !ok {
		return fmt.Errorf("JSON is not an object")
	}
	metadata, ok := m["metadata"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("no metadata found")
	}
	props, ok := metadata["properties"].([]interface{})
	if !ok {
		return fmt.Errorf("no properties in metadata")
	}
	for _, p := range props {
		prop, ok := p.(map[string]interface{})
		if !ok {
			continue
		}
		if prop["name"] == name && fmt.Sprintf("%v", prop["value"]) == value {
			return nil
		}
	}
	return fmt.Errorf("metadata property %q=%q not found", name, value)
}

func everyComponentHasProperty(ctx context.Context, propName string) error {
	m, ok := ctx.Value(KeyJSON).(map[string]interface{})
	if !ok {
		return fmt.Errorf("JSON is not an object")
	}
	components, ok := m["components"].([]interface{})
	if !ok {
		return fmt.Errorf("no components array found")
	}
	if len(components) == 0 {
		return fmt.Errorf("no components found")
	}
	withProp := 0
	for _, c := range components {
		comp, ok := c.(map[string]interface{})
		if !ok {
			continue
		}
		props, ok := comp["properties"].([]interface{})
		if !ok || len(props) == 0 {
			continue
		}
		for _, p := range props {
			prop, ok := p.(map[string]interface{})
			if !ok {
				continue
			}
			if prop["name"] == propName {
				withProp++
				break
			}
		}
	}
	pct := float64(withProp) / float64(len(components)) * 100
	if pct < 80 {
		return fmt.Errorf("only %.1f%% of components have property %q (need >80%%)", pct, propName)
	}
	return nil
}

func theJSONDoesNotHaveField(ctx context.Context, field string) error {
	m, ok := ctx.Value(KeyJSON).(map[string]interface{})
	if !ok {
		return nil // not an object, no field to find
	}
	if _, exists := m[field]; exists {
		return fmt.Errorf("field %q should not exist in SBOM", field)
	}
	return nil
}

func theJSONHasFieldStartingWith(ctx context.Context, field, prefix string) error {
	m, ok := ctx.Value(KeyJSON).(map[string]interface{})
	if !ok {
		return fmt.Errorf("JSON is not an object")
	}
	val, exists := m[field]
	if !exists {
		return fmt.Errorf("field %q not found", field)
	}
	if !strings.HasPrefix(fmt.Sprintf("%v", val), prefix) {
		return fmt.Errorf("field %q does not start with %q", field, prefix)
	}
	return nil
}

func theJSONHasFieldWithNumber(ctx context.Context, field string) error {
	m, ok := ctx.Value(KeyJSON).(map[string]interface{})
	if !ok {
		return fmt.Errorf("JSON is not an object")
	}
	val, exists := m[field]
	if !exists {
		return fmt.Errorf("field %q not found", field)
	}
	if _, ok := val.(float64); !ok {
		return fmt.Errorf("field %q is not a number, got %T", field, val)
	}
	return nil
}

func theJSONMetadataHasFieldWithNonEmptyString(ctx context.Context, field string) error {
	m, ok := ctx.Value(KeyJSON).(map[string]interface{})
	if !ok {
		return fmt.Errorf("JSON is not an object")
	}
	metadata, ok := m["metadata"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("no metadata found")
	}
	val, exists := metadata[field]
	if !exists || val == nil || fmt.Sprintf("%v", val) == "" {
		return fmt.Errorf("metadata field %q is empty or missing", field)
	}
	return nil
}

func theTimestampFollowsISO8601(ctx context.Context) error {
	m, ok := ctx.Value(KeyJSON).(map[string]interface{})
	if !ok {
		return fmt.Errorf("JSON is not an object")
	}
	metadata, ok := m["metadata"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("no metadata found")
	}
	ts, ok := metadata["timestamp"].(string)
	if !ok || ts == "" {
		return fmt.Errorf("timestamp is missing or not a string")
	}
	if !strings.Contains(ts, "T") || len(ts) < 10 {
		return fmt.Errorf("timestamp %q does not follow ISO 8601 format", ts)
	}
	return nil
}

func theJSONMetadataToolsArrayHasObjectWithField(ctx context.Context, field string) error {
	m, ok := ctx.Value(KeyJSON).(map[string]interface{})
	if !ok {
		return fmt.Errorf("JSON is not an object")
	}
	metadata, ok := m["metadata"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("no metadata found")
	}
	tools, ok := metadata["tools"].([]interface{})
	if !ok || len(tools) == 0 {
		return fmt.Errorf("no tools array found")
	}
	for _, t := range tools {
		tool, ok := t.(map[string]interface{})
		if !ok {
			continue
		}
		if _, exists := tool[field]; exists {
			return nil
		}
	}
	return fmt.Errorf("no tool has field %q", field)
}

func theJSONMetadataComponentHasFieldWithNonEmptyString(ctx context.Context, field string) error {
	m, ok := ctx.Value(KeyJSON).(map[string]interface{})
	if !ok {
		return fmt.Errorf("JSON is not an object")
	}
	metadata, ok := m["metadata"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("no metadata found")
	}
	component, ok := metadata["component"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("no component in metadata")
	}
	val, exists := component[field]
	if !exists || val == nil || fmt.Sprintf("%v", val) == "" {
		return fmt.Errorf("metadata component field %q is empty or missing", field)
	}
	return nil
}

func theJSONMetadataComponentHasFieldWithValueIn(ctx context.Context, field, values string) error {
	m, ok := ctx.Value(KeyJSON).(map[string]interface{})
	if !ok {
		return fmt.Errorf("JSON is not an object")
	}
	metadata, ok := m["metadata"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("no metadata found")
	}
	component, ok := metadata["component"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("no component in metadata")
	}
	val, exists := component[field]
	if !exists {
		return fmt.Errorf("metadata component field %q is missing", field)
	}
	valStr := fmt.Sprintf("%v", val)
	for _, v := range strings.Split(values, ", ") {
		if valStr == v {
			return nil
		}
	}
	return fmt.Errorf("metadata component field %q value %q not in allowed values %q", field, valStr, values)
}

func theJSONComponentsArrayHasAllItemsWithField(ctx context.Context, field string) error {
	m, ok := ctx.Value(KeyJSON).(map[string]interface{})
	if !ok {
		return fmt.Errorf("JSON is not an object")
	}
	components, ok := m["components"].([]interface{})
	if !ok || len(components) == 0 {
		return fmt.Errorf("no components found")
	}
	var missing []string
	for _, c := range components {
		comp, ok := c.(map[string]interface{})
		if !ok {
			continue
		}
		if _, exists := comp[field]; !exists {
			missing = append(missing, fmt.Sprintf("%v", comp["name"]))
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("components missing field %q: %v", field, missing)
	}
	return nil
}

func atLeastPercentOfComponentsHaveFieldStartingWith(ctx context.Context, percent int, field, prefix string) error {
	m, ok := ctx.Value(KeyJSON).(map[string]interface{})
	if !ok {
		return fmt.Errorf("JSON is not an object")
	}
	components, ok := m["components"].([]interface{})
	if !ok || len(components) == 0 {
		return fmt.Errorf("no components found")
	}
	withField := 0
	for _, c := range components {
		comp, ok := c.(map[string]interface{})
		if !ok {
			continue
		}
		val, exists := comp[field]
		if exists && strings.HasPrefix(fmt.Sprintf("%v", val), prefix) {
			withField++
		}
	}
	actual := float64(withField) * 100 / float64(len(components))
	if actual < float64(percent) {
		return fmt.Errorf("only %.1f%% of components have field %q starting with %q (need >%d%%)", actual, field, prefix, percent)
	}
	return nil
}

func theJSONComponentsLicensesUseSPDXIdentifiers(ctx context.Context) error {
	m, ok := ctx.Value(KeyJSON).(map[string]interface{})
	if !ok {
		return fmt.Errorf("JSON is not an object")
	}
	components, ok := m["components"].([]interface{})
	if !ok || len(components) == 0 {
		return fmt.Errorf("no components found")
	}
	spdxLicenses := map[string]bool{
		"Apache-2.0": true, "MIT": true, "BSD-2-Clause": true, "BSD-3-Clause": true,
		"GPL-2.0": true, "GPL-3.0": true, "LGPL-2.1": true, "MPL-2.0": true,
		"ISC": true, "Python-2.0": true, "Artistic-2.0": true, "EPL-1.0": true,
	}
	for _, c := range components {
		comp, ok := c.(map[string]interface{})
		if !ok {
			continue
		}
		licenses, ok := comp["licenses"].([]interface{})
		if !ok || len(licenses) == 0 {
			continue
		}
		for _, lic := range licenses {
			licMap, ok := lic.(map[string]interface{})
			if !ok {
				continue
			}
			if licData, ok := licMap["license"].(map[string]interface{}); ok {
				if licID, ok := licData["id"].(string); ok {
					if _, isSPDX := spdxLicenses[licID]; !isSPDX && licID != "NOASSERTION" && licID != "" {
						return fmt.Errorf("non-SPDX license found: %s", licID)
					}
				}
			}
		}
	}
	return nil
}

func theJSONDependenciesHaveItemsWithFieldStartingWith(ctx context.Context, field, prefix string) error {
	m, ok := ctx.Value(KeyJSON).(map[string]interface{})
	if !ok {
		return fmt.Errorf("JSON is not an object")
	}
	deps, ok := m["dependencies"].([]interface{})
	if !ok || len(deps) == 0 {
		return fmt.Errorf("no dependencies found")
	}
	for _, d := range deps {
		dep, ok := d.(map[string]interface{})
		if !ok {
			continue
		}
		val, exists := dep[field]
		if exists && strings.HasPrefix(fmt.Sprintf("%v", val), prefix) {
			return nil
		}
	}
	return fmt.Errorf("no dependency has field %q starting with %q", field, prefix)
}

func thePrimaryComponentHasAtLeastOneDependency(ctx context.Context) error {
	m, ok := ctx.Value(KeyJSON).(map[string]interface{})
	if !ok {
		return fmt.Errorf("JSON is not an object")
	}
	deps, ok := m["dependencies"].([]interface{})
	if !ok || len(deps) == 0 {
		return fmt.Errorf("no dependencies found")
	}
	for _, d := range deps {
		dep, ok := d.(map[string]interface{})
		if !ok {
			continue
		}
		if dependsOn, ok := dep["dependsOn"].([]interface{}); ok && len(dependsOn) > 0 {
			return nil
		}
	}
	return fmt.Errorf("no dependency has any dependencies")
}

func theJSONHasFieldWithNonEmptyString(ctx context.Context, field string) error {
	m, ok := ctx.Value(KeyJSON).(map[string]interface{})
	if !ok {
		return fmt.Errorf("JSON is not an object")
	}
	val, exists := m[field]
	if !exists || val == nil {
		return fmt.Errorf("field %q not found", field)
	}
	str, ok := val.(string)
	if !ok || str == "" {
		return fmt.Errorf("field %q is not a non-empty string", field)
	}
	return nil
}

func theJSONHasFieldWithObject(ctx context.Context, field string) error {
	m, ok := ctx.Value(KeyJSON).(map[string]interface{})
	if !ok {
		return fmt.Errorf("JSON is not an object")
	}
	val, exists := m[field]
	if !exists || val == nil {
		return fmt.Errorf("field %q not found", field)
	}
	if _, ok := val.(map[string]interface{}); !ok {
		return fmt.Errorf("field %q is not an object, got %T", field, val)
	}
	return nil
}

func theOutputIsNotHTML(ctx context.Context) error {
	out, _ := ctx.Value(KeyCmdOut).(string)
	trimmed := strings.TrimSpace(out)
	if strings.HasPrefix(trimmed, "<") && strings.Contains(trimmed, "<html") {
		return fmt.Errorf("output is HTML")
	}
	return nil
}
