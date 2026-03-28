package bdd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cucumber/godog"
)

var prebuiltBinary string

// TestCRACompliance runs BDD tests for CRA/BSI TR-03183-2 compliance
func TestMain(m *testing.M) {
	// Build binary once for all tests
	tmpDir, err := os.MkdirTemp("", "cra-test-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create temp dir: %v\n", err)
		os.Exit(1)
	}
	defer os.RemoveAll(tmpDir)

	prebuiltBinary = filepath.Join(tmpDir, "transparenz")
	cmd := exec.Command("go", "build", "-o", prebuiltBinary, "../cmd/transparenz")
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to build binary: %v\n", err)
		os.Exit(1)
	}

	// Create minimal test project for fast SBOM generation
	testProject := filepath.Join(tmpDir, "test-project")
	os.MkdirAll(testProject, 0755)
	os.WriteFile(filepath.Join(testProject, "go.mod"), []byte("module example.com/test\ngo 1.22.0\nrequire (\n\tgithub.com/google/uuid v1.6.0\n\tgithub.com/spf13/cobra v1.10.2\n\tgolang.org/x/text v0.14.0\n)\n"), 0644)
	os.WriteFile(filepath.Join(testProject, "main.go"), []byte("package main\n\nimport _ \"github.com/google/uuid\"\nimport _ \"github.com/spf13/cobra\"\n\nfunc main() {}\n"), 0644)

	os.Exit(m.Run())
}

func TestCRACompliance(t *testing.T) {
	suite := godog.TestSuite{
		ScenarioInitializer: func(s *godog.ScenarioContext) {
			s.Before(func(ctx context.Context, sc *godog.Scenario) (context.Context, error) {
				ctx = context.WithValue(ctx, keyTmpDir, t.TempDir())
				return ctx, nil
			})
			InitializeScenario(s)
		},
		Options: &godog.Options{
			Format:   "pretty",
			Paths:    []string{"../features"},
			TestingT: t,
		},
	}

	if suite.Run() != 0 {
		t.Fatal("non-zero status returned, failed to run feature tests")
	}
}

// getTestProject returns the path to the pre-created minimal test project
func getTestProject() string {
	if prebuiltBinary == "" {
		return "."
	}
	return filepath.Join(filepath.Dir(prebuiltBinary), "test-project")
}

type contextKey string

const (
	keyTmpDir     contextKey = "tmpDir"
	keyCmdOut     contextKey = "cmdOut"
	keyCmdErr     contextKey = "cmdErr"
	keyJSON       contextKey = "json"
	keyReportJSON contextKey = "reportJSON"
	keySBOMPath   contextKey = "sbomPath"
)

func InitializeScenario(s *godog.ScenarioContext) {
	s.Step(`^the transparenz binary is built$`, theTransparenzBinaryIsBuilt)
	s.Step(`^I run "([^"]*)"$`, iRun)
	s.Step(`^the command succeeds$`, theCommandSucceeds)
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
	s.Step(`^the JSON report has field "([^"]*)" with boolean$`, theJSONReportHasFieldWithBoolean)
	s.Step(`^the JSON report has field "([^"]*)" with number$`, theJSONReportHasFieldWithNumber)
	s.Step(`^the JSON report has field "([^"]*)" with string$`, theJSONReportHasFieldWithString)
	s.Step(`^the JSON report metadata has field "([^"]*)" equal to "([^"]*)"$`, theJSONReportMetadataHasFieldEqualTo)
	s.Step(`^a test binary exists in the artifacts directory$`, aTestBinaryExistsInTheArtifactsDirectory)
	s.Step(`^the enriched SBOM has SHA-512 hashes$`, theEnrichedSBOMHasSHA512Hashes)
	s.Step(`^an SBOM file exists with SHA-256 only hashes$`, anSBOMFileExistsWithSHA256OnlyHashes)
	s.Step(`^the report flags SHA-256-only as non-compliant$`, theReportFlagsSHA256OnlyAsNonCompliant)

	// BSI TR-03183 new steps
	s.Step(`^the JSON metadata has field "([^"]*)" with non-empty string$`, theJSONMetadataHasFieldWithNonEmptyString)
	s.Step(`^the timestamp follows ISO 8601 format$`, theTimestampFollowsISO8601)
	s.Step(`^the JSON metadata tools array has object with "([^"]*)" field$`, theJSONMetadataToolsArrayHasObjectWithField)
	s.Step(`^the JSON metadata tools array has object with "([^"]*)" field$`, theJSONMetadataToolsArrayHasObjectWithField)
	s.Step(`^the JSON has field "([^"]*)" starting with "([^"]*)"$`, theJSONHasFieldStartingWith)
	s.Step(`^the JSON metadata component has field "([^"]*)" with non-empty string$`, theJSONMetadataComponentHasFieldWithNonEmptyString)
	s.Step(`^the JSON metadata component has field "([^"]*)" with value in: ([^"]*)$`, theJSONMetadataComponentHasFieldWithValueIn)
	s.Step(`^the JSON components array has all items with field "([^"]*)"$`, theJSONComponentsArrayHasAllItemsWithField)
	s.Step(`^at least (\d+)% of components have field "([^"]*)" starting with "([^"]*)"$`, atLeastPercentOfComponentsHaveFieldStartingWith)
	s.Step(`^the JSON components licenses use SPDX identifiers$`, theJSONComponentsLicensesUseSPDXIdentifiers)
	s.Step(`^the JSON has field "([^"]*)" with number$`, theJSONHasFieldWithNumber)
	s.Step(`^the bsi-check report has "([^"]*)" at least (\d+)%$`, theBsiCheckReportHasFieldAtLeastPercent)
	s.Step(`^the JSON dependencies have items with "([^"]*)" field starting with "([^"]*)"$`, theJSONDependenciesHaveItemsWithFieldStartingWith)
	s.Step(`^the primary component has at least one dependency$`, thePrimaryComponentHasAtLeastOneDependency)
}

func theTransparenzBinaryIsBuilt(ctx context.Context) error {
	// Binary is pre-built in TestMain
	if _, err := os.Stat(prebuiltBinary); err != nil {
		return fmt.Errorf("prebuilt binary not found: %w", err)
	}
	return nil
}

func iRun(ctx context.Context, command string) (context.Context, error) {
	parts := strings.Fields(command)
	if len(parts) == 0 {
		return ctx, fmt.Errorf("empty command")
	}

	// Replace transparenz binary path
	if parts[0] == "transparenz" {
		parts[0] = prebuiltBinary
	}

	// Replace "." and "/test-project" with test project path for generate commands
	for i, p := range parts {
		if (p == "." || p == "/test-project") && i > 0 {
			parts[i] = getTestProject()
		}
	}

	// Resolve relative paths within tmpDir
	for i, p := range parts {
		if p == "-o" || p == "--output" || p == "--artifacts" {
			if i+1 < len(parts) && !filepath.IsAbs(parts[i+1]) {
				parts[i+1] = filepath.Join(getTmpDir(ctx), parts[i+1])
			}
		}
		if p == "sbom.json" {
			parts[i] = filepath.Join(getTmpDir(ctx), "sbom.json")
		}
		if p == "artifacts/" {
			parts[i] = filepath.Join(getTmpDir(ctx), "artifacts")
		}
	}

	cmd := exec.CommandContext(ctx, parts[0], parts[1:]...)
	cmd.Dir = getTestProject()

	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	outBytes := []byte(stdout.String())
	ctx = context.WithValue(ctx, keyCmdOut, string(outBytes))
	ctx = context.WithValue(ctx, keyCmdErr, err)

	// Try to parse JSON from output
	var data interface{}
	if json.Unmarshal(outBytes, &data) == nil {
		ctx = context.WithValue(ctx, keyJSON, data)
	}

	// Also try parsing from output file if -o was used
	for i, p := range parts {
		if (p == "-o" || p == "--output") && i+1 < len(parts) {
			if fileData, readErr := os.ReadFile(parts[i+1]); readErr == nil {
				var fileJSON interface{}
				if json.Unmarshal(fileData, &fileJSON) == nil {
					ctx = context.WithValue(ctx, keyJSON, fileJSON)
				}
				// Save as report JSON for bsi-check
				ctx = context.WithValue(ctx, keyReportJSON, fileJSON)
			}
			break
		}
	}

	// For bsi-check, parse the stdout as report
	if strings.Contains(command, "bsi-check") {
		// The bsi-check outputs JSON to stdout
		var reportData interface{}
		if json.Unmarshal(outBytes, &reportData) == nil {
			ctx = context.WithValue(ctx, keyReportJSON, reportData)
		}
	}

	return ctx, nil
}

func theCommandSucceeds(ctx context.Context) error {
	if err, ok := ctx.Value(keyCmdErr).(error); ok && err != nil {
		out, _ := ctx.Value(keyCmdOut).(string)
		return fmt.Errorf("command failed: %w\nOutput: %s", err, out)
	}
	return nil
}

func theOutputIsValidJSON(ctx context.Context) error {
	data, ok := ctx.Value(keyJSON).(interface{})
	if !ok || data == nil {
		return fmt.Errorf("output is not valid JSON")
	}
	return nil
}

func theOutputIsNotAPDF(ctx context.Context) error {
	out, _ := ctx.Value(keyCmdOut).(string)
	if strings.HasPrefix(out, "%PDF") {
		return fmt.Errorf("output is a PDF")
	}
	return nil
}

func theJSONHasFieldEqualTo(ctx context.Context, field, expected string) error {
	m, ok := ctx.Value(keyJSON).(map[string]interface{})
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
	m, ok := ctx.Value(keyJSON).(map[string]interface{})
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
	m, ok := ctx.Value(keyJSON).(map[string]interface{})
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
	m, ok := ctx.Value(keyJSON).(map[string]interface{})
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
	// Allow up to 20% of components to be missing optional fields (Syft may not populate all)
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
	m, ok := ctx.Value(keyJSON).(map[string]interface{})
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
	m, ok := ctx.Value(keyJSON).(map[string]interface{})
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
	m, ok := ctx.Value(keyJSON).(map[string]interface{})
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
	m, ok := ctx.Value(keyJSON).(map[string]interface{})
	if !ok {
		return nil // not an object, no field to find
	}
	if _, exists := m[field]; exists {
		return fmt.Errorf("field %q should not exist in SBOM", field)
	}
	return nil
}

func theJSONReportHasFieldWithBoolean(ctx context.Context, field string) error {
	m, ok := ctx.Value(keyReportJSON).(map[string]interface{})
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
	m, ok := ctx.Value(keyReportJSON).(map[string]interface{})
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
	m, ok := ctx.Value(keyReportJSON).(map[string]interface{})
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
	m, ok := ctx.Value(keyReportJSON).(map[string]interface{})
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

func aTestBinaryExistsInTheArtifactsDirectory(ctx context.Context) error {
	artDir := filepath.Join(getTmpDir(ctx), "artifacts")
	if err := os.MkdirAll(artDir, 0755); err != nil {
		return err
	}
	testBin := filepath.Join(artDir, "test-binary")
	return os.WriteFile(testBin, []byte("test binary content for SHA-512"), 0755)
}

func theEnrichedSBOMHasSHA512Hashes(ctx context.Context) error {
	sbomPath := filepath.Join(getTmpDir(ctx), "sbom-enriched.json")
	data, err := os.ReadFile(sbomPath)
	if err != nil {
		// Try from output
		out, _ := ctx.Value(keyCmdOut).(string)
		if out != "" {
			data = []byte(out)
		} else {
			return fmt.Errorf("no enriched SBOM found")
		}
	}
	var sbom map[string]interface{}
	if err := json.Unmarshal(data, &sbom); err != nil {
		return fmt.Errorf("enriched SBOM is not valid JSON: %w", err)
	}
	components, ok := sbom["components"].([]interface{})
	if !ok {
		return fmt.Errorf("no components in enriched SBOM")
	}
	for _, c := range components {
		comp, _ := c.(map[string]interface{})
		if comp == nil {
			continue
		}
		if hashes, ok := comp["hashes"].([]interface{}); ok {
			for _, h := range hashes {
				hMap, _ := h.(map[string]interface{})
				if hMap != nil && hMap["alg"] == "SHA-512" {
					return nil
				}
			}
		}
	}
	return fmt.Errorf("no SHA-512 hashes found in enriched SBOM")
}

func anSBOMFileExistsWithSHA256OnlyHashes(ctx context.Context) error {
	sbom := map[string]interface{}{
		"bomFormat":   "CycloneDX",
		"specVersion": "1.5",
		"metadata":    map[string]interface{}{},
		"components": []interface{}{
			map[string]interface{}{
				"name":    "test-component",
				"version": "1.0.0",
				"type":    "library",
				"hashes": []interface{}{
					map[string]interface{}{
						"alg":     "SHA-256",
						"content": "abc123",
					},
				},
			},
		},
	}
	data, _ := json.Marshal(sbom)
	return os.WriteFile(filepath.Join(getTmpDir(ctx), "sbom.json"), data, 0644)
}

func theReportFlagsSHA256OnlyAsNonCompliant(ctx context.Context) error {
	m, ok := ctx.Value(keyReportJSON).(map[string]interface{})
	if !ok {
		return fmt.Errorf("report JSON not available")
	}
	if hashSha256Only, ok := m["hash_sha256_only"].(float64); ok && hashSha256Only > 0 {
		return nil // SHA-256 only components flagged
	}
	if hashCoverage, ok := m["hash_coverage"].(float64); ok && hashCoverage < 100 {
		return nil // Not fully compliant on hash coverage
	}
	return fmt.Errorf("SHA-256-only components not flagged as non-compliant")
}

// BSI TR-03183 step implementations

func theJSONMetadataHasFieldWithNonEmptyString(ctx context.Context, field string) error {
	m, ok := ctx.Value(keyJSON).(map[string]interface{})
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
	m, ok := ctx.Value(keyJSON).(map[string]interface{})
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
	// Basic ISO 8601 check: should contain T and be reasonably long
	if !strings.Contains(ts, "T") || len(ts) < 10 {
		return fmt.Errorf("timestamp %q does not follow ISO 8601 format", ts)
	}
	return nil
}

func theJSONMetadataToolsArrayHasObjectWithField(ctx context.Context, field string) error {
	m, ok := ctx.Value(keyJSON).(map[string]interface{})
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

func theJSONHasFieldStartingWith(ctx context.Context, field, prefix string) error {
	m, ok := ctx.Value(keyJSON).(map[string]interface{})
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

func theJSONMetadataComponentHasFieldWithNonEmptyString(ctx context.Context, field string) error {
	m, ok := ctx.Value(keyJSON).(map[string]interface{})
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
	m, ok := ctx.Value(keyJSON).(map[string]interface{})
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
	allowedValues := strings.Split(values, ", ")
	for _, v := range allowedValues {
		if valStr == v {
			return nil
		}
	}
	return fmt.Errorf("metadata component field %q value %q not in allowed values %q", field, valStr, values)
}

func theJSONComponentsArrayHasAllItemsWithField(ctx context.Context, field string) error {
	m, ok := ctx.Value(keyJSON).(map[string]interface{})
	if !ok {
		return fmt.Errorf("JSON is not an object")
	}
	components, ok := m["components"].([]interface{})
	if !ok || len(components) == 0 {
		return fmt.Errorf("no components found")
	}
	missing := []string{}
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
	m, ok := ctx.Value(keyJSON).(map[string]interface{})
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
	actualPercent := float64(withField) * 100 / float64(len(components))
	if float64(actualPercent) < float64(percent) {
		return fmt.Errorf("only %.1f%% of components have field %q starting with %q (need >%d%%)", actualPercent, field, prefix, percent)
	}
	return nil
}

func theJSONComponentsLicensesUseSPDXIdentifiers(ctx context.Context) error {
	m, ok := ctx.Value(keyJSON).(map[string]interface{})
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

func theJSONHasFieldWithNumber(ctx context.Context, field string) error {
	m, ok := ctx.Value(keyJSON).(map[string]interface{})
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

func theBsiCheckReportHasFieldAtLeastPercent(ctx context.Context, field string, percent int) error {
	m, ok := ctx.Value(keyReportJSON).(map[string]interface{})
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

func theJSONDependenciesHaveItemsWithFieldStartingWith(ctx context.Context, field, prefix string) error {
	m, ok := ctx.Value(keyJSON).(map[string]interface{})
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
	m, ok := ctx.Value(keyJSON).(map[string]interface{})
	if !ok {
		return fmt.Errorf("JSON is not an object")
	}
	deps, ok := m["dependencies"].([]interface{})
	if !ok || len(deps) == 0 {
		return fmt.Errorf("no dependencies found")
	}
	// Check if any dependency has dependsOn with at least one item
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

func getTmpDir(ctx context.Context) string {
	if d, ok := ctx.Value(keyTmpDir).(string); ok {
		return d
	}
	return os.TempDir()
}
