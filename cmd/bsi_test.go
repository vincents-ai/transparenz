package cmd

import (
	"encoding/json"
	"strings"
	"testing"
)

// parseJSON is a helper that unmarshals a JSON string into map[string]interface{}.
func parseJSON(t *testing.T, s string) map[string]interface{} {
	t.Helper()
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		t.Fatalf("parseJSON: %v", err)
	}
	return m
}

// validSHA512 is a syntactically valid 128-char hex string (regex ^[a-fA-F0-9]{128}$).
var validSHA512 = strings.Repeat("a", 128)

// validSHA256 is a syntactically valid 64-char hex string.
var validSHA256 = strings.Repeat("b", 64)

// fullyCompliantCycloneDXJSON is a CycloneDX 1.6 SBOM with all BSI requirements met.
const fullyCompliantCycloneDXJSON = `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:test-123",
  "metadata": {
    "timestamp": "2024-01-01T00:00:00Z",
    "component": {"type": "application", "name": "myapp", "version": "1.0.0"},
    "properties": [{"name": "completeness", "value": "complete"}]
  },
  "components": [
    {
      "type": "library",
      "name": "somelib",
      "version": "2.0.0",
      "purl": "pkg:golang/somelib@2.0.0",
      "hashes": [{"alg": "SHA-512", "content": "PLACEHOLDER_SHA512"}],
      "licenses": [{"license": {"id": "MIT"}}],
      "supplier": {"name": "Test Org"},
      "properties": [
        {"name": "executable", "value": "false"},
        {"name": "archive", "value": "false"},
        {"name": "structured", "value": "true"}
      ]
    }
  ],
  "dependencies": [{"ref": "urn:uuid:test-123", "dependsOn": []}]
}`

// buildCompliantJSON replaces the PLACEHOLDER_SHA512 sentinel with the actual hash value.
func buildCompliantJSON() map[string]interface{} {
	s := strings.ReplaceAll(fullyCompliantCycloneDXJSON, "PLACEHOLDER_SHA512", validSHA512)
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		panic("buildCompliantJSON: " + err.Error())
	}
	return m
}

// --------------------------------------------------------------------------
// TestIsVersionGTE – boundary cases for the version comparison helper
// --------------------------------------------------------------------------

func TestIsVersionGTE(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"1.6", "1.6", true},  // equal
		{"1.5", "1.6", false}, // strictly less
		{"2.3", "2.3", true},  // equal multi-digit minor
		{"3.0", "2.3", true},  // major bump
		{"1.4", "1.6", false}, // older minor
		{"2.0", "1.6", true},  // major ahead
		{"1.10", "1.6", true}, // numeric comparison (10 > 6)
	}

	for _, tc := range cases {
		got := isVersionGTE(tc.a, tc.b)
		if got != tc.want {
			t.Errorf("isVersionGTE(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}

// --------------------------------------------------------------------------
// TestValidateBSICompliance_FullyCompliantCycloneDX
// --------------------------------------------------------------------------

func TestValidateBSICompliance_FullyCompliantCycloneDX(t *testing.T) {
	sbom := buildCompliantJSON()
	result := validateBSICompliance(sbom)

	compliant, _ := result["compliant"].(bool)
	if !compliant {
		t.Errorf("expected compliant=true, got false; findings: %v", result["findings"])
	}

	overallScore, _ := result["overall_score"].(float64)
	if overallScore <= 90.0 {
		t.Errorf("expected overall_score > 90.0, got %.2f", overallScore)
	}

	hashCoverage, _ := result["hash_coverage"].(float64)
	if hashCoverage != 100.0 {
		t.Errorf("expected hash_coverage=100.0, got %.2f", hashCoverage)
	}

	licenseCoverage, _ := result["license_coverage"].(float64)
	if licenseCoverage != 100.0 {
		t.Errorf("expected license_coverage=100.0, got %.2f", licenseCoverage)
	}
}

// --------------------------------------------------------------------------
// TestValidateBSICompliance_MissingHashes
// --------------------------------------------------------------------------

func TestValidateBSICompliance_MissingHashes(t *testing.T) {
	sbomJSON := `{
		"bomFormat": "CycloneDX",
		"specVersion": "1.6",
		"metadata": {
			"properties": [{"name": "completeness", "value": "complete"}]
		},
		"components": [
			{
				"type": "library",
				"name": "noHashLib",
				"version": "1.0.0",
				"licenses": [{"license": {"id": "Apache-2.0"}}],
				"supplier": {"name": "Acme"},
				"properties": [
					{"name": "executable", "value": "false"},
					{"name": "archive", "value": "false"},
					{"name": "structured", "value": "true"}
				]
			}
		]
	}`

	result := validateBSICompliance(parseJSON(t, sbomJSON))

	compliant, _ := result["compliant"].(bool)
	if compliant {
		t.Error("expected compliant=false when component has no hash")
	}

	hashCoverage, _ := result["hash_coverage"].(float64)
	if hashCoverage != 0.0 {
		t.Errorf("expected hash_coverage=0.0, got %.2f", hashCoverage)
	}

	findings, _ := result["findings"].([]BSIFinding)
	found := false
	for _, f := range findings {
		if strings.Contains(strings.ToLower(f.Message), "sha-512") ||
			strings.Contains(strings.ToLower(f.Message), "sha512") ||
			strings.Contains(strings.ToLower(f.Message), "hash") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected a finding mentioning 'hash' or 'sha512', got: %v", findings)
	}
}

// --------------------------------------------------------------------------
// TestValidateBSICompliance_SHA256OnlyNotSufficient
// --------------------------------------------------------------------------

func TestValidateBSICompliance_SHA256OnlyNotSufficient(t *testing.T) {
	sbomJSON := `{
		"bomFormat": "CycloneDX",
		"specVersion": "1.6",
		"metadata": {
			"properties": [{"name": "completeness", "value": "complete"}]
		},
		"components": [
			{
				"type": "library",
				"name": "sha256only",
				"version": "1.0.0",
				"hashes": [{"alg": "SHA-256", "content": "PLACEHOLDER_SHA256"}],
				"licenses": [{"license": {"id": "MIT"}}],
				"supplier": {"name": "Acme"},
				"properties": [
					{"name": "executable", "value": "false"},
					{"name": "archive", "value": "false"},
					{"name": "structured", "value": "true"}
				]
			}
		]
	}`
	sbomJSON = strings.ReplaceAll(sbomJSON, "PLACEHOLDER_SHA256", validSHA256)

	result := validateBSICompliance(parseJSON(t, sbomJSON))

	compliant, _ := result["compliant"].(bool)
	if compliant {
		t.Error("expected compliant=false when only SHA-256 hash present (SHA-512 required)")
	}

	// There must be a CRITICAL finding about SHA-512
	findings, _ := result["findings"].([]BSIFinding)
	criticalAboutSHA512 := false
	for _, f := range findings {
		if f.Severity == "CRITICAL" &&
			(strings.Contains(strings.ToLower(f.Message), "sha-512") ||
				strings.Contains(strings.ToLower(f.Message), "sha512")) {
			criticalAboutSHA512 = true
			break
		}
	}
	if !criticalAboutSHA512 {
		t.Errorf("expected CRITICAL finding about SHA-512 absence, findings: %v", findings)
	}
}

// --------------------------------------------------------------------------
// TestValidateBSICompliance_MissingDependencyCompleteness
// --------------------------------------------------------------------------

func TestValidateBSICompliance_MissingDependencyCompleteness(t *testing.T) {
	// Fully compliant except no completeness property in metadata
	sbomJSON := strings.ReplaceAll(`{
		"bomFormat": "CycloneDX",
		"specVersion": "1.6",
		"metadata": {
			"properties": []
		},
		"components": [
			{
				"type": "library",
				"name": "somelib",
				"version": "1.0.0",
				"hashes": [{"alg": "SHA-512", "content": "PLACEHOLDER_SHA512"}],
				"licenses": [{"license": {"id": "MIT"}}],
				"supplier": {"name": "Acme"},
				"properties": [
					{"name": "executable", "value": "false"},
					{"name": "archive", "value": "false"},
					{"name": "structured", "value": "true"}
				]
			}
		]
	}`, "PLACEHOLDER_SHA512", validSHA512)

	result := validateBSICompliance(parseJSON(t, sbomJSON))

	dependencyComplete, _ := result["dependency_complete"].(bool)
	if dependencyComplete {
		t.Error("expected dependency_complete=false when completeness property is absent")
	}

	compliant, _ := result["compliant"].(bool)
	if compliant {
		t.Error("expected compliant=false when dependency completeness is missing")
	}
}

// --------------------------------------------------------------------------
// TestValidateBSICompliance_OldSpecVersion
// --------------------------------------------------------------------------

func TestValidateBSICompliance_OldSpecVersion(t *testing.T) {
	sbomJSON := strings.ReplaceAll(`{
		"bomFormat": "CycloneDX",
		"specVersion": "1.5",
		"metadata": {
			"properties": [{"name": "completeness", "value": "complete"}]
		},
		"components": [
			{
				"type": "library",
				"name": "somelib",
				"version": "1.0.0",
				"hashes": [{"alg": "SHA-512", "content": "PLACEHOLDER_SHA512"}],
				"licenses": [{"license": {"id": "MIT"}}],
				"supplier": {"name": "Acme"},
				"properties": [
					{"name": "executable", "value": "false"},
					{"name": "archive", "value": "false"},
					{"name": "structured", "value": "true"}
				]
			}
		]
	}`, "PLACEHOLDER_SHA512", validSHA512)

	result := validateBSICompliance(parseJSON(t, sbomJSON))

	formatCompliant, _ := result["format_compliant"].(bool)
	if formatCompliant {
		t.Error("expected format_compliant=false for CycloneDX 1.5")
	}
}

// --------------------------------------------------------------------------
// TestValidateBSICompliance_SPDX23Accepted
// --------------------------------------------------------------------------

func TestValidateBSICompliance_SPDX23Accepted(t *testing.T) {
	// SPDX 2.3 with minimal valid content; checksums use SPDX field names
	sbomJSON := strings.ReplaceAll(`{
		"spdxVersion": "SPDX-2.3",
		"SPDXID": "SPDXRef-DOCUMENT",
		"name": "test-sbom",
		"packages": [
			{
				"SPDXID": "SPDXRef-pkg1",
				"name": "spdxlib",
				"versionInfo": "1.0.0",
				"downloadLocation": "https://example.com",
				"filesAnalyzed": true,
				"checksums": [
					{"algorithm": "SHA512", "checksumValue": "PLACEHOLDER_SHA512"}
				],
				"licenseConcluded": "MIT",
				"licenseDeclared": "MIT",
				"supplier": "Organization: Acme",
				"annotations": [
					{"comment": "BSI TR-03183-2 executable=false archive=false structured=true"}
				]
			}
		],
		"annotations": [
			{"comment": "dependencyCompleteness=complete"}
		]
	}`, "PLACEHOLDER_SHA512", validSHA512)

	result := validateBSICompliance(parseJSON(t, sbomJSON))

	formatCompliant, _ := result["format_compliant"].(bool)
	if !formatCompliant {
		t.Errorf("expected format_compliant=true for SPDX 2.3, findings: %v", result["findings"])
	}

	// Must not have any CRITICAL finding related to format version
	findings, _ := result["findings"].([]BSIFinding)
	for _, f := range findings {
		if f.Severity == "CRITICAL" && f.Category == "Format Version" {
			t.Errorf("unexpected CRITICAL format-version finding for SPDX-2.3: %+v", f)
		}
	}
}

// --------------------------------------------------------------------------
// TestRunBSICheck_ReturnsParsedScore
// --------------------------------------------------------------------------

func TestRunBSICheck_ReturnsParsedScore(t *testing.T) {
	// Use the same fully compliant CycloneDX 1.6 fixture from other tests.
	sbomJSON := strings.ReplaceAll(fullyCompliantCycloneDXJSON, "PLACEHOLDER_SHA512", validSHA512)

	compliant, score, err := RunBSICheck(sbomJSON)
	if err != nil {
		t.Fatalf("RunBSICheck returned unexpected error: %v", err)
	}
	if !compliant {
		t.Error("expected compliant=true for fully-compliant SBOM")
	}
	if score < 0.9 || score > 1.0 {
		t.Errorf("expected score in [0.9, 1.0], got %.4f", score)
	}
}

// --------------------------------------------------------------------------
// TestRunBSICheck_EmptyJSON
// --------------------------------------------------------------------------

func TestRunBSICheck_EmptyJSON(t *testing.T) {
	_, _, err := RunBSICheck("")
	if err == nil {
		t.Fatal("expected error for empty JSON")
	}
}

// --------------------------------------------------------------------------
// TestValidateBSICompliance_ScoreWeighting
// --------------------------------------------------------------------------

// Expected: 100% hashes, 0% licenses, 0% suppliers, 0% properties,
//
//	completeness=true, formatCompliant=true (specVersion 1.6)
//
// Score = 100*0.30 + 0*0.25 + 0*0.15 + 0*0.15 + 100*0.10 + 100*0.05 = 45.0
func TestValidateBSICompliance_ScoreWeighting(t *testing.T) {
	sbomJSON := strings.ReplaceAll(`{
		"bomFormat": "CycloneDX",
		"specVersion": "1.6",
		"metadata": {
			"properties": [{"name": "completeness", "value": "complete"}]
		},
		"components": [
			{
				"type": "library",
				"name": "weightlib",
				"version": "1.0.0",
				"hashes": [{"alg": "SHA-512", "content": "PLACEHOLDER_SHA512"}]
			}
		]
	}`, "PLACEHOLDER_SHA512", validSHA512)

	result := validateBSICompliance(parseJSON(t, sbomJSON))

	// Verify individual coverage values first
	hashCoverage, _ := result["hash_coverage"].(float64)
	if hashCoverage != 100.0 {
		t.Errorf("expected hash_coverage=100.0, got %.2f", hashCoverage)
	}

	licenseCoverage, _ := result["license_coverage"].(float64)
	if licenseCoverage != 0.0 {
		t.Errorf("expected license_coverage=0.0, got %.2f", licenseCoverage)
	}

	supplierCoverage, _ := result["supplier_coverage"].(float64)
	if supplierCoverage != 0.0 {
		t.Errorf("expected supplier_coverage=0.0, got %.2f", supplierCoverage)
	}

	propertyCoverage, _ := result["property_coverage"].(float64)
	if propertyCoverage != 0.0 {
		t.Errorf("expected property_coverage=0.0, got %.2f", propertyCoverage)
	}

	dependencyComplete, _ := result["dependency_complete"].(bool)
	if !dependencyComplete {
		t.Error("expected dependency_complete=true")
	}

	formatCompliant, _ := result["format_compliant"].(bool)
	if !formatCompliant {
		t.Error("expected format_compliant=true")
	}

	overallScore, _ := result["overall_score"].(float64)
	const expectedScore = 45.0
	if overallScore != expectedScore {
		t.Errorf("expected overall_score=%.1f, got %.4f", expectedScore, overallScore)
	}
}
