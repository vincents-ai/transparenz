package bsi

import "testing"

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

// TestValidate_DelegatesToCanonicalConformance is the regression guard for the
// regulatory-review finding: the library bsi.Validate() previously ran a
// weaker, divergent check that let SBOMs missing mandatory BSI TR-03183-2
// fields pass. It now delegates to CheckConformance (same logic as the CLI), so
// an SBOM without SHA-512 hashes must FAIL validation.
func TestValidate_DelegatesToCanonicalConformance(t *testing.T) {
	// A CycloneDX 1.6 SBOM with a component that has no cryptographic hash.
	// BSI TR-03183-2 mandates SHA-512.
	const noHashSBOM = `{
		"bomFormat": "CycloneDX",
		"specVersion": "1.6",
		"metadata": {"properties": [{"name": "completeness", "value": "complete"}]},
		"components": [
			{"type": "library", "name": "nolib", "version": "1.0.0",
			 "licenses": [{"license": {"id": "MIT"}}],
			 "supplier": {"name": "Test"},
			 "properties": [{"name": "executable", "value": "false"},
			                {"name": "archive", "value": "false"},
			                {"name": "structured", "value": "true"}]}
		]
	}`

	result, err := NewValidator().Validate(noHashSBOM)
	if err != nil {
		t.Fatalf("Validate returned unexpected error: %v", err)
	}
	if result.Valid {
		t.Fatalf("expected SBOM missing SHA-512 to FAIL validation, but Valid=true (findings: %+v)", result.Findings)
	}
	// And the failure must mention hashes, proving it came from the canonical check.
	foundHashFinding := false
	for _, f := range result.Findings {
		if f.Severity == "critical" || f.Severity == "CRITICAL" {
			foundHashFinding = true
			break
		}
	}
	if !foundHashFinding {
		t.Fatalf("expected a CRITICAL hash finding, got %+v", result.Findings)
	}
}
