package cmd

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestCLI_Generate_Scope tests the --scope flag on the generate command.
func TestCLI_Generate_Scope(t *testing.T) {
	cliBin := getCLIBinary(t)
	testDir := getTestDir(t)

	tests := []struct {
		name          string
		args          []string
		wantErr       bool
		wantScope     string // expected transparenz:scope value in CycloneDX output
		wantScopeNote string // expected prefix in SPDX documentComment
	}{
		{
			name:      "scope source with cyclonedx",
			args:      []string{"generate", testdata, "-f", "cyclonedx", "--scope", "source"},
			wantErr:   false,
			wantScope: "source",
		},
		{
			name:      "scope binary with cyclonedx",
			args:      []string{"generate", testdata, "-f", "cyclonedx", "--scope", "binary"},
			wantErr:   false,
			wantScope: "binary",
		},
		{
			name:          "scope source with spdx",
			args:          []string{"generate", testdata, "-f", "spdx", "--scope", "source"},
			wantErr:       false,
			wantScopeNote: "transparenz:scope=source",
		},
		{
			name:          "scope binary with spdx",
			args:          []string{"generate", testdata, "-f", "spdx", "--scope", "binary"},
			wantErr:       false,
			wantScopeNote: "transparenz:scope=binary",
		},
		{
			name:    "default scope produces source annotation (cyclonedx)",
			args:    []string{"generate", testdata, "-f", "cyclonedx"},
			wantErr: false,
			// default --scope is "source"; the annotation must be present
			wantScope: "source",
		},
		{
			name:    "invalid scope returns error",
			args:    []string{"generate", testdata, "--scope", "invalid"},
			wantErr: true,
		},
		{
			name:    "invalid scope typo returns error",
			args:    []string{"generate", testdata, "--scope", "src"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := exec.Command(cliBin, tt.args...)
			cmd.Dir = testDir

			output, err := cmd.CombinedOutput()

			if tt.wantErr {
				require.Error(t, err, "command should fail for invalid scope, output: %s", string(output))
				return
			}

			require.NoError(t, err, "command should succeed, output: %s", truncate(string(output), 400))

			outStr := string(output)

			// Check CycloneDX property injection
			if tt.wantScope != "" {
				// Parse JSON to find metadata.properties
				var doc map[string]interface{}
				if parseErr := json.Unmarshal([]byte(outStr), &doc); parseErr != nil {
					// Output might be "SBOM successfully written to ..." text; try loading the file
					// For stdout tests, the entire output should be JSON.
					t.Fatalf("output is not valid JSON: %v\noutput: %s", parseErr, truncate(outStr, 300))
				}
				scope := extractCycloneDXScope(t, doc)
				require.Equal(t, tt.wantScope, scope,
					"transparenz:scope property should be %q in CycloneDX metadata.properties", tt.wantScope)
			}

			// Check SPDX documentComment injection
			if tt.wantScopeNote != "" {
				require.True(t, strings.Contains(outStr, tt.wantScopeNote),
					"SPDX output should contain %q, got: %s", tt.wantScopeNote, truncate(outStr, 400))
			}
		})
	}
}

// TestCLI_Generate_ScopeOutputFile tests scope injection when writing to a file.
func TestCLI_Generate_ScopeOutputFile(t *testing.T) {
	cliBin := getCLIBinary(t)
	testDir := getTestDir(t)

	outFile := filepath.Join(testDir, "testdata", "sbom_scope_test.json")
	defer os.Remove(outFile)

	args := []string{"generate", testdata, "-f", "cyclonedx", "--scope", "source", "-o", outFile}
	cmd := exec.Command(cliBin, args...)
	cmd.Dir = testDir

	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "command should succeed, output: %s", string(output))

	// Read the file and verify scope annotation
	data, err := os.ReadFile(outFile)
	require.NoError(t, err, "output file should exist")

	var doc map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &doc), "output file should be valid JSON")

	scope := extractCycloneDXScope(t, doc)
	require.Equal(t, "source", scope, "transparenz:scope should be 'source' in output file")
}

// extractCycloneDXScope walks metadata.properties and returns the value of
// transparenz:scope, or "" if not found.
func extractCycloneDXScope(t *testing.T, doc map[string]interface{}) string {
	t.Helper()
	meta, ok := doc["metadata"].(map[string]interface{})
	if !ok {
		t.Log("no metadata object in CycloneDX document")
		return ""
	}
	props, ok := meta["properties"].([]interface{})
	if !ok {
		t.Log("no metadata.properties array in CycloneDX document")
		return ""
	}
	for _, p := range props {
		pm, ok := p.(map[string]interface{})
		if !ok {
			continue
		}
		if pm["name"] == "transparenz:scope" {
			v, _ := pm["value"].(string)
			return v
		}
	}
	return ""
}
