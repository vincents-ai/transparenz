package cmd

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const testdata = "./testdata"

func getTestDir(t *testing.T) string {
	cwd, err := os.Getwd()
	require.NoError(t, err)

	// If we're in cmd directory, return parent (transparenz-go)
	if filepath.Base(cwd) == "cmd" {
		return filepath.Dir(cwd)
	}

	// If we're already in transparenz-go root
	if filepath.Base(cwd) == "transparenz-go" {
		return cwd
	}

	return cwd
}

func getCLIBinary(t *testing.T) string {
	return filepath.Join(getTestDir(t), "transparenz")
}

func TestCLI_Generate(t *testing.T) {
	cliBin := getCLIBinary(t)

	tests := []struct {
		name       string
		args       []string
		wantFormat string
		wantFile   bool
	}{
		{
			name:       "generate SPDX from Go project",
			args:       []string{"generate", testdata, "-f", "spdx"},
			wantFormat: "spdx",
			wantFile:   false,
		},
		{
			name:       "generate CycloneDX from Go project",
			args:       []string{"generate", testdata, "-f", "cyclonedx"},
			wantFormat: "cyclonedx",
			wantFile:   false,
		},
		{
			name:       "generate with output file",
			args:       []string{"generate", testdata, "-o", "testdata/sbom_output.json"},
			wantFormat: "spdx",
			wantFile:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testDir := getTestDir(t)
			cmd := exec.Command(cliBin, tt.args...)
			cmd.Dir = testDir

			output, err := cmd.CombinedOutput()

			require.NoError(t, err, "command should succeed, output: %s", truncate(string(output), 200))
			require.NotEmpty(t, output, "output should not be empty")

			outStr := strings.ToLower(string(output))

			if tt.wantFormat == "spdx" {
				require.True(t, strings.Contains(outStr, "spdx"),
					"output should contain SPDX, got: %s", truncate(outStr, 200))
			} else if tt.wantFormat == "cyclonedx" {
				require.True(t, strings.Contains(outStr, "bomformat") || strings.Contains(outStr, "cyclonedx"),
					"output should contain CycloneDX format")
			}

			if tt.wantFile {
				_, err := os.Stat(filepath.Join(testDir, "testdata/sbom_output.json"))
				require.NoError(t, err, "output file should exist")
				os.Remove(filepath.Join(testDir, "testdata/sbom_output.json"))
			}
		})
	}
}

func TestCLI_BSICheck(t *testing.T) {
	cliBin := getCLIBinary(t)

	tests := []struct {
		name    string
		args    []string
		wantErr bool
	}{
		{
			name:    "bsi-check SPDX SBOM",
			args:    []string{"bsi-check", filepath.Join(testdata, "sbom.spdx.json")},
			wantErr: false,
		},
		{
			name:    "bsi-check CycloneDX SBOM",
			args:    []string{"bsi-check", filepath.Join(testdata, "sbom.cyclonedx.json")},
			wantErr: false,
		},
		{
			name:    "bsi-check non-existent file",
			args:    []string{"bsi-check", "nonexistent.json"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testDir := getTestDir(t)
			cmd := exec.Command(cliBin, tt.args...)
			cmd.Dir = testDir

			output, err := cmd.CombinedOutput()

			if tt.wantErr {
				require.Error(t, err, "command should fail for non-existent file")
				return
			}

			require.NoError(t, err, "command should succeed, output: %s", truncate(string(output), 200))
			require.NotEmpty(t, output, "output should not be empty")

			outStr := string(output)
			require.True(t,
				strings.Contains(outStr, "overall_score") ||
					strings.Contains(outStr, "overall") ||
					strings.Contains(outStr, "compliance") ||
					strings.Contains(outStr, "Compliant"),
				"output should contain compliance information")
		})
	}
}

func TestCLI_DbMigrate(t *testing.T) {
	cliBin := getCLIBinary(t)

	tests := []struct {
		name    string
		args    []string
		wantErr bool
	}{
		{
			name:    "migrate without database",
			args:    []string{"db", "migrate"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testDir := getTestDir(t)
			cmd := exec.Command(cliBin, tt.args...)
			cmd.Dir = testDir
			_, err := cmd.CombinedOutput()

			if tt.wantErr {
				require.Error(t, err, "command should fail without database")
			}
		})
	}
}

func TestCLI_Version(t *testing.T) {
	cliBin := getCLIBinary(t)
	testDir := getTestDir(t)

	cmd := exec.Command(cliBin, "--version")
	cmd.Dir = testDir

	output, err := cmd.CombinedOutput()

	require.NoError(t, err, "version command should succeed")
	require.NotEmpty(t, output, "version output should not be empty")
	require.True(t, strings.Contains(string(output), "0.1.0"), "version should be 0.1.0")
}

func TestCLI_Help(t *testing.T) {
	cliBin := getCLIBinary(t)
	testDir := getTestDir(t)

	cmd := exec.Command(cliBin, "--help")
	cmd.Dir = testDir

	output, err := cmd.CombinedOutput()

	require.NoError(t, err, "help command should succeed")
	require.NotEmpty(t, output, "help output should not be empty")

	outStr := string(output)
	require.True(t, strings.Contains(outStr, "transparenz"), "help should mention transparenz")
	require.True(t, strings.Contains(outStr, "SBOM") || strings.Contains(outStr, "generate"), "help should mention SBOM commands")
}

func TestCLI_Root(t *testing.T) {
	cliBin := getCLIBinary(t)
	testDir := getTestDir(t)

	cmd := exec.Command(cliBin)
	cmd.Dir = testDir

	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "root command should work")
	require.True(t, len(output) > 0, "should have some output")
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
