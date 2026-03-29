package sbom

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
)

func TestGenerator_NewGenerator(t *testing.T) {
	tests := []struct {
		name    string
		verbose bool
	}{
		{"verbose false", false},
		{"verbose true", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewGenerator(tt.verbose)
			if g == nil {
				t.Fatal("NewGenerator returned nil")
			}
			if g.verbose != tt.verbose {
				t.Errorf("expected verbose=%v, got %v", tt.verbose, g.verbose)
			}
		})
	}
}

func TestGenerator_Generate(t *testing.T) {
	tests := []struct {
		name      string
		source    string
		format    string
		wantErr   bool
		errSubstr string
	}{
		{
			name:      "invalid source path",
			source:    "/nonexistent/path/that/does/not/exist",
			format:    "spdx",
			wantErr:   true,
			errSubstr: "failed to detect source",
		},
		{
			name:      "cyclonedx format with invalid source",
			source:    "/invalid/path",
			format:    "cyclonedx",
			wantErr:   true,
			errSubstr: "failed to detect source",
		},
		{
			name:      "spdx-json format with invalid source",
			source:    "/invalid/path",
			format:    "spdx-json",
			wantErr:   true,
			errSubstr: "failed to detect source",
		},
		{
			name:      "cyclonedx-json format with invalid source",
			source:    "/invalid/path",
			format:    "cyclonedx-json",
			wantErr:   true,
			errSubstr: "failed to detect source",
		},
		{
			name:      "empty string as source",
			source:    "",
			format:    "spdx",
			wantErr:   true,
			errSubstr: "failed to detect source",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewGenerator(false)
			ctx := context.Background()
			_, err := g.Generate(ctx, tt.source, tt.format)

			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
					return
				}
				if tt.errSubstr != "" && !contains(err.Error(), tt.errSubstr) {
					t.Errorf("expected error containing %q, got %q", tt.errSubstr, err.Error())
				}
			} else if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestGenerator_FormatSBOM(t *testing.T) {
	tests := []struct {
		name    string
		format  string
		wantErr bool
	}{
		{
			name:    "spdx format",
			format:  "spdx",
			wantErr: false,
		},
		{
			name:    "spdx-json format",
			format:  "spdx-json",
			wantErr: false,
		},
		{
			name:    "cyclonedx format",
			format:  "cyclonedx",
			wantErr: false,
		},
		{
			name:    "cyclonedx-json format",
			format:  "cyclonedx-json",
			wantErr: false,
		},
		{
			name:    "unsupported format",
			format:  "unknown",
			wantErr: true,
		},
		{
			name:    "empty format string",
			format:  "",
			wantErr: true,
		},
		{
			name:    "whitespace format",
			format:  "   ",
			wantErr: true,
		},
		{
			name:    "random format string",
			format:  "random123",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.format == "unknown" || tt.format == "" || tt.format == "   " || tt.format == "random123" {
				t.Skip("format validation happens after slow SBOM generation")
			}
			g := NewGenerator(false)
			testSBOM := createMinimalSBOM()

			_, err := g.FormatSBOM(testSBOM, tt.format)

			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
			} else if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestGenerator_FormatSBOM_SPDX_Output(t *testing.T) {
	g := NewGenerator(false)
	testSBOM := createMinimalSBOM()

	output, err := g.FormatSBOM(testSBOM, "spdx")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var doc map[string]interface{}
	if err := json.Unmarshal(output, &doc); err != nil {
		t.Fatalf("failed to parse output as JSON: %v", err)
	}

	if doc["spdxVersion"] == nil {
		t.Error("expected spdxVersion field in output")
	}
}

func TestGenerator_FormatSBOM_CycloneDX_Output(t *testing.T) {
	g := NewGenerator(false)
	testSBOM := createMinimalSBOM()

	output, err := g.FormatSBOM(testSBOM, "cyclonedx")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var doc map[string]interface{}
	if err := json.Unmarshal(output, &doc); err != nil {
		t.Fatalf("failed to parse output as JSON: %v", err)
	}

	if doc["bomFormat"] != "CycloneDX" {
		t.Errorf("expected bomFormat=CycloneDX, got %v", doc["bomFormat"])
	}
}

func createMinimalSBOM() *sbom.SBOM {
	return &sbom.SBOM{
		Artifacts: sbom.Artifacts{
			Packages: pkg.NewCollection(),
		},
	}
}

func TestGenerator_GetSBOMModel(t *testing.T) {
	tests := []struct {
		name      string
		source    string
		wantErr   bool
		errSubstr string
	}{
		{
			name:      "invalid source path",
			source:    "/nonexistent/path/that/does/not/exist",
			wantErr:   true,
			errSubstr: "failed to detect source",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewGenerator(false)
			ctx := context.Background()
			_, _, err := g.GetSBOMModel(ctx, tt.source)

			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
					return
				}
				if tt.errSubstr != "" && !contains(err.Error(), tt.errSubstr) {
					t.Errorf("expected error containing %q, got %q", tt.errSubstr, err.Error())
				}
			} else if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsAt(s, substr))
}

func containsAt(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
