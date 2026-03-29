package sbom

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestParser_NewParser(t *testing.T) {
	tests := []struct {
		name    string
		verbose bool
	}{
		{"verbose false", false},
		{"verbose true", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewParser(tt.verbose)
			if p == nil {
				t.Fatal("NewParser returned nil")
			}
			if p.verbose != tt.verbose {
				t.Errorf("expected verbose=%v, got %v", tt.verbose, p.verbose)
			}
		})
	}
}

func TestParser_ParseFile(t *testing.T) {
	tests := []struct {
		name      string
		filename  string
		wantErr   bool
		errSubstr string
	}{
		{
			name:      "valid SPDX JSON",
			filename:  "testdata/spdx_valid.json",
			wantErr:   false,
			errSubstr: "",
		},
		{
			name:      "valid CycloneDX JSON",
			filename:  "testdata/cyclonedx_valid.json",
			wantErr:   false,
			errSubstr: "",
		},
		{
			name:      "invalid JSON format",
			filename:  "testdata/invalid.json",
			wantErr:   true,
			errSubstr: "unknown SBOM format",
		},
		{
			name:      "non-existent file",
			filename:  "testdata/nonexistent.json",
			wantErr:   true,
			errSubstr: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewParser(false)

			var data []byte
			if tt.filename != "testdata/nonexistent.json" {
				var err error
				data, err = os.ReadFile(filepath.Join(".", tt.filename))
				if err != nil && tt.filename != "testdata/nonexistent.json" {
					t.Skipf("skipping: %v", err)
					return
				}
			} else {
				data = []byte{}
			}

			_, err := p.ParseFile(data)

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

func TestParser_ParseFile_Verbose(t *testing.T) {
	p := NewParser(true)

	data := []byte(`{
		"spdxVersion": "SPDX-2.3",
		"dataLicense": "CC0-1.0",
		"SPDXID": "SPDXRef-DOCUMENT",
		"name": "test-sbom",
		"documentNamespace": "https://example.org/test",
		"creationInfo": {
			"created": "2024-01-15T10:00:00Z",
			"creators": ["Tool: test-generator"]
		},
		"packages": [],
		"relationships": []
	}`)

	sbom, err := p.ParseFile(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sbom == nil {
		t.Fatal("expected non-nil SBOM")
	}
}

func TestParser_detectFormat(t *testing.T) {
	tests := []struct {
		name    string
		data    string
		want    string
		wantErr bool
	}{
		{
			name:    "SPDX format",
			data:    `{"spdxVersion": "SPDX-2.3"}`,
			want:    "spdx",
			wantErr: false,
		},
		{
			name:    "CycloneDX format",
			data:    `{"bomFormat": "CycloneDX", "specVersion": "1.5"}`,
			want:    "cyclonedx",
			wantErr: false,
		},
		{
			name:    "invalid format",
			data:    `{"notASBOM": "invalid"}`,
			want:    "",
			wantErr: true,
		},
		{
			name:    "empty JSON",
			data:    `{}`,
			want:    "",
			wantErr: true,
		},
		{
			name:    "invalid JSON",
			data:    `not valid json`,
			want:    "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewParser(false)
			format, err := p.detectFormat([]byte(tt.data))

			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if format != tt.want {
					t.Errorf("expected format=%q, got %q", tt.want, format)
				}
			}
		})
	}
}

func TestParser_ParseFile_MalformedJSON(t *testing.T) {
	p := NewParser(false)

	tests := []struct {
		name      string
		data      string
		errSubstr string
	}{
		{
			name:      "malformed JSON - not valid",
			data:      `{"spdxVersion":}`,
			errSubstr: "failed to detect SBOM format",
		},
		{
			name:      "empty data",
			data:      ``,
			errSubstr: "failed to detect SBOM format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := p.ParseFile([]byte(tt.data))
			if err == nil {
				t.Error("expected error, got nil")
				return
			}
			if !contains(err.Error(), tt.errSubstr) {
				t.Errorf("expected error containing %q, got %q", tt.errSubstr, err.Error())
			}
		})
	}
}

func TestParser_ParseFile_Verbose_CycloneDX(t *testing.T) {
	p := NewParser(true)

	data := []byte(`{
		"bomFormat": "CycloneDX",
		"specVersion": "1.5",
		"serialNumber": "urn:uuid:test-12345",
		"version": 1,
		"components": []
	}`)

	sbom, err := p.ParseFile(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sbom == nil {
		t.Fatal("expected non-nil SBOM")
	}
}

func TestParser_ParseFile_MinimalSPDX(t *testing.T) {
	p := NewParser(false)

	data := []byte(`{
		"spdxVersion": "SPDX-2.3",
		"dataLicense": "CC0-1.0",
		"SPDXID": "SPDXRef-DOCUMENT"
	}`)

	sbom, err := p.ParseFile(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sbom == nil {
		t.Fatal("expected non-nil SBOM")
	}
}

func TestParser_ParseFile_MinimalCycloneDX(t *testing.T) {
	p := NewParser(false)

	data := []byte(`{
		"bomFormat": "CycloneDX",
		"specVersion": "1.5"
	}`)

	sbom, err := p.ParseFile(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sbom == nil {
		t.Fatal("expected non-nil SBOM")
	}
}

var _ = json.Marshal
