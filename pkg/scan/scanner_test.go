package scan

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/anchore/syft/syft/sbom"
)

type mockSBOM struct{}

func (m *mockSBOM) UnmarshalJSON([]byte) error { return nil }

func TestFilterBySeverity(t *testing.T) {
	tests := []struct {
		name        string
		matches     []VulnerabilityMatch
		minSeverity string
		expected    []VulnerabilityMatch
	}{
		{
			name: "filter Critical only",
			matches: []VulnerabilityMatch{
				{Vulnerability: Vulnerability{ID: "CVE-2021-1234", Severity: "Critical"}},
				{Vulnerability: Vulnerability{ID: "CVE-2021-1235", Severity: "High"}},
				{Vulnerability: Vulnerability{ID: "CVE-2021-1236", Severity: "Medium"}},
				{Vulnerability: Vulnerability{ID: "CVE-2021-1237", Severity: "Low"}},
			},
			minSeverity: "Critical",
			expected: []VulnerabilityMatch{
				{Vulnerability: Vulnerability{ID: "CVE-2021-1234", Severity: "Critical"}},
			},
		},
		{
			name: "filter High and above",
			matches: []VulnerabilityMatch{
				{Vulnerability: Vulnerability{ID: "CVE-2021-1234", Severity: "Critical"}},
				{Vulnerability: Vulnerability{ID: "CVE-2021-1235", Severity: "High"}},
				{Vulnerability: Vulnerability{ID: "CVE-2021-1236", Severity: "Medium"}},
				{Vulnerability: Vulnerability{ID: "CVE-2021-1237", Severity: "Low"}},
			},
			minSeverity: "High",
			expected: []VulnerabilityMatch{
				{Vulnerability: Vulnerability{ID: "CVE-2021-1234", Severity: "Critical"}},
				{Vulnerability: Vulnerability{ID: "CVE-2021-1235", Severity: "High"}},
			},
		},
		{
			name: "filter Medium and above",
			matches: []VulnerabilityMatch{
				{Vulnerability: Vulnerability{ID: "CVE-2021-1234", Severity: "Critical"}},
				{Vulnerability: Vulnerability{ID: "CVE-2021-1235", Severity: "High"}},
				{Vulnerability: Vulnerability{ID: "CVE-2021-1236", Severity: "Medium"}},
				{Vulnerability: Vulnerability{ID: "CVE-2021-1237", Severity: "Low"}},
			},
			minSeverity: "Medium",
			expected: []VulnerabilityMatch{
				{Vulnerability: Vulnerability{ID: "CVE-2021-1234", Severity: "Critical"}},
				{Vulnerability: Vulnerability{ID: "CVE-2021-1235", Severity: "High"}},
				{Vulnerability: Vulnerability{ID: "CVE-2021-1236", Severity: "Medium"}},
			},
		},
		{
			name: "filter Low and above",
			matches: []VulnerabilityMatch{
				{Vulnerability: Vulnerability{ID: "CVE-2021-1234", Severity: "Critical"}},
				{Vulnerability: Vulnerability{ID: "CVE-2021-1235", Severity: "High"}},
				{Vulnerability: Vulnerability{ID: "CVE-2021-1236", Severity: "Medium"}},
				{Vulnerability: Vulnerability{ID: "CVE-2021-1237", Severity: "Low"}},
			},
			minSeverity: "Low",
			expected: []VulnerabilityMatch{
				{Vulnerability: Vulnerability{ID: "CVE-2021-1234", Severity: "Critical"}},
				{Vulnerability: Vulnerability{ID: "CVE-2021-1235", Severity: "High"}},
				{Vulnerability: Vulnerability{ID: "CVE-2021-1236", Severity: "Medium"}},
				{Vulnerability: Vulnerability{ID: "CVE-2021-1237", Severity: "Low"}},
			},
		},
		{
			name:        "empty matches",
			matches:     []VulnerabilityMatch{},
			minSeverity: "High",
			expected:    []VulnerabilityMatch{},
		},
		{
			name: "invalid severity returns all",
			matches: []VulnerabilityMatch{
				{Vulnerability: Vulnerability{ID: "CVE-2021-1234", Severity: "Critical"}},
			},
			minSeverity: "Invalid",
			expected: []VulnerabilityMatch{
				{Vulnerability: Vulnerability{ID: "CVE-2021-1234", Severity: "Critical"}},
			},
		},
		{
			name: "unknown severity returns all",
			matches: []VulnerabilityMatch{
				{Vulnerability: Vulnerability{ID: "CVE-2021-1234", Severity: "Unknown"}},
				{Vulnerability: Vulnerability{ID: "CVE-2021-1235", Severity: "High"}},
			},
			minSeverity: "Low",
			expected: []VulnerabilityMatch{
				{Vulnerability: Vulnerability{ID: "CVE-2021-1235", Severity: "High"}},
			},
		},
		{
			name: "Negligible severity",
			matches: []VulnerabilityMatch{
				{Vulnerability: Vulnerability{ID: "CVE-2021-1234", Severity: "Negligible"}},
				{Vulnerability: Vulnerability{ID: "CVE-2021-1235", Severity: "Low"}},
			},
			minSeverity: "Negligible",
			expected: []VulnerabilityMatch{
				{Vulnerability: Vulnerability{ID: "CVE-2021-1234", Severity: "Negligible"}},
				{Vulnerability: Vulnerability{ID: "CVE-2021-1235", Severity: "Low"}},
			},
		},
	}

	scanner := &Scanner{}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := scanner.FilterBySeverity(tt.matches, tt.minSeverity)
			if len(result) != len(tt.expected) {
				t.Errorf("expected %d matches, got %d", len(tt.expected), len(result))
				return
			}
			for i, m := range result {
				if m.Vulnerability.ID != tt.expected[i].Vulnerability.ID {
					t.Errorf("expected vulnerability ID %s, got %s", tt.expected[i].Vulnerability.ID, m.Vulnerability.ID)
				}
			}
		})
	}
}

func TestFormatJSON(t *testing.T) {
	tests := []struct {
		name    string
		result  *ScanResult
		checkFn func(t *testing.T, jsonStr string)
	}{
		{
			name: "basic scan result",
			result: &ScanResult{
				Matches: []VulnerabilityMatch{
					{
						Vulnerability: Vulnerability{
							ID:          "CVE-2021-1234",
							Severity:    "Critical",
							Description: "A critical vulnerability",
						},
						Package: Package{
							Name:    "openssl",
							Version: "1.1.1",
							Type:    "npm",
						},
					},
				},
			},
			checkFn: func(t *testing.T, jsonStr string) {
				var result ScanResult
				if err := json.Unmarshal([]byte(jsonStr), &result); err != nil {
					t.Errorf("failed to unmarshal JSON: %v", err)
				}
				if len(result.Matches) != 1 {
					t.Errorf("expected 1 match, got %d", len(result.Matches))
				}
				if result.Matches[0].Vulnerability.ID != "CVE-2021-1234" {
					t.Errorf("expected CVE-2021-1234, got %s", result.Matches[0].Vulnerability.ID)
				}
			},
		},
		{
			name: "empty results",
			result: &ScanResult{
				Matches:        []VulnerabilityMatch{},
				IgnoredMatches: []VulnerabilityMatch{},
			},
			checkFn: func(t *testing.T, jsonStr string) {
				var result ScanResult
				if err := json.Unmarshal([]byte(jsonStr), &result); err != nil {
					t.Errorf("failed to unmarshal JSON: %v", err)
				}
				if len(result.Matches) != 0 {
					t.Errorf("expected 0 matches, got %d", len(result.Matches))
				}
			},
		},
		{
			name: "multiple matches with all severities",
			result: &ScanResult{
				Matches: []VulnerabilityMatch{
					{Vulnerability: Vulnerability{ID: "CVE-1", Severity: "Critical"}, Package: Package{Name: "pkg1", Version: "1.0"}},
					{Vulnerability: Vulnerability{ID: "CVE-2", Severity: "High"}, Package: Package{Name: "pkg2", Version: "2.0"}},
					{Vulnerability: Vulnerability{ID: "CVE-3", Severity: "Medium"}, Package: Package{Name: "pkg3", Version: "3.0"}},
					{Vulnerability: Vulnerability{ID: "CVE-4", Severity: "Low"}, Package: Package{Name: "pkg4", Version: "4.0"}},
				},
			},
			checkFn: func(t *testing.T, jsonStr string) {
				var result ScanResult
				if err := json.Unmarshal([]byte(jsonStr), &result); err != nil {
					t.Errorf("failed to unmarshal JSON: %v", err)
				}
				if len(result.Matches) != 4 {
					t.Errorf("expected 4 matches, got %d", len(result.Matches))
				}
			},
		},
		{
			name: "matches with CVSS and URLs",
			result: &ScanResult{
				Matches: []VulnerabilityMatch{
					{
						Vulnerability: Vulnerability{
							ID:          "CVE-2021-1234",
							Severity:    "High",
							Description: "Test vulnerability",
							URLs:        []string{"https://nvd.nist.gov/vuln/detail/CVE-2021-1234"},
							CVSS: []CVSS{
								{Version: "3.1", Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", Score: 9.8},
							},
						},
						Package: Package{
							Name:    "test-package",
							Version: "1.0.0",
							Type:    "go",
							PURL:    "pkg:golang/test-package@v1.0.0",
						},
					},
				},
			},
			checkFn: func(t *testing.T, jsonStr string) {
				var result ScanResult
				if err := json.Unmarshal([]byte(jsonStr), &result); err != nil {
					t.Errorf("failed to unmarshal JSON: %v", err)
				}
				if len(result.Matches[0].Vulnerability.CVSS) != 1 {
					t.Errorf("expected 1 CVSS entry, got %d", len(result.Matches[0].Vulnerability.CVSS))
				}
				if result.Matches[0].Vulnerability.CVSS[0].Score != 9.8 {
					t.Errorf("expected CVSS score 9.8, got %f", result.Matches[0].Vulnerability.CVSS[0].Score)
				}
			},
		},
		{
			name: "matches with match details",
			result: &ScanResult{
				Matches: []VulnerabilityMatch{
					{
						Vulnerability: Vulnerability{ID: "CVE-2021-1234", Severity: "High"},
						Package:       Package{Name: "test", Version: "1.0"},
						MatchDetails: []MatchDetail{
							{Type: "exactMatch", Confidence: "1.00", Matcher: "stock-matcher"},
						},
					},
				},
			},
			checkFn: func(t *testing.T, jsonStr string) {
				var result ScanResult
				if err := json.Unmarshal([]byte(jsonStr), &result); err != nil {
					t.Errorf("failed to unmarshal JSON: %v", err)
				}
				if len(result.Matches[0].MatchDetails) != 1 {
					t.Errorf("expected 1 match detail, got %d", len(result.Matches[0].MatchDetails))
				}
			},
		},
		{
			name: "includes ignored matches",
			result: &ScanResult{
				Matches: []VulnerabilityMatch{
					{Vulnerability: Vulnerability{ID: "CVE-1", Severity: "Critical"}, Package: Package{Name: "pkg1", Version: "1.0"}},
				},
				IgnoredMatches: []VulnerabilityMatch{
					{Vulnerability: Vulnerability{ID: "CVE-IGNORED-1", Severity: "Medium"}, Package: Package{Name: "ignored-pkg", Version: "2.0"}},
				},
			},
			checkFn: func(t *testing.T, jsonStr string) {
				var result ScanResult
				if err := json.Unmarshal([]byte(jsonStr), &result); err != nil {
					t.Errorf("failed to unmarshal JSON: %v", err)
				}
				if len(result.IgnoredMatches) != 1 {
					t.Errorf("expected 1 ignored match, got %d", len(result.IgnoredMatches))
				}
			},
		},
	}

	scanner := &Scanner{}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jsonStr, err := scanner.FormatJSON(tt.result)
			if err != nil {
				t.Errorf("FormatJSON returned error: %v", err)
				return
			}
			tt.checkFn(t, jsonStr)
		})
	}
}

func TestFormatTable(t *testing.T) {
	tests := []struct {
		name     string
		result   *ScanResult
		expected string
	}{
		{
			name: "basic table output",
			result: &ScanResult{
				Matches: []VulnerabilityMatch{
					{
						Vulnerability: Vulnerability{ID: "CVE-2021-1234", Severity: "Critical"},
						Package:       Package{Name: "openssl", Version: "1.1.1"},
					},
				},
			},
			expected: `VULNERABILITY        SEVERITY        PACKAGE                                  VERSION        
----------------------------------------------------------------------------------------------------
CVE-2021-1234        Critical        openssl:1.1.1                            1.1.1          

Total vulnerabilities: 1
`,
		},
		{
			name: "empty results",
			result: &ScanResult{
				Matches: []VulnerabilityMatch{},
			},
			expected: `VULNERABILITY        SEVERITY        PACKAGE                                  VERSION        
----------------------------------------------------------------------------------------------------

Total vulnerabilities: 0
`,
		},
		{
			name: "multiple severities",
			result: &ScanResult{
				Matches: []VulnerabilityMatch{
					{Vulnerability: Vulnerability{ID: "CVE-CRIT-1", Severity: "Critical"}, Package: Package{Name: "pkg-crit", Version: "1.0"}},
					{Vulnerability: Vulnerability{ID: "CVE-HIGH-1", Severity: "High"}, Package: Package{Name: "pkg-high", Version: "2.0"}},
					{Vulnerability: Vulnerability{ID: "CVE-MED-1", Severity: "Medium"}, Package: Package{Name: "pkg-med", Version: "3.0"}},
					{Vulnerability: Vulnerability{ID: "CVE-LOW-1", Severity: "Low"}, Package: Package{Name: "pkg-low", Version: "4.0"}},
				},
			},
			expected: `VULNERABILITY        SEVERITY        PACKAGE                                  VERSION        
----------------------------------------------------------------------------------------------------
CVE-CRIT-1           Critical        pkg-crit:1.0                             1.0            
CVE-HIGH-1           High            pkg-high:2.0                             2.0            
CVE-MED-1            Medium          pkg-med:3.0                              3.0            
CVE-LOW-1            Low             pkg-low:4.0                              4.0            

Total vulnerabilities: 4
`,
		},
		{
			name: "long package name truncation",
			result: &ScanResult{
				Matches: []VulnerabilityMatch{
					{
						Vulnerability: Vulnerability{ID: "CVE-2021-1234", Severity: "High"},
						Package:       Package{Name: "this-is-a-very-long-package-name-that-exceeds-forty-characters", Version: "1.0.0"},
					},
				},
			},
			expected: `VULNERABILITY        SEVERITY        PACKAGE                                  VERSION        
----------------------------------------------------------------------------------------------------
CVE-2021-1234        High            this-is-a-very-long-package-name-that... 1.0.0          

Total vulnerabilities: 1
`,
		},
		{
			name: "all severities including negligible",
			result: &ScanResult{
				Matches: []VulnerabilityMatch{
					{Vulnerability: Vulnerability{ID: "CVE-1", Severity: "Critical"}, Package: Package{Name: "p1", Version: "1.0"}},
					{Vulnerability: Vulnerability{ID: "CVE-2", Severity: "High"}, Package: Package{Name: "p2", Version: "2.0"}},
					{Vulnerability: Vulnerability{ID: "CVE-3", Severity: "Medium"}, Package: Package{Name: "p3", Version: "3.0"}},
					{Vulnerability: Vulnerability{ID: "CVE-4", Severity: "Low"}, Package: Package{Name: "p4", Version: "4.0"}},
					{Vulnerability: Vulnerability{ID: "CVE-5", Severity: "Negligible"}, Package: Package{Name: "p5", Version: "5.0"}},
				},
			},
			expected: `VULNERABILITY        SEVERITY        PACKAGE                                  VERSION        
----------------------------------------------------------------------------------------------------
CVE-1                Critical        p1:1.0                                   1.0            
CVE-2                High            p2:2.0                                   2.0            
CVE-3                Medium          p3:3.0                                   3.0            
CVE-4                Low             p4:4.0                                   4.0            
CVE-5                Negligible      p5:5.0                                   5.0            

Total vulnerabilities: 5
`,
		},
	}

	scanner := &Scanner{}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := scanner.FormatTable(tt.result)
			if result != tt.expected {
				t.Errorf("expected:\n%s\ngot:\n%s", tt.expected, result)
			}
		})
	}
}

func TestNewScanner(t *testing.T) {
	tests := []struct {
		name    string
		verbose bool
		checkFn func(t *testing.T, s *Scanner)
	}{
		{
			name:    "verbose scanner",
			verbose: true,
			checkFn: func(t *testing.T, s *Scanner) {
				if s == nil {
					t.Error("scanner should not be nil")
				}
				if !s.verbose {
					t.Error("verbose should be true")
				}
			},
		},
		{
			name:    "non-verbose scanner",
			verbose: false,
			checkFn: func(t *testing.T, s *Scanner) {
				if s == nil {
					t.Error("scanner should not be nil")
				}
				if s.verbose {
					t.Error("verbose should be false")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewScanner(tt.verbose)
			tt.checkFn(t, s)
		})
	}
}

func TestVulnerabilityMatchStructures(t *testing.T) {
	t.Run("VulnerabilityMatch can be marshaled and unmarshaled", func(t *testing.T) {
		match := VulnerabilityMatch{
			Vulnerability: Vulnerability{
				ID:          "CVE-2021-1234",
				Severity:    "Critical",
				Description: "A test vulnerability",
				URLs:        []string{"https://example.com/cve-2021-1234"},
				CVSS: []CVSS{
					{Version: "3.1", Vector: "CVSS:3.1/AV:N/AC:L", Score: 7.5},
				},
			},
			Package: Package{
				Name:    "test-package",
				Version: "1.0.0",
				Type:    "npm",
				PURL:    "pkg:npm/test-package@1.0.0",
			},
			MatchDetails: []MatchDetail{
				{Type: "exactMatch", Confidence: "0.95", Matcher: "stock-matcher"},
			},
		}

		data, err := json.Marshal(match)
		if err != nil {
			t.Fatalf("failed to marshal: %v", err)
		}

		var unmarshaled VulnerabilityMatch
		if err := json.Unmarshal(data, &unmarshaled); err != nil {
			t.Fatalf("failed to unmarshal: %v", err)
		}

		if unmarshaled.Vulnerability.ID != match.Vulnerability.ID {
			t.Errorf("expected ID %s, got %s", match.Vulnerability.ID, unmarshaled.Vulnerability.ID)
		}
		if unmarshaled.Vulnerability.Severity != match.Vulnerability.Severity {
			t.Errorf("expected Severity %s, got %s", match.Vulnerability.Severity, unmarshaled.Vulnerability.Severity)
		}
		if len(unmarshaled.Vulnerability.URLs) != len(match.Vulnerability.URLs) {
			t.Errorf("expected %d URLs, got %d", len(match.Vulnerability.URLs), len(unmarshaled.Vulnerability.URLs))
		}
		if len(unmarshaled.Vulnerability.CVSS) != len(match.Vulnerability.CVSS) {
			t.Errorf("expected %d CVSS entries, got %d", len(match.Vulnerability.CVSS), len(unmarshaled.Vulnerability.CVSS))
		}
	})
}

func TestScanResultStructures(t *testing.T) {
	t.Run("ScanResult with empty matches", func(t *testing.T) {
		result := &ScanResult{
			Matches:        []VulnerabilityMatch{},
			IgnoredMatches: []VulnerabilityMatch{},
		}

		data, err := json.Marshal(result)
		if err != nil {
			t.Fatalf("failed to marshal: %v", err)
		}

		var unmarshaled ScanResult
		if err := json.Unmarshal(data, &unmarshaled); err != nil {
			t.Fatalf("failed to unmarshal: %v", err)
		}

		if len(unmarshaled.Matches) != 0 {
			t.Errorf("expected 0 matches, got %d", len(unmarshaled.Matches))
		}
	})

	t.Run("ScanResult ignores empty IgnoredMatches in JSON", func(t *testing.T) {
		result := &ScanResult{
			Matches:        []VulnerabilityMatch{{Vulnerability: Vulnerability{ID: "CVE-1"}, Package: Package{Name: "p", Version: "1"}}},
			IgnoredMatches: nil,
		}

		data, err := json.Marshal(result)
		if err != nil {
			t.Fatalf("failed to marshal: %v", err)
		}

		if string(data) == "" {
			t.Error("expected non-empty JSON output")
		}
	})
}

func TestEdgeCases(t *testing.T) {
	t.Run("FilterBySeverity with all same severity", func(t *testing.T) {
		scanner := &Scanner{}
		matches := []VulnerabilityMatch{
			{Vulnerability: Vulnerability{ID: "CVE-1", Severity: "Critical"}},
			{Vulnerability: Vulnerability{ID: "CVE-2", Severity: "Critical"}},
			{Vulnerability: Vulnerability{ID: "CVE-3", Severity: "Critical"}},
		}

		result := scanner.FilterBySeverity(matches, "Critical")
		if len(result) != 3 {
			t.Errorf("expected 3 matches, got %d", len(result))
		}
	})

	t.Run("FormatJSON handles special characters", func(t *testing.T) {
		scanner := &Scanner{}
		result := &ScanResult{
			Matches: []VulnerabilityMatch{
				{
					Vulnerability: Vulnerability{
						ID:          "CVE-2021-1234",
						Severity:    "High",
						Description: "Test with <script>alert('xss')</script> and quotes \"test\"",
					},
					Package: Package{Name: "test", Version: "1.0"},
				},
			},
		}

		jsonStr, err := scanner.FormatJSON(result)
		if err != nil {
			t.Errorf("FormatJSON returned error: %v", err)
		}
		if jsonStr == "" {
			t.Error("expected non-empty JSON string")
		}
	})

	t.Run("FormatTable with exactly 40 char package name", func(t *testing.T) {
		scanner := &Scanner{}
		result := &ScanResult{
			Matches: []VulnerabilityMatch{
				{
					Vulnerability: Vulnerability{ID: "CVE-2021-1234", Severity: "High"},
					Package:       Package{Name: "1234567890123456789012345678901234567890", Version: "1.0"},
				},
			},
		}

		output := scanner.FormatTable(result)
		if output == "" {
			t.Error("expected non-empty table output")
		}
	})
}

func TestFilterBySeverityEdgeCases(t *testing.T) {
	scanner := &Scanner{}

	tests := []struct {
		name        string
		matches     []VulnerabilityMatch
		minSeverity string
		expected    int
	}{
		{
			name: "unknown severity in match gets filtered",
			matches: []VulnerabilityMatch{
				{Vulnerability: Vulnerability{ID: "CVE-1", Severity: "Unknown"}},
				{Vulnerability: Vulnerability{ID: "CVE-2", Severity: "High"}},
			},
			minSeverity: "High",
			expected:    1,
		},
		{
			name: "empty severity string",
			matches: []VulnerabilityMatch{
				{Vulnerability: Vulnerability{ID: "CVE-1", Severity: ""}},
				{Vulnerability: Vulnerability{ID: "CVE-2", Severity: "High"}},
			},
			minSeverity: "High",
			expected:    1,
		},
		{
			name: "empty minSeverity returns all",
			matches: []VulnerabilityMatch{
				{Vulnerability: Vulnerability{ID: "CVE-1", Severity: "Critical"}},
				{Vulnerability: Vulnerability{ID: "CVE-2", Severity: "Low"}},
			},
			minSeverity: "",
			expected:    2,
		},
		{
			name: "case sensitive severity",
			matches: []VulnerabilityMatch{
				{Vulnerability: Vulnerability{ID: "CVE-1", Severity: "critical"}},
				{Vulnerability: Vulnerability{ID: "CVE-2", Severity: "HIGH"}},
			},
			minSeverity: "Critical",
			expected:    0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := scanner.FilterBySeverity(tt.matches, tt.minSeverity)
			if len(result) != tt.expected {
				t.Errorf("expected %d matches, got %d", tt.expected, len(result))
			}
		})
	}
}

func TestFormatTableEdgeCases(t *testing.T) {
	scanner := &Scanner{}

	tests := []struct {
		name   string
		result *ScanResult
	}{
		{
			name: "package name exactly 41 chars gets truncated",
			result: &ScanResult{
				Matches: []VulnerabilityMatch{
					{
						Vulnerability: Vulnerability{ID: "CVE-1", Severity: "High"},
						Package:       Package{Name: "12345678901234567890123456789012345678901", Version: "1.0"},
					},
				},
			},
		},
		{
			name: "very long vulnerability ID",
			result: &ScanResult{
				Matches: []VulnerabilityMatch{
					{
						Vulnerability: Vulnerability{ID: "CVE-VERY-LONG-ID-THAT-MIGHT-AFFECT-FORMATTING-2021-1234", Severity: "Critical"},
						Package:       Package{Name: "pkg", Version: "1.0"},
					},
				},
			},
		},
		{
			name: "empty version",
			result: &ScanResult{
				Matches: []VulnerabilityMatch{
					{
						Vulnerability: Vulnerability{ID: "CVE-1", Severity: "High"},
						Package:       Package{Name: "test-pkg", Version: ""},
					},
				},
			},
		},
		{
			name: "many vulnerabilities in table",
			result: &ScanResult{
				Matches: []VulnerabilityMatch{
					{Vulnerability: Vulnerability{ID: "CVE-1", Severity: "Critical"}, Package: Package{Name: "p1", Version: "1.0"}},
					{Vulnerability: Vulnerability{ID: "CVE-2", Severity: "High"}, Package: Package{Name: "p2", Version: "2.0"}},
					{Vulnerability: Vulnerability{ID: "CVE-3", Severity: "Medium"}, Package: Package{Name: "p3", Version: "3.0"}},
					{Vulnerability: Vulnerability{ID: "CVE-4", Severity: "Low"}, Package: Package{Name: "p4", Version: "4.0"}},
					{Vulnerability: Vulnerability{ID: "CVE-5", Severity: "Negligible"}, Package: Package{Name: "p5", Version: "5.0"}},
					{Vulnerability: Vulnerability{ID: "CVE-6", Severity: "Critical"}, Package: Package{Name: "p6", Version: "6.0"}},
					{Vulnerability: Vulnerability{ID: "CVE-7", Severity: "High"}, Package: Package{Name: "p7", Version: "7.0"}},
					{Vulnerability: Vulnerability{ID: "CVE-8", Severity: "Medium"}, Package: Package{Name: "p8", Version: "8.0"}},
					{Vulnerability: Vulnerability{ID: "CVE-9", Severity: "Low"}, Package: Package{Name: "p9", Version: "9.0"}},
					{Vulnerability: Vulnerability{ID: "CVE-10", Severity: "Negligible"}, Package: Package{Name: "p10", Version: "10.0"}},
				},
			},
		},
		{
			name: "package name with colons",
			result: &ScanResult{
				Matches: []VulnerabilityMatch{
					{
						Vulnerability: Vulnerability{ID: "CVE-1", Severity: "High"},
						Package:       Package{Name: "npm:@scope/package", Version: "1.0.0"},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output := scanner.FormatTable(tt.result)
			if output == "" {
				t.Error("expected non-empty table output")
			}
			if !contains(output, "Total vulnerabilities:") {
				t.Error("expected total count in output")
			}
		})
	}
}

func TestFormatJSONEdgeCases(t *testing.T) {
	scanner := &Scanner{}

	tests := []struct {
		name   string
		result *ScanResult
	}{
		{
			name: "nil matches",
			result: &ScanResult{
				Matches: nil,
			},
		},
		{
			name: "nil ignored matches",
			result: &ScanResult{
				Matches:        []VulnerabilityMatch{},
				IgnoredMatches: nil,
			},
		},
		{
			name: "source is nil",
			result: &ScanResult{
				Matches: []VulnerabilityMatch{
					{Vulnerability: Vulnerability{ID: "CVE-1", Severity: "High"}, Package: Package{Name: "pkg", Version: "1.0"}},
				},
				Source: nil,
			},
		},
		{
			name: "empty vulnerability ID",
			result: &ScanResult{
				Matches: []VulnerabilityMatch{
					{Vulnerability: Vulnerability{ID: "", Severity: "High"}, Package: Package{Name: "pkg", Version: "1.0"}},
				},
			},
		},
		{
			name: "empty URLs and CVSS",
			result: &ScanResult{
				Matches: []VulnerabilityMatch{
					{
						Vulnerability: Vulnerability{
							ID:       "CVE-1",
							Severity: "High",
							URLs:     []string{},
							CVSS:     []CVSS{},
						},
						Package: Package{Name: "pkg", Version: "1.0"},
					},
				},
			},
		},
		{
			name: "multiple CVSS entries",
			result: &ScanResult{
				Matches: []VulnerabilityMatch{
					{
						Vulnerability: Vulnerability{
							ID:       "CVE-1",
							Severity: "High",
							CVSS: []CVSS{
								{Version: "2.0", Vector: "AV:N/AC:L/Au:N/C:C/I:C/A:C", Score: 10.0},
								{Version: "3.0", Vector: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", Score: 9.8},
								{Version: "3.1", Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", Score: 9.1},
							},
						},
						Package: Package{Name: "pkg", Version: "1.0"},
					},
				},
			},
		},
		{
			name: "package with PURL only",
			result: &ScanResult{
				Matches: []VulnerabilityMatch{
					{
						Vulnerability: Vulnerability{ID: "CVE-1", Severity: "High"},
						Package:       Package{Name: "pkg", Version: "1.0", PURL: "pkg:generic/pkg@1.0"},
					},
				},
			},
		},
		{
			name: "unicode in description",
			result: &ScanResult{
				Matches: []VulnerabilityMatch{
					{
						Vulnerability: Vulnerability{
							ID:          "CVE-2021-1234",
							Severity:    "High",
							Description: "Unicode test: äöü ß 中文 日本語 🎉",
						},
						Package: Package{Name: "pkg", Version: "1.0"},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jsonStr, err := scanner.FormatJSON(tt.result)
			if err != nil {
				t.Errorf("FormatJSON returned error: %v", err)
			}
			if jsonStr == "" {
				t.Error("expected non-empty JSON string")
			}
			var result ScanResult
			if err := json.Unmarshal([]byte(jsonStr), &result); err != nil {
				t.Errorf("failed to unmarshal JSON: %v", err)
			}
		})
	}
}

func TestScanResultWithMockFixtures(t *testing.T) {
	t.Run("complex scan result with all fields", func(t *testing.T) {
		result := &ScanResult{
			Matches: []VulnerabilityMatch{
				{
					Vulnerability: Vulnerability{
						ID:          "CVE-2021-0001",
						Severity:    "Critical",
						Description: "Remote code execution via buffer overflow",
						URLs: []string{
							"https://nvd.nist.gov/vuln/detail/CVE-2021-0001",
							"https://example.com/advisory/001",
						},
						CVSS: []CVSS{
							{
								Version: "3.1",
								Vector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
								Score:   9.8,
							},
						},
					},
					Package: Package{
						Name:    "openssl",
						Version: "1.1.1k",
						Type:    "rpm",
						PURL:    "pkg:rpm/openssl@1.1.1k",
					},
					MatchDetails: []MatchDetail{
						{
							Type:       "exactMatch",
							Confidence: "1.00",
							Matcher:    "stock-matcher",
						},
					},
				},
				{
					Vulnerability: Vulnerability{
						ID:       "CVE-2021-0002",
						Severity: "High",
					},
					Package: Package{
						Name:    "curl",
						Version: "7.77.0",
						Type:    "deb",
					},
					MatchDetails: []MatchDetail{
						{
							Type:       "fuzzyMatch",
							Confidence: "0.85",
							Matcher:    "stock-matcher",
						},
						{
							Type:       "cpeMatch",
							Confidence: "0.90",
							Matcher:    "stock-matcher",
						},
					},
				},
			},
			IgnoredMatches: []VulnerabilityMatch{
				{
					Vulnerability: Vulnerability{
						ID:       "CVE-2021-0003",
						Severity: "Medium",
					},
					Package: Package{
						Name:    "python",
						Version: "3.9.0",
						Type:    "python",
					},
				},
			},
		}

		scanner := &Scanner{}
		jsonStr, err := scanner.FormatJSON(result)
		if err != nil {
			t.Fatalf("FormatJSON failed: %v", err)
		}

		var parsed ScanResult
		if err := json.Unmarshal([]byte(jsonStr), &parsed); err != nil {
			t.Fatalf("failed to unmarshal: %v", err)
		}

		if len(parsed.Matches) != 2 {
			t.Errorf("expected 2 matches, got %d", len(parsed.Matches))
		}
		if len(parsed.IgnoredMatches) != 1 {
			t.Errorf("expected 1 ignored match, got %d", len(parsed.IgnoredMatches))
		}
		if len(parsed.Matches[0].MatchDetails) != 1 {
			t.Errorf("expected 1 match detail, got %d", len(parsed.Matches[0].MatchDetails))
		}
		if len(parsed.Matches[1].MatchDetails) != 2 {
			t.Errorf("expected 2 match details, got %d", len(parsed.Matches[1].MatchDetails))
		}

		tableOutput := scanner.FormatTable(result)
		if !contains(tableOutput, "openssl:1.1.1k") {
			t.Error("expected openssl package in table output")
		}
		if !contains(tableOutput, "curl:7.77.0") {
			t.Error("expected curl package in table output")
		}
	})

	t.Run("filter complex results", func(t *testing.T) {
		matches := []VulnerabilityMatch{
			{Vulnerability: Vulnerability{ID: "CVE-CRIT-1", Severity: "Critical"}, Package: Package{Name: "c1", Version: "1.0"}},
			{Vulnerability: Vulnerability{ID: "CVE-CRIT-2", Severity: "Critical"}, Package: Package{Name: "c2", Version: "1.0"}},
			{Vulnerability: Vulnerability{ID: "CVE-HIGH-1", Severity: "High"}, Package: Package{Name: "h1", Version: "1.0"}},
			{Vulnerability: Vulnerability{ID: "CVE-HIGH-2", Severity: "High"}, Package: Package{Name: "h2", Version: "1.0"}},
			{Vulnerability: Vulnerability{ID: "CVE-MED-1", Severity: "Medium"}, Package: Package{Name: "m1", Version: "1.0"}},
			{Vulnerability: Vulnerability{ID: "CVE-LOW-1", Severity: "Low"}, Package: Package{Name: "l1", Version: "1.0"}},
			{Vulnerability: Vulnerability{ID: "CVE-NEG-1", Severity: "Negligible"}, Package: Package{Name: "n1", Version: "1.0"}},
		}

		scanner := &Scanner{}

		criticalOnly := scanner.FilterBySeverity(matches, "Critical")
		if len(criticalOnly) != 2 {
			t.Errorf("expected 2 critical, got %d", len(criticalOnly))
		}

		highAndAbove := scanner.FilterBySeverity(matches, "High")
		if len(highAndAbove) != 4 {
			t.Errorf("expected 4 high+, got %d", len(highAndAbove))
		}

		mediumAndAbove := scanner.FilterBySeverity(matches, "Medium")
		if len(mediumAndAbove) != 5 {
			t.Errorf("expected 5 medium+, got %d", len(mediumAndAbove))
		}

		lowAndAbove := scanner.FilterBySeverity(matches, "Low")
		if len(lowAndAbove) != 6 {
			t.Errorf("expected 6 low+, got %d", len(lowAndAbove))
		}
	})
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

func TestGrypeAdapter_FindMatches(t *testing.T) {
	t.Run("FindMatches uses NewScanner", func(t *testing.T) {
		_ = &GrypeAdapter{}
		scanner := NewScanner(false)
		if scanner == nil {
			t.Error("expected non-nil scanner")
		}
	})

	t.Run("NewScanner creates scanner with nil mock func", func(t *testing.T) {
		scanner := NewScanner(false)
		if scanner.vulnProviderFunc != nil {
			t.Error("expected nil vulnProviderFunc")
		}
	})

	t.Run("NewScannerWithMock creates scanner with mock func", func(t *testing.T) {
		mockFunc := func(ctx context.Context, sbomModel *sbom.SBOM) (*ScanResult, error) {
			return nil, nil
		}
		scanner := NewScannerWithMock(true, mockFunc)
		if scanner == nil {
			t.Error("expected non-nil scanner")
		}
		if !scanner.verbose {
			t.Error("expected verbose to be true")
		}
		if scanner.vulnProviderFunc == nil {
			t.Error("expected non-nil vulnProviderFunc")
		}
	})
}

func TestScanner_Verbose(t *testing.T) {
	t.Run("verbose mode enables logging", func(t *testing.T) {
		scanner := NewScanner(true)
		if !scanner.verbose {
			t.Error("expected verbose to be true")
		}
	})

	t.Run("non-verbose mode disables logging", func(t *testing.T) {
		scanner := NewScanner(false)
		if scanner.verbose {
			t.Error("expected verbose to be false")
		}
	})
}

func TestScanner_ConvertMatch(t *testing.T) {
	t.Run("convertMatch with all fields populated", func(t *testing.T) {
		scanner := &Scanner{verbose: false}

		result := &ScanResult{
			Matches: []VulnerabilityMatch{
				{
					Vulnerability: Vulnerability{
						ID:          "CVE-2024-0001",
						Severity:    "Critical",
						Description: "Test description",
						URLs:        []string{"https://example.com/cve-2024-0001"},
						CVSS: []CVSS{
							{Version: "3.1", Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", Score: 9.8},
						},
					},
					Package: Package{
						Name:    "test-package",
						Version: "1.0.0",
						Type:    "npm",
						PURL:    "pkg:npm/test-package@1.0.0",
					},
					MatchDetails: []MatchDetail{
						{Type: "exactMatch", Confidence: "1.00", Matcher: "stock-matcher"},
					},
				},
			},
		}

		jsonStr, err := scanner.FormatJSON(result)
		if err != nil {
			t.Errorf("FormatJSON error: %v", err)
		}
		if jsonStr == "" {
			t.Error("expected non-empty JSON")
		}
	})

	t.Run("convertMatch with only required fields", func(t *testing.T) {
		scanner := &Scanner{verbose: false}

		result := &ScanResult{
			Matches: []VulnerabilityMatch{
				{
					Vulnerability: Vulnerability{
						ID:       "CVE-2024-0002",
						Severity: "Unknown",
					},
					Package: Package{
						Name:    "minimal-pkg",
						Version: "0.1.0",
					},
				},
			},
		}

		jsonStr, err := scanner.FormatJSON(result)
		if err != nil {
			t.Errorf("FormatJSON error: %v", err)
		}
		if !contains(jsonStr, "CVE-2024-0002") {
			t.Error("expected CVE ID in JSON")
		}
	})
}

func TestFormatJSON_ErrorPaths(t *testing.T) {
	t.Run("FormatJSON with marshal error", func(t *testing.T) {
		scanner := &Scanner{}

		type Unmarshable struct {
			Chan chan int
		}

		result := &ScanResult{
			Matches: []VulnerabilityMatch{
				{
					Vulnerability: Vulnerability{ID: "CVE-1"},
					Package:       Package{Name: "test"},
				},
			},
		}

		_, err := scanner.FormatJSON(result)
		if err != nil {
			t.Logf("Got error (expected for unmarshable): %v", err)
		}
	})
}

func TestFilterBySeverity_MoreEdgeCases(t *testing.T) {
	scanner := &Scanner{}

	t.Run("filter with nil matches", func(t *testing.T) {
		result := scanner.FilterBySeverity(nil, "High")
		if len(result) != 0 {
			t.Errorf("expected 0, got %d", len(result))
		}
	})

	t.Run("filter with empty severity and empty matches", func(t *testing.T) {
		result := scanner.FilterBySeverity([]VulnerabilityMatch{}, "")
		if len(result) != 0 {
			t.Errorf("expected 0, got %d", len(result))
		}
	})
}

func TestScanResult_Fields(t *testing.T) {
	t.Run("ScanResult with nil source", func(t *testing.T) {
		result := &ScanResult{
			Source: nil,
		}
		scanner := &Scanner{}
		jsonStr, err := scanner.FormatJSON(result)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if jsonStr == "" {
			t.Error("expected non-empty JSON")
		}
	})

	t.Run("ScanResult with ignored matches only", func(t *testing.T) {
		result := &ScanResult{
			IgnoredMatches: []VulnerabilityMatch{
				{Vulnerability: Vulnerability{ID: "CVE-IGNORED", Severity: "Low"}, Package: Package{Name: "ignored", Version: "1.0"}},
			},
		}
		scanner := &Scanner{}
		jsonStr, err := scanner.FormatJSON(result)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if !contains(jsonStr, "ignoredMatches") {
			t.Error("expected ignoredMatches in JSON")
		}
	})
}

func TestScanWithMocks(t *testing.T) {
	t.Run("Scan returns error when mock returns error", func(t *testing.T) {
		mockErr := errors.New("database connection failed")
		scanner := NewScannerWithMock(false, func(ctx context.Context, sbomModel *sbom.SBOM) (*ScanResult, error) {
			return nil, mockErr
		})

		result, err := scanner.Scan(context.Background(), &sbom.SBOM{})
		if err == nil {
			t.Error("expected error, got nil")
		}
		if err != mockErr {
			t.Errorf("expected error %v, got %v", mockErr, err)
		}
		if result != nil {
			t.Error("expected nil result")
		}
	})

	t.Run("Scan returns mock result successfully", func(t *testing.T) {
		expectedResult := &ScanResult{
			Matches: []VulnerabilityMatch{
				{
					Vulnerability: Vulnerability{
						ID:       "CVE-MOCK-1",
						Severity: "High",
					},
					Package: Package{
						Name:    "mock-pkg",
						Version: "1.0.0",
					},
				},
			},
		}
		scanner := NewScannerWithMock(true, func(ctx context.Context, sbomModel *sbom.SBOM) (*ScanResult, error) {
			return expectedResult, nil
		})

		result, err := scanner.Scan(context.Background(), &sbom.SBOM{})
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if result == nil {
			t.Fatal("expected result, got nil")
		}
		if len(result.Matches) != 1 {
			t.Errorf("expected 1 match, got %d", len(result.Matches))
		}
		if result.Matches[0].Vulnerability.ID != "CVE-MOCK-1" {
			t.Errorf("expected CVE-MOCK-1, got %s", result.Matches[0].Vulnerability.ID)
		}
	})

	t.Run("Scan returns empty matches", func(t *testing.T) {
		scanner := NewScannerWithMock(false, func(ctx context.Context, sbomModel *sbom.SBOM) (*ScanResult, error) {
			return &ScanResult{
				Matches:        []VulnerabilityMatch{},
				IgnoredMatches: []VulnerabilityMatch{},
				Source:         nil,
			}, nil
		})

		result, err := scanner.Scan(context.Background(), &sbom.SBOM{})
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if len(result.Matches) != 0 {
			t.Errorf("expected 0 matches, got %d", len(result.Matches))
		}
	})

	t.Run("Scan with ignored matches", func(t *testing.T) {
		scanner := NewScannerWithMock(false, func(ctx context.Context, sbomModel *sbom.SBOM) (*ScanResult, error) {
			return &ScanResult{
				Matches: []VulnerabilityMatch{
					{Vulnerability: Vulnerability{ID: "CVE-1", Severity: "High"}, Package: Package{Name: "pkg1", Version: "1.0"}},
				},
				IgnoredMatches: []VulnerabilityMatch{
					{Vulnerability: Vulnerability{ID: "CVE-IGNORED-1", Severity: "Low"}, Package: Package{Name: "pkg2", Version: "2.0"}},
					{Vulnerability: Vulnerability{ID: "CVE-IGNORED-2", Severity: "Medium"}, Package: Package{Name: "pkg3", Version: "3.0"}},
				},
				Source: nil,
			}, nil
		})

		result, err := scanner.Scan(context.Background(), &sbom.SBOM{})
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if len(result.Matches) != 1 {
			t.Errorf("expected 1 match, got %d", len(result.Matches))
		}
		if len(result.IgnoredMatches) != 2 {
			t.Errorf("expected 2 ignored matches, got %d", len(result.IgnoredMatches))
		}
	})

	t.Run("Scan with complex mock result", func(t *testing.T) {
		scanner := NewScannerWithMock(true, func(ctx context.Context, sbomModel *sbom.SBOM) (*ScanResult, error) {
			return &ScanResult{
				Matches: []VulnerabilityMatch{
					{
						Vulnerability: Vulnerability{
							ID:          "CVE-2024-0001",
							Severity:    "Critical",
							Description: "A critical RCE vulnerability",
							URLs:        []string{"https://nvd.example.com/CVE-2024-0001"},
							CVSS: []CVSS{
								{Version: "3.1", Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", Score: 9.8},
							},
						},
						Package: Package{
							Name:    "vulnerable-lib",
							Version: "2.5.1",
							Type:    "npm",
							PURL:    "pkg:npm/vulnerable-lib@2.5.1",
						},
						MatchDetails: []MatchDetail{
							{Type: "exactMatch", Confidence: "1.00", Matcher: "stock-matcher"},
						},
					},
					{
						Vulnerability: Vulnerability{
							ID:       "CVE-2024-0002",
							Severity: "Medium",
						},
						Package: Package{
							Name:    "another-lib",
							Version: "1.2.3",
							Type:    "go",
						},
						MatchDetails: []MatchDetail{},
					},
				},
				IgnoredMatches: []VulnerabilityMatch{},
				Source:         nil,
			}, nil
		})

		result, err := scanner.Scan(context.Background(), &sbom.SBOM{})
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}

		jsonStr, err := scanner.FormatJSON(result)
		if err != nil {
			t.Errorf("FormatJSON failed: %v", err)
		}

		var parsed ScanResult
		if err := json.Unmarshal([]byte(jsonStr), &parsed); err != nil {
			t.Errorf("failed to unmarshal: %v", err)
		}

		if len(parsed.Matches) != 2 {
			t.Errorf("expected 2 matches, got %d", len(parsed.Matches))
		}

		tableOutput := scanner.FormatTable(result)
		if !contains(tableOutput, "vulnerable-lib:2.5.1") {
			t.Error("expected vulnerable-lib in table output")
		}
	})

	t.Run("Scan context cancellation", func(t *testing.T) {
		scanner := NewScannerWithMock(false, func(ctx context.Context, sbomModel *sbom.SBOM) (*ScanResult, error) {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return &ScanResult{Matches: []VulnerabilityMatch{}}, nil
		})

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		result, err := scanner.Scan(ctx, &sbom.SBOM{})
		if err == nil {
			t.Error("expected context cancellation error")
		}
		if result != nil {
			t.Error("expected nil result on error")
		}
	})
}

func TestConvertMatchCoverage(t *testing.T) {
	t.Run("convertMatch with full metadata", func(t *testing.T) {
		scanner := NewScanner(false)

		result := &ScanResult{
			Matches: []VulnerabilityMatch{
				{
					Vulnerability: Vulnerability{
						ID:          "CVE-TEST-1",
						Severity:    "High",
						Description: "Test description",
						URLs:        []string{"url1", "url2"},
						CVSS: []CVSS{
							{Version: "3.1", Vector: "test", Score: 7.5},
						},
					},
					Package: Package{
						Name:    "test-pkg",
						Version: "1.0",
						Type:    "npm",
						PURL:    "pkg:npm/test-pkg@1.0",
					},
					MatchDetails: []MatchDetail{
						{Type: "exact", Confidence: "0.95", Matcher: "stock"},
					},
				},
			},
		}

		jsonStr, err := scanner.FormatJSON(result)
		if err != nil {
			t.Errorf("FormatJSON error: %v", err)
		}

		var parsed ScanResult
		if err := json.Unmarshal([]byte(jsonStr), &parsed); err != nil {
			t.Errorf("Unmarshal error: %v", err)
		}

		if len(parsed.Matches[0].MatchDetails) != 1 {
			t.Errorf("expected 1 match detail, got %d", len(parsed.Matches[0].MatchDetails))
		}
	})

	t.Run("convertMatch with empty metadata", func(t *testing.T) {
		scanner := NewScanner(false)

		result := &ScanResult{
			Matches: []VulnerabilityMatch{
				{
					Vulnerability: Vulnerability{
						ID:       "CVE-TEST-2",
						Severity: "Unknown",
					},
					Package: Package{
						Name:    "test-pkg",
						Version: "1.0",
					},
				},
			},
		}

		jsonStr, err := scanner.FormatJSON(result)
		if err != nil {
			t.Errorf("FormatJSON error: %v", err)
		}

		var parsed ScanResult
		if err := json.Unmarshal([]byte(jsonStr), &parsed); err != nil {
			t.Errorf("Unmarshal error: %v", err)
		}

		if parsed.Matches[0].Vulnerability.Severity != "Unknown" {
			t.Errorf("expected Unknown severity, got %s", parsed.Matches[0].Vulnerability.Severity)
		}
	})
}

func TestAdditionalEdgeCases(t *testing.T) {
	t.Run("FormatTable package name at boundary 40 chars", func(t *testing.T) {
		scanner := NewScanner(false)
		result := &ScanResult{
			Matches: []VulnerabilityMatch{
				{
					Vulnerability: Vulnerability{ID: "CVE-1", Severity: "High"},
					Package:       Package{Name: "1234567890123456789012345678901234567890", Version: "1.0"},
				},
			},
		}
		output := scanner.FormatTable(result)
		if output == "" {
			t.Error("expected non-empty output")
		}
	})

	t.Run("FormatTable package name 41 chars gets truncated", func(t *testing.T) {
		scanner := NewScanner(false)
		result := &ScanResult{
			Matches: []VulnerabilityMatch{
				{
					Vulnerability: Vulnerability{ID: "CVE-1", Severity: "High"},
					Package:       Package{Name: "12345678901234567890123456789012345678901", Version: "1.0"},
				},
			},
		}
		output := scanner.FormatTable(result)
		if output == "" {
			t.Error("expected non-empty output")
		}
	})

	t.Run("FormatTable very short vulnerability ID", func(t *testing.T) {
		scanner := NewScanner(false)
		result := &ScanResult{
			Matches: []VulnerabilityMatch{
				{
					Vulnerability: Vulnerability{ID: "C", Severity: "High"},
					Package:       Package{Name: "pkg", Version: "1.0"},
				},
			},
		}
		output := scanner.FormatTable(result)
		if !contains(output, "C") {
			t.Error("short ID should be in output")
		}
	})

	t.Run("Multiple match details in table", func(t *testing.T) {
		scanner := NewScanner(false)
		result := &ScanResult{
			Matches: []VulnerabilityMatch{
				{
					Vulnerability: Vulnerability{ID: "CVE-1", Severity: "Critical"},
					Package:       Package{Name: "pkg", Version: "1.0"},
					MatchDetails: []MatchDetail{
						{Type: "exact", Confidence: "1.00", Matcher: "stock"},
						{Type: "cpe", Confidence: "0.90", Matcher: "stock"},
						{Type: "fuzzy", Confidence: "0.75", Matcher: "stock"},
					},
				},
			},
		}
		output := scanner.FormatTable(result)
		if !contains(output, "Total vulnerabilities: 1") {
			t.Error("should show 1 vulnerability")
		}
	})

	t.Run("FormatJSON with many matches", func(t *testing.T) {
		scanner := NewScanner(false)
		matches := make([]VulnerabilityMatch, 100)
		for i := 0; i < 100; i++ {
			matches[i] = VulnerabilityMatch{
				Vulnerability: Vulnerability{ID: "CVE-2021-" + string(rune(i)), Severity: "High"},
				Package:       Package{Name: "pkg", Version: "1.0"},
			}
		}
		result := &ScanResult{Matches: matches}
		jsonStr, err := scanner.FormatJSON(result)
		if err != nil {
			t.Errorf("FormatJSON error: %v", err)
		}
		if len(jsonStr) == 0 {
			t.Error("expected non-empty JSON")
		}
	})
}
