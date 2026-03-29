package scan

import (
	"encoding/json"
	"testing"
)

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
