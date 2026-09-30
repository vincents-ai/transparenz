package sbom

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMatchIndex_AddAndLookup(t *testing.T) {
	idx := NewMatchIndex()
	idx.Add("lodash", "4.17.20", "CVE-2021-23337", "high")
	idx.Add("lodash", "4.17.20", "CVE-2020-8201", "medium")

	entries := idx.Lookup("lodash", "4.17.20")
	assert.Len(t, entries, 2)
	assert.Equal(t, "CVE-2021-23337", entries[0].cve)
	assert.Equal(t, "CVE-2020-8201", entries[1].cve)
}

func TestMatchIndex_LookupEmpty(t *testing.T) {
	idx := NewMatchIndex()
	entries := idx.Lookup("nonexistent", "1.0")
	assert.Empty(t, entries)
}

func TestVulnzMatcher_MatchComponents(t *testing.T) {
	matcher := NewVulnzMatcher()
	// Feed the underlying index
	vm := matcher.(*vulnzMatcher)
	vm.matchIdx.Add("express", "4.17.1", "CVE-2024-1234", "critical")

	components := []SBOMComponent{
		{Name: "express", Version: "4.17.1", Type: "library", PURL: "pkg:npm/express@4.17.1"},
	}

	matches := matcher.MatchComponents(components)
	assert.Len(t, matches, 1)
	assert.Equal(t, "CVE-2024-1234", matches[0].CVE)
	assert.Equal(t, "express", matches[0].Component.Name)
}

func TestVulnzMatcher_MatchViaPURL(t *testing.T) {
	matcher := NewVulnzMatcher()
	vm := matcher.(*vulnzMatcher)
	vm.matchIdx.Add("@babel/core", "7.20.0", "CVE-2023-0001", "high")

	// Component name differs from PURL name — should still match via PURL
	components := []SBOMComponent{
		{Name: "core", Version: "7.20.0", Type: "library", PURL: "pkg:npm/%40babel/core@7.20.0"},
	}

	matches := matcher.MatchComponents(components)
	assert.Len(t, matches, 1)
	assert.Equal(t, "CVE-2023-0001", matches[0].CVE)
}

func TestVulnzMatcher_DeduplicatesCVEs(t *testing.T) {
	matcher := NewVulnzMatcher()
	vm := matcher.(*vulnzMatcher)
	vm.matchIdx.Add("lodash", "4.17.20", "CVE-2021-23337", "high")
	vm.matchIdx.Add("lodash", "4.17.20", "CVE-2021-23337", "high") // duplicate

	components := []SBOMComponent{
		{Name: "lodash", Version: "4.17.20", Type: "library"},
	}

	matches := matcher.MatchComponents(components)
	assert.Len(t, matches, 1, "should deduplicate CVEs")
}

func TestVulnzMatcher_NoMatches(t *testing.T) {
	matcher := NewVulnzMatcher()
	components := []SBOMComponent{
		{Name: "safe-lib", Version: "1.0.0", Type: "library"},
	}
	matches := matcher.MatchComponents(components)
	assert.Empty(t, matches)
}

func TestParseSBOMComponents_CycloneDX(t *testing.T) {
	doc := []byte(`{
		"bomFormat": "CycloneDX",
		"components": [
			{"name": "express", "version": "4.17.1", "type": "library", "purl": "pkg:npm/express@4.17.1"},
			{"name": "lodash", "version": "4.17.21", "type": "library", "purl": "pkg:npm/lodash@4.17.21"},
			{"name": "no-type", "version": "1.0.0"}
		]
	}`)

	components := ParseSBOMComponents(doc)
	assert.Len(t, components, 3)
	assert.Equal(t, "express", components[0].Name)
	assert.Equal(t, "4.17.1", components[0].Version)
	assert.Equal(t, "pkg:npm/express@4.17.1", components[0].PURL)
	assert.Equal(t, "lodash", components[1].Name)
	assert.Equal(t, "no-type", components[2].Name)
	assert.Equal(t, "library", components[2].Type, "missing type should default to library")
}

func TestParseSBOMComponents_SPDX(t *testing.T) {
	doc := []byte(`{
		"spdxVersion": "SPDX-2.3",
		"packages": [
			{
				"name": "golang.org/x/text",
				"versionInfo": "v0.3.7",
				"SPDXID": "SPDXRef-go-x-text",
				"externalRefs": [
					{
						"referenceCategory": "PACKAGE-MANAGER",
						"referenceLocator": "pkg:golang/golang.org/x/text@v0.3.7"
					}
				]
			}
		]
	}`)

	components := ParseSBOMComponents(doc)
	assert.Len(t, components, 1)
	assert.Equal(t, "golang.org/x/text", components[0].Name)
	assert.Equal(t, "v0.3.7", components[0].Version)
	assert.Equal(t, "pkg:golang/golang.org/x/text@v0.3.7", components[0].PURL)
}

func TestParseSBOMComponents_InvalidJSON(t *testing.T) {
	components := ParseSBOMComponents([]byte(`not json`))
	assert.Nil(t, components)
}

func TestParseSBOMComponents_UnknownFormat(t *testing.T) {
	doc := []byte(`{"something": "else"}`)
	components := ParseSBOMComponents(doc)
	assert.Nil(t, components)
}

func TestParseSBOMComponents_EmptyComponents(t *testing.T) {
	doc := []byte(`{"components": []}`)
	components := ParseSBOMComponents(doc)
	assert.Empty(t, components)
}

func TestExtractCycloneDXPURL_Present(t *testing.T) {
	comp := map[string]interface{}{
		"name": "test",
		"purl": "pkg:npm/test@1.0.0",
	}
	assert.Equal(t, "pkg:npm/test@1.0.0", extractCycloneDXPURL(comp))
}

func TestExtractCycloneDXPURL_Missing(t *testing.T) {
	comp := map[string]interface{}{
		"name": "test",
	}
	assert.Equal(t, "", extractCycloneDXPURL(comp))
}

func TestExtractSPDXPURL_Present(t *testing.T) {
	pkg := map[string]interface{}{
		"name": "test",
		"externalRefs": []interface{}{
			map[string]interface{}{
				"referenceCategory": "PACKAGE-MANAGER",
				"referenceLocator":  "pkg:golang/test@1.0.0",
			},
		},
	}
	assert.Equal(t, "pkg:golang/test@1.0.0", extractSPDXPURL(pkg))
}

func TestExtractSPDXPURL_NoMatchingRef(t *testing.T) {
	pkg := map[string]interface{}{
		"externalRefs": []interface{}{
			map[string]interface{}{
				"referenceCategory": "SECURITY",
				"referenceLocator":  "cpe:2.3:a:test:1.0",
			},
		},
	}
	assert.Equal(t, "", extractSPDXPURL(pkg))
}

func TestExtractSPDXPURL_NoRefs(t *testing.T) {
	pkg := map[string]interface{}{
		"name": "test",
	}
	assert.Equal(t, "", extractSPDXPURL(pkg))
}

func TestToString(t *testing.T) {
	assert.Equal(t, "hello", toString("hello"))
	assert.Equal(t, "42", toString(42))
	assert.Equal(t, "", toString(nil))
	assert.Equal(t, "true", toString(true))
}

func TestParseCycloneDXComponents_SkipsInvalid(t *testing.T) {
	raw := []interface{}{
		map[string]interface{}{"name": "valid", "version": "1.0"},
		"not a map",                              // should be skipped
		42,                                       // should be skipped
		map[string]interface{}{"version": "2.0"}, // no name, skipped
	}
	components := parseCycloneDXComponents(raw)
	assert.Len(t, components, 1)
	assert.Equal(t, "valid", components[0].Name)
}

func TestParseSPDXComponents_UsesSPDXID(t *testing.T) {
	raw := []interface{}{
		map[string]interface{}{
			"SPDXID":      "SPDXRef-pkg-1",
			"versionInfo": "1.0",
		},
	}
	components := parseSPDXComponents(raw)
	assert.Len(t, components, 1)
	assert.Equal(t, "SPDXRef-pkg-1", components[0].Name)
}

// Two components affected by the same CVE are two separate exposures. The
// matcher deduplicated on the CVE alone, so the second component disappeared
// from the result entirely — the report then reads as though that component is
// clean, and a fix shipped for the first appears to cover the second.
func TestTwoComponentsSharingACVEBothSurvive(t *testing.T) {
	matcher := NewVulnzMatcher()
	vm := matcher.(*vulnzMatcher)
	vm.matchIdx.Add("libfoo", "1.0.0", "CVE-2026-0001", "critical")
	vm.matchIdx.Add("libbar", "2.0.0", "CVE-2026-0001", "critical")

	components := []SBOMComponent{
		{Name: "libfoo", Version: "1.0.0", Type: "library"},
		{Name: "libbar", Version: "2.0.0", Type: "library"},
	}

	matches := matcher.MatchComponents(components)
	assert.Len(t, matches, 2,
		"both components are affected; dropping one makes the report understate "+
			"the exposure")
	seen := map[string]string{}
	for _, m := range matches {
		seen[m.Component.Name] = m.CVE
	}
	assert.Equal(t, "CVE-2026-0001", seen["libfoo"])
	assert.Equal(t, "CVE-2026-0001", seen["libbar"])
}

// A component is reachable through several lookup names — its own name and
// names derived from its PURL — so the same CVE can be found more than once for
// one component. Those duplicate observations must merge rather than produce
// phantom rows.
func TestDuplicateObservationsOfOneComponentMerge(t *testing.T) {
	matcher := NewVulnzMatcher()
	vm := matcher.(*vulnzMatcher)
	vm.matchIdx.Add("express", "4.17.1", "CVE-2024-1234", "critical")
	vm.matchIdx.Add("express", "4.17.1", "CVE-2024-1234", "critical")

	components := []SBOMComponent{
		{Name: "express", Version: "4.17.1", Type: "library", PURL: "pkg:npm/express@4.17.1"},
	}

	matches := matcher.MatchComponents(components)
	assert.Len(t, matches, 1,
		"two feeds reporting the same relationship for one component is one exposure")
}

// Components sharing a name but differing in version or ecosystem are different
// products, and a fix shipped for one is not a fix for the other.
func TestSameNameDifferentVersionOrEcosystemStaysDistinct(t *testing.T) {
	old := SBOMComponent{Name: "openssl", Version: "1.0.0", Type: "library"}
	fixed := SBOMComponent{Name: "openssl", Version: "3.0.0", Type: "library"}
	assert.NotEqual(t, exposureKey("CVE-2026-0002", old), exposureKey("CVE-2026-0002", fixed))

	npm := SBOMComponent{Name: "glob", Version: "7.0.0", Type: "npm"}
	maven := SBOMComponent{Name: "glob", Version: "7.0.0", Type: "maven"}
	assert.NotEqual(t, exposureKey("CVE-2026-0003", npm), exposureKey("CVE-2026-0003", maven))

	// And the same component is stable, so duplicate observations collapse.
	assert.Equal(t, exposureKey("CVE-2026-0004", npm), exposureKey("CVE-2026-0004", npm))

	// Field boundaries are preserved by the NUL separator.
	assert.NotEqual(t,
		exposureKey("CVE-1", SBOMComponent{Name: "a", Version: "bc"}),
		exposureKey("CVE-1", SBOMComponent{Name: "ab", Version: "c"}))
}
