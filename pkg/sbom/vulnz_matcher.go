package sbom

import (
	"encoding/json"
	"fmt"

	"github.com/anchore/packageurl-go"
)

type SBOMComponent struct {
	Name    string
	Version string
	Type    string
	PURL    string
}

type matchEntry struct {
	cve      string
	severity string
}

type VulnerabilityMatch struct {
	Component SBOMComponent
	CVE       string
	Severity  string
}

type MatchIndex struct {
	entries map[string][]matchEntry
}

func NewMatchIndex() *MatchIndex {
	return &MatchIndex{
		entries: make(map[string][]matchEntry),
	}
}

func (idx *MatchIndex) Add(name, version, cve, severity string) {
	entries := idx.entries[name]
	entries = append(entries, matchEntry{cve: cve, severity: severity})
	idx.entries[name] = entries
}

func (idx *MatchIndex) Lookup(name, version string) []matchEntry {
	return idx.entries[name]
}

// VulnerabilityMatcher defines the interface for matching SBOM components to vulnerabilities.
type VulnerabilityMatcher interface {
	// MatchComponents matches a list of SBOM components against vulnerability data.
	MatchComponents(components []SBOMComponent) []VulnerabilityMatch
}

// vulnzMatcher matches SBOM components to vulnerability data
type vulnzMatcher struct {
	matchIdx *MatchIndex
}

// NewVulnzMatcher creates a new vulnerability matcher.
// Returns VulnerabilityMatcher interface.
func NewVulnzMatcher() VulnerabilityMatcher {
	return &vulnzMatcher{
		matchIdx: NewMatchIndex(),
	}
}

func (m *vulnzMatcher) MatchComponents(components []SBOMComponent) []VulnerabilityMatch {
	var matches []VulnerabilityMatch
	seen := make(map[string]bool)

	for _, comp := range components {
		lookupNames := []string{comp.Name}
		if comp.PURL != "" {
			if p, err := packageurl.FromString(comp.PURL); err == nil {
				if p.Name != "" {
					lookupNames = append(lookupNames, p.Name)
				}
				if p.Namespace != "" {
					lookupNames = append(lookupNames, p.Namespace+"/"+p.Name)
				}
			}
		}

		for _, name := range lookupNames {
			entries := m.matchIdx.Lookup(name, comp.Version)
			for _, entry := range entries {
				if !seen[entry.cve] {
					seen[entry.cve] = true
					matches = append(matches, VulnerabilityMatch{
						Component: comp,
						CVE:       entry.cve,
						Severity:  entry.severity,
					})
				}
			}
		}
	}

	return matches
}

func ParseSBOMComponents(sbomDoc []byte) []SBOMComponent {
	var sbom map[string]interface{}
	if err := json.Unmarshal(sbomDoc, &sbom); err != nil {
		return nil
	}

	if componentsRaw, ok := sbom["components"].([]interface{}); ok {
		return parseCycloneDXComponents(componentsRaw)
	}

	if packagesRaw, ok := sbom["packages"].([]interface{}); ok {
		return parseSPDXComponents(packagesRaw)
	}

	return nil
}

func parseCycloneDXComponents(raw []interface{}) []SBOMComponent {
	var components []SBOMComponent
	for _, c := range raw {
		cm, ok := c.(map[string]interface{})
		if !ok {
			continue
		}
		name := toString(cm["name"])
		if name == "" {
			continue
		}
		comp := SBOMComponent{
			Name:    name,
			Version: toString(cm["version"]),
			Type:    toString(cm["type"]),
			PURL:    extractCycloneDXPURL(cm),
		}
		if comp.Type == "" {
			comp.Type = "library"
		}
		components = append(components, comp)
	}
	return components
}

func extractCycloneDXPURL(comp map[string]interface{}) string {
	if purl, ok := comp["purl"].(string); ok {
		return purl
	}
	return ""
}

func parseSPDXComponents(raw []interface{}) []SBOMComponent {
	var components []SBOMComponent
	for _, p := range raw {
		pm, ok := p.(map[string]interface{})
		if !ok {
			continue
		}
		name := toString(pm["name"])
		if name == "" {
			if spdxID, ok := pm["SPDXID"].(string); ok {
				name = spdxID
			}
		}
		comp := SBOMComponent{
			Name:    name,
			Version: toString(pm["versionInfo"]),
			Type:    "library",
			PURL:    extractSPDXPURL(pm),
		}
		if comp.Name != "" {
			components = append(components, comp)
		}
	}
	return components
}

func extractSPDXPURL(pkg map[string]interface{}) string {
	if refs, ok := pkg["externalRefs"].([]interface{}); ok {
		for _, r := range refs {
			rm, ok := r.(map[string]interface{})
			if !ok {
				continue
			}
			if toString(rm["referenceCategory"]) == "PACKAGE-MANAGER" {
				return toString(rm["referenceLocator"])
			}
		}
	}
	return ""
}

func toString(v interface{}) string {
	if v == nil {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return fmt.Sprintf("%v", v)
	}
	return s
}
