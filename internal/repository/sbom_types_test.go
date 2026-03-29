package repository

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func loadTypeTestFixture(t *testing.T, filename string) []byte {
	data, err := os.ReadFile(filepath.Join("testdata", filename))
	if err != nil {
		t.Fatalf("failed to read test fixture: %v", err)
	}
	return data
}

func TestSPDXDocument_Unmarshal(t *testing.T) {
	data := loadTypeTestFixture(t, "spdx_sample.json")

	var doc SPDXDocument
	err := json.Unmarshal(data, &doc)
	if err != nil {
		t.Fatalf("failed to unmarshal SPDX document: %v", err)
	}

	if doc.SPDXVersion != "SPDX-2.3" {
		t.Errorf("SPDXVersion = %v, want SPDX-2.3", doc.SPDXVersion)
	}
	if doc.Name != "test-project" {
		t.Errorf("Name = %v, want test-project", doc.Name)
	}
	if doc.DocumentNamespace != "https://example.org/test-project" {
		t.Errorf("DocumentNamespace = %v, want https://example.org/test-project", doc.DocumentNamespace)
	}
	if len(doc.Packages) != 3 {
		t.Errorf("len(Packages) = %v, want 3", len(doc.Packages))
	}
}

func TestSPDXPackage_Unmarshal(t *testing.T) {
	data := loadTypeTestFixture(t, "spdx_sample.json")

	var doc SPDXDocument
	json.Unmarshal(data, &doc)

	pkg := doc.Packages[0]
	if pkg.Name != "test-project" {
		t.Errorf("Package Name = %v, want test-project", pkg.Name)
	}
	if pkg.VersionInfo != "1.0.0" {
		t.Errorf("VersionInfo = %v, want 1.0.0", pkg.VersionInfo)
	}
	if pkg.LicenseConcluded != "MIT" {
		t.Errorf("LicenseConcluded = %v, want MIT", pkg.LicenseConcluded)
	}
	if pkg.Supplier != "Test Supplier" {
		t.Errorf("Supplier = %v, want Test Supplier", pkg.Supplier)
	}

	if len(pkg.ExternalRefs) != 2 {
		t.Errorf("len(ExternalRefs) = %v, want 2", len(pkg.ExternalRefs))
	}

	var foundPURL, foundCPE bool
	for _, ref := range pkg.ExternalRefs {
		if ref.ReferenceType == "purl" && ref.ReferenceLocator == "pkg:golang/test-project@1.0.0" {
			foundPURL = true
		}
		if ref.ReferenceType == "cpe23Type" && ref.ReferenceCategory == "SECURITY" {
			foundCPE = true
		}
	}
	if !foundPURL {
		t.Error("PURL external reference not found")
	}
	if !foundCPE {
		t.Error("CPE external reference not found")
	}
}

func TestSPDXPackage_NoAssertion(t *testing.T) {
	data := loadTypeTestFixture(t, "spdx_sample.json")

	var doc SPDXDocument
	json.Unmarshal(data, &doc)

	pkg := doc.Packages[2]
	if pkg.LicenseConcluded != "NOASSERTION" {
		t.Errorf("LicenseConcluded = %v, want NOASSERTION", pkg.LicenseConcluded)
	}
	if pkg.DownloadLocation != "NOASSERTION" {
		t.Errorf("DownloadLocation = %v, want NOASSERTION", pkg.DownloadLocation)
	}
}

func TestCycloneDXDocument_Unmarshal(t *testing.T) {
	data := loadTypeTestFixture(t, "cyclonedx_sample.json")

	var doc CycloneDXDocument
	err := json.Unmarshal(data, &doc)
	if err != nil {
		t.Fatalf("failed to unmarshal CycloneDX document: %v", err)
	}

	if doc.BomFormat != "CycloneDX" {
		t.Errorf("BomFormat = %v, want CycloneDX", doc.BomFormat)
	}
	if doc.SpecVersion != "1.5" {
		t.Errorf("SpecVersion = %v, want 1.5", doc.SpecVersion)
	}
	if doc.SerialNumber != "urn:uuid:550e8400-e29b-41d4-a716-446655440000" {
		t.Errorf("SerialNumber = %v, want urn:uuid:...", doc.SerialNumber)
	}
	if len(doc.Components) != 3 {
		t.Errorf("len(Components) = %v, want 3", len(doc.Components))
	}
}

func TestCycloneDXComponent_Unmarshal(t *testing.T) {
	data := loadTypeTestFixture(t, "cyclonedx_sample.json")

	var doc CycloneDXDocument
	json.Unmarshal(data, &doc)

	comp := doc.Components[0]
	if comp.Name != "test-project" {
		t.Errorf("Component Name = %v, want test-project", comp.Name)
	}
	if comp.Version != "1.0.0" {
		t.Errorf("Version = %v, want 1.0.0", comp.Version)
	}
	if comp.Purl != "pkg:golang/test-project@1.0.0" {
		t.Errorf("Purl = %v, want pkg:golang/test-project@1.0.0", comp.Purl)
	}
	if comp.CPE != "cpe:2.3:a:test:test-project:1.0.0:*:*:*:*:*:*:*" {
		t.Errorf("CPE = %v, want cpe:...", comp.CPE)
	}
	if comp.Description != "Main test project" {
		t.Errorf("Description = %v, want Main test project", comp.Description)
	}
	if comp.Supplier == nil {
		t.Fatal("Supplier should not be nil")
	}
	if comp.Supplier.Name != "Test Supplier" {
		t.Errorf("Supplier.Name = %v, want Test Supplier", comp.Supplier.Name)
	}

	if len(comp.Licenses) != 1 {
		t.Errorf("len(Licenses) = %v, want 1", len(comp.Licenses))
	}
	if comp.Licenses[0].License.ID != "MIT" {
		t.Errorf("License ID = %v, want MIT", comp.Licenses[0].License.ID)
	}
}

func TestCycloneDXMetadata_Unmarshal(t *testing.T) {
	data := loadTypeTestFixture(t, "cyclonedx_sample.json")

	var doc CycloneDXDocument
	json.Unmarshal(data, &doc)

	if doc.Metadata == nil {
		t.Fatal("Metadata should not be nil")
	}
	if doc.Metadata.Timestamp != "2024-01-15T10:00:00Z" {
		t.Errorf("Timestamp = %v, want 2024-01-15T10:00:00Z", doc.Metadata.Timestamp)
	}
	if len(doc.Metadata.Tools) != 1 {
		t.Errorf("len(Tools) = %v, want 1", len(doc.Metadata.Tools))
	}
	if doc.Metadata.Tools[0].Name != "test-generator" {
		t.Errorf("Tool Name = %v, want test-generator", doc.Metadata.Tools[0].Name)
	}
	if doc.Metadata.Component == nil {
		t.Fatal("Metadata.Component should not be nil")
	}
	if doc.Metadata.Component.Name != "test-project" {
		t.Errorf("Metadata Component Name = %v, want test-project", doc.Metadata.Component.Name)
	}
}

func TestCycloneDXLicense_NameOnly(t *testing.T) {
	data := loadTypeTestFixture(t, "cyclonedx_sample.json")

	var doc CycloneDXDocument
	json.Unmarshal(data, &doc)

	comp := doc.Components[1]
	if len(comp.Licenses) != 1 {
		t.Fatalf("len(Licenses) = %v, want 1", len(comp.Licenses))
	}
	if comp.Licenses[0].License.Name != "Apache-2.0" {
		t.Errorf("License Name = %v, want Apache-2.0", comp.Licenses[0].License.Name)
	}
	if comp.Licenses[0].License.ID != "" {
		t.Errorf("License ID = %v, want empty", comp.Licenses[0].License.ID)
	}
}

func TestGrypeScanResult_Unmarshal(t *testing.T) {
	data := loadTypeTestFixture(t, "grype_scan.json")

	var scan GrypeScanResult
	err := json.Unmarshal(data, &scan)
	if err != nil {
		t.Fatalf("failed to unmarshal Grype scan result: %v", err)
	}

	if scan.Descriptor == nil {
		t.Fatal("Descriptor should not be nil")
	}
	if scan.Descriptor.Name != "grype" {
		t.Errorf("Descriptor.Name = %v, want grype", scan.Descriptor.Name)
	}
	if scan.Descriptor.Version != "0.80.0" {
		t.Errorf("Descriptor.Version = %v, want 0.80.0", scan.Descriptor.Version)
	}

	if len(scan.Matches) != 4 {
		t.Errorf("len(Matches) = %v, want 4", len(scan.Matches))
	}
}

func TestGrypeMatch_Severities(t *testing.T) {
	data := loadTypeTestFixture(t, "grype_scan.json")

	var scan GrypeScanResult
	json.Unmarshal(data, &scan)

	severities := make(map[string]int)
	for _, match := range scan.Matches {
		severities[match.Vulnerability.Severity]++
	}

	if severities["Critical"] != 1 {
		t.Errorf("Critical count = %v, want 1", severities["Critical"])
	}
	if severities["High"] != 1 {
		t.Errorf("High count = %v, want 1", severities["High"])
	}
	if severities["Medium"] != 1 {
		t.Errorf("Medium count = %v, want 1", severities["Medium"])
	}
	if severities["Low"] != 1 {
		t.Errorf("Low count = %v, want 1", severities["Low"])
	}
}

func TestGrypeMatch_Artifact(t *testing.T) {
	data := loadTypeTestFixture(t, "grype_scan.json")

	var scan GrypeScanResult
	json.Unmarshal(data, &scan)

	match := scan.Matches[0]
	if match.Artifact.Name != "test-package" {
		t.Errorf("Artifact.Name = %v, want test-package", match.Artifact.Name)
	}
	if match.Artifact.Version != "1.0.0" {
		t.Errorf("Artifact.Version = %v, want 1.0.0", match.Artifact.Version)
	}
	if match.Artifact.PURL != "pkg:alpine/test-package@1.0.0" {
		t.Errorf("Artifact.PURL = %v, want pkg:alpine/test-package@1.0.0", match.Artifact.PURL)
	}
}

func TestGrypeVulnerability_Fix(t *testing.T) {
	data := loadTypeTestFixture(t, "grype_scan.json")

	var scan GrypeScanResult
	json.Unmarshal(data, &scan)

	match := scan.Matches[0]
	if match.Vulnerability.Fix == nil {
		t.Fatal("Fix should not be nil")
	}
	if match.Vulnerability.Fix.State != "fixed" {
		t.Errorf("Fix.State = %v, want fixed", match.Vulnerability.Fix.State)
	}
	if len(match.Vulnerability.Fix.Versions) != 1 || match.Vulnerability.Fix.Versions[0] != "2.0.0" {
		t.Errorf("Fix.Versions = %v, want [2.0.0]", match.Vulnerability.Fix.Versions)
	}
}

func TestGrypeMatch_NoFix(t *testing.T) {
	data := loadTypeTestFixture(t, "grype_scan.json")

	var scan GrypeScanResult
	json.Unmarshal(data, &scan)

	match := scan.Matches[1]
	if match.Vulnerability.Fix != nil {
		t.Errorf("Fix should be nil for non-fixed vulnerability")
	}
}

func TestGrypeDistro_Unmarshal(t *testing.T) {
	data := loadTypeTestFixture(t, "grype_scan.json")

	var scan GrypeScanResult
	json.Unmarshal(data, &scan)

	if scan.Distro == nil {
		t.Fatal("Distro should not be nil")
	}
	if scan.Distro.Name != "alpine" {
		t.Errorf("Distro.Name = %v, want alpine", scan.Distro.Name)
	}
	if scan.Distro.Version != "3.19" {
		t.Errorf("Distro.Version = %v, want 3.19", scan.Distro.Version)
	}
}

func TestSPDXExtRef_Categories(t *testing.T) {
	data := loadTypeTestFixture(t, "spdx_sample.json")

	var doc SPDXDocument
	json.Unmarshal(data, &doc)

	pkg := doc.Packages[0]
	var packageManager, securityCategory string
	for _, ref := range pkg.ExternalRefs {
		if ref.ReferenceCategory == "PACKAGE_MANAGER" {
			packageManager = ref.ReferenceCategory
		}
		if ref.ReferenceCategory == "SECURITY" {
			securityCategory = ref.ReferenceCategory
		}
	}
	if packageManager == "" {
		t.Error("PACKAGE_MANAGER category not found")
	}
	if securityCategory == "" {
		t.Error("SECURITY category not found")
	}
}

func TestCycloneDXHash_Unmarshal(t *testing.T) {
	cdxJSON := `{
		"bomFormat": "CycloneDX",
		"specVersion": "1.5",
		"components": [{
			"type": "library",
			"name": "test",
			"hashes": [
				{"alg": "SHA-256", "content": "abc123"},
				{"alg": "SHA-512", "content": "def456"}
			]
		}]
	}`

	var doc CycloneDXDocument
	err := json.Unmarshal([]byte(cdxJSON), &doc)
	if err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if len(doc.Components[0].Hashes) != 2 {
		t.Errorf("len(Hashes) = %v, want 2", len(doc.Components[0].Hashes))
	}
	if doc.Components[0].Hashes[0].Alg != "SHA-256" {
		t.Errorf("Hash[0].Alg = %v, want SHA-256", doc.Components[0].Hashes[0].Alg)
	}
	if doc.Components[0].Hashes[1].Content != "def456" {
		t.Errorf("Hash[1].Content = %v, want def456", doc.Components[0].Hashes[1].Content)
	}
}

func TestGrypeCVSS_Unmarshal(t *testing.T) {
	grypeJSON := `{
		"matches": [{
			"vulnerability": {
				"id": "CVE-2024-TEST",
				"severity": "High",
				"cvss": [{
					"version": "3.1",
					"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
					"metrics": {
						"baseScore": 7.5,
						"exploitabilityScore": 3.9,
						"impactScore": 3.6
					}
				}]
			},
			"artifact": {"name": "test"}
		}]
	}`

	var scan GrypeScanResult
	err := json.Unmarshal([]byte(grypeJSON), &scan)
	if err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if len(scan.Matches[0].Vulnerability.CVSS) != 1 {
		t.Errorf("len(CVSS) = %v, want 1", len(scan.Matches[0].Vulnerability.CVSS))
	}
	cvss := scan.Matches[0].Vulnerability.CVSS[0]
	if cvss.Version != "3.1" {
		t.Errorf("CVSS.Version = %v, want 3.1", cvss.Version)
	}
	if cvss.Vector != "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N" {
		t.Errorf("CVSS.Vector = %v, want CVSS:...", cvss.Vector)
	}
}

func TestGrypeRelatedVulnerabilities_Unmarshal(t *testing.T) {
	grypeJSON := `{
		"matches": [{
			"vulnerability": {
				"id": "CVE-2024-TEST",
				"severity": "Medium"
			},
			"relatedVulnerabilities": [
				{"id": "GHSA-xxxx-yyyy", "namespace": "github:distro:alpine"},
				{"id": "CVE-2024-ALIAS", "namespace": "alpine:3.19"}
			],
			"artifact": {"name": "test"}
		}]
	}`

	var scan GrypeScanResult
	err := json.Unmarshal([]byte(grypeJSON), &scan)
	if err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if len(scan.Matches[0].RelatedVulnerabilities) != 2 {
		t.Errorf("len(RelatedVulnerabilities) = %v, want 2", len(scan.Matches[0].RelatedVulnerabilities))
	}
	if scan.Matches[0].RelatedVulnerabilities[0].ID != "GHSA-xxxx-yyyy" {
		t.Errorf("RelatedVuln[0].ID = %v, want GHSA-xxxx-yyyy", scan.Matches[0].RelatedVulnerabilities[0].ID)
	}
}
