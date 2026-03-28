// SPDX-License-Identifier: AGPL-3.0-or-later OR Commercial
// Copyright (c) 2026 Vincent Palmer

package repository

// SPDX structures for typed parsing of SPDX SBOM documents
// These types provide compile-time safety and validation for SBOM parsing,
// replacing brittle map[string]interface{} type assertions.

// SPDXDocument represents an SPDX 2.x document structure
type SPDXDocument struct {
	SPDXVersion       string        `json:"spdxVersion"`
	DataLicense       string        `json:"dataLicense"`
	SPDXID            string        `json:"SPDXID"`
	Name              string        `json:"name"`
	DocumentNamespace string        `json:"documentNamespace"`
	DocumentDescribes []string      `json:"documentDescribes,omitempty"`
	Packages          []SPDXPackage `json:"packages"`
	CreationInfo      *SPDXCreation `json:"creationInfo,omitempty"`
}

// SPDXCreation contains SPDX document creation metadata
type SPDXCreation struct {
	Created            string   `json:"created,omitempty"`
	Creators           []string `json:"creators,omitempty"`
	LicenseListVersion string   `json:"licenseListVersion,omitempty"`
}

// SPDXPackage represents a package in an SPDX document
type SPDXPackage struct {
	SPDXID           string         `json:"SPDXID"`
	Name             string         `json:"name"`
	VersionInfo      string         `json:"versionInfo,omitempty"`
	LicenseConcluded string         `json:"licenseConcluded,omitempty"`
	LicenseDeclared  string         `json:"licenseDeclared,omitempty"`
	Supplier         string         `json:"supplier,omitempty"`
	Originator       string         `json:"originator,omitempty"`
	DownloadLocation string         `json:"downloadLocation,omitempty"`
	Description      string         `json:"description,omitempty"`
	Checksums        []SPDXChecksum `json:"checksums,omitempty"`
	ExternalRefs     []SPDXExtRef   `json:"externalRefs,omitempty"`
}

// SPDXChecksum represents a checksum in SPDX format
type SPDXChecksum struct {
	Algorithm     string `json:"algorithm"`
	ChecksumValue string `json:"checksumValue"`
	Comment       string `json:"comment,omitempty"`
}

// SPDXExtRef represents an external reference in SPDX format
type SPDXExtRef struct {
	ReferenceCategory string `json:"referenceCategory"`
	ReferenceType     string `json:"referenceType"`
	ReferenceLocator  string `json:"referenceLocator"`
}

// CycloneDX structures for typed parsing of CycloneDX SBOM documents

// CycloneDXDocument represents a CycloneDX BOM document
type CycloneDXDocument struct {
	BomFormat    string               `json:"bomFormat"`
	SpecVersion  string               `json:"specVersion"`
	Version      int                  `json:"version"`
	SerialNumber string               `json:"serialNumber,omitempty"`
	Metadata     *CycloneDXMetadata   `json:"metadata,omitempty"`
	Components   []CycloneDXComponent `json:"components"`
}

// CycloneDXMetadata contains BOM metadata
type CycloneDXMetadata struct {
	Timestamp string              `json:"timestamp,omitempty"`
	Tools     []CycloneDXTool     `json:"tools,omitempty"`
	Component *CycloneDXComponent `json:"component,omitempty"`
}

// CycloneDXTool represents a tool that generated the BOM
type CycloneDXTool struct {
	Vendor  string `json:"vendor,omitempty"`
	Name    string `json:"name,omitempty"`
	Version string `json:"version,omitempty"`
}

// CycloneDXComponent represents a component in CycloneDX format
type CycloneDXComponent struct {
	Type        string                 `json:"type"`
	Name        string                 `json:"name"`
	Version     string                 `json:"version,omitempty"`
	Purl        string                 `json:"purl,omitempty"`
	CPE         string                 `json:"cpe,omitempty"`
	Description string                 `json:"description,omitempty"`
	Licenses    []CycloneDXLicense     `json:"licenses,omitempty"`
	Hashes      []CycloneDXHash        `json:"hashes,omitempty"`
	Supplier    *CycloneDXOrganization `json:"supplier,omitempty"`
}

// CycloneDXLicense represents a license in CycloneDX format
type CycloneDXLicense struct {
	License CycloneDXLicenseData `json:"license"`
}

// CycloneDXLicenseData contains license details
type CycloneDXLicenseData struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
	URL  string `json:"url,omitempty"`
}

// CycloneDXHash represents a hash in CycloneDX format
type CycloneDXHash struct {
	Alg     string `json:"alg"`
	Content string `json:"content"`
}

// CycloneDXOrganization represents an organization (supplier, manufacturer, etc.)
type CycloneDXOrganization struct {
	Name string `json:"name"`
	URL  string `json:"url,omitempty"`
}

// Grype structures for typed parsing of Grype vulnerability scan results
// These types provide compile-time safety for vulnerability data parsing,
// replacing brittle map[string]interface{} type assertions per BSI TR-03183 requirements.

// GrypeScanResult represents the root structure of a Grype scan result
type GrypeScanResult struct {
	Matches    []GrypeMatch     `json:"matches"`
	Source     *GrypeSource     `json:"source,omitempty"`
	Distro     *GrypeDistro     `json:"distro,omitempty"`
	Descriptor *GrypeDescriptor `json:"descriptor,omitempty"`
}

// GrypeMatch represents a vulnerability match in Grype results
type GrypeMatch struct {
	Vulnerability          GrypeVulnerability `json:"vulnerability"`
	RelatedVulnerabilities []GrypeRelatedVuln `json:"relatedVulnerabilities,omitempty"`
	MatchDetails           []GrypeMatchDetail `json:"matchDetails,omitempty"`
	Artifact               GrypeArtifact      `json:"artifact"`
}

// GrypeVulnerability contains vulnerability metadata
type GrypeVulnerability struct {
	ID          string      `json:"id"`
	DataSource  string      `json:"dataSource,omitempty"`
	Namespace   string      `json:"namespace,omitempty"`
	Severity    string      `json:"severity"`
	URLs        []string    `json:"urls,omitempty"`
	Description string      `json:"description,omitempty"`
	CVSS        []GrypeCVSS `json:"cvss,omitempty"`
	Fix         *GrypeFix   `json:"fix,omitempty"`
}

// GrypeCVSS contains CVSS score information
type GrypeCVSS struct {
	Version string                 `json:"version"`
	Vector  string                 `json:"vector,omitempty"`
	Metrics map[string]interface{} `json:"metrics,omitempty"`
}

// GrypeFix contains fix information for a vulnerability
type GrypeFix struct {
	Versions []string `json:"versions,omitempty"`
	State    string   `json:"state,omitempty"`
}

// GrypeRelatedVuln represents related vulnerabilities (aliases)
type GrypeRelatedVuln struct {
	ID         string `json:"id"`
	DataSource string `json:"dataSource,omitempty"`
	Namespace  string `json:"namespace,omitempty"`
}

// GrypeMatchDetail contains match metadata
type GrypeMatchDetail struct {
	Type       string                 `json:"type"`
	Matcher    string                 `json:"matcher"`
	SearchedBy map[string]interface{} `json:"searchedBy,omitempty"`
	Found      map[string]interface{} `json:"found,omitempty"`
}

// GrypeArtifact represents the artifact (package) associated with a match
type GrypeArtifact struct {
	Name      string                 `json:"name"`
	Version   string                 `json:"version,omitempty"`
	Type      string                 `json:"type,omitempty"`
	Locations []GrypeLocation        `json:"locations,omitempty"`
	Language  string                 `json:"language,omitempty"`
	Licenses  []string               `json:"licenses,omitempty"`
	CPEs      []string               `json:"cpes,omitempty"`
	PURL      string                 `json:"purl,omitempty"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

// GrypeLocation represents a file system location
type GrypeLocation struct {
	Path    string `json:"path"`
	LayerID string `json:"layerID,omitempty"`
}

// GrypeSource contains scan source metadata
type GrypeSource struct {
	Type   string      `json:"type"`
	Target interface{} `json:"target,omitempty"`
}

// GrypeDistro contains distribution metadata
type GrypeDistro struct {
	Name    string   `json:"name,omitempty"`
	Version string   `json:"version,omitempty"`
	IDLike  []string `json:"idLike,omitempty"`
}

// GrypeDescriptor contains tool descriptor metadata
type GrypeDescriptor struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}
