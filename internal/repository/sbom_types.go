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
