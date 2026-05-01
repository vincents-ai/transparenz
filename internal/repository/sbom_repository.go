// SPDX-License-Identifier: AGPL-3.0-or-later OR Commercial
// Copyright (c) 2026 Vincent Palmer

package repository

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/vincents-ai/transparenz/internal/models"
)

// SBOMRepository handles database operations for SBOMs
type SBOMRepository struct {
	db *gorm.DB
}

// NewSBOMRepository creates a new SBOM repository
func NewSBOMRepository(db *gorm.DB) *SBOMRepository {
	return &SBOMRepository{db: db}
}

// normalizeHashAlgorithm normalizes SBOM algorithm names to match the PackageHash DB constraint.
// Accepted values: SHA1, SHA256, SHA384, SHA512, MD5, SHA3-256, SHA3-384, SHA3-512,
// BLAKE2b-256, BLAKE2b-384, BLAKE2b-512.
// Returns an empty string if the algorithm is not recognized or supported.
func normalizeHashAlgorithm(alg string) string {
	switch strings.ToUpper(alg) {
	case "SHA-1", "SHA1":
		return "SHA1"
	case "SHA-256", "SHA256":
		return "SHA256"
	case "SHA-384", "SHA384":
		return "SHA384"
	case "SHA-512", "SHA512":
		return "SHA512"
	case "MD5":
		return "MD5"
	case "SHA3-256":
		return "SHA3-256"
	case "SHA3-384":
		return "SHA3-384"
	case "SHA3-512":
		return "SHA3-512"
	case "BLAKE2B-256":
		return "BLAKE2b-256"
	case "BLAKE2B-384":
		return "BLAKE2b-384"
	case "BLAKE2B-512":
		return "BLAKE2b-512"
	default:
		return ""
	}
}

// SaveSBOM parses SBOM JSON and saves it to the database with all packages
// Uses typed structs for robust parsing with compile-time safety
func (r *SBOMRepository) SaveSBOM(ctx context.Context, sbomJSON string, sourcePath string) (uuid.UUID, error) {
	// Determine SBOM format by attempting to parse with typed structs
	var format string
	var formatVersion string
	var documentNamespace string
	var name string
	var version string
	var packages []models.Package
	var hashes []models.PackageHash
	var rawData interface{}
	var generatedAt *time.Time

	// Try SPDX format first
	var spdxDoc SPDXDocument
	if err := json.Unmarshal([]byte(sbomJSON), &spdxDoc); err == nil && spdxDoc.SPDXVersion != "" {
		format = "SPDX"
		formatVersion = strings.TrimPrefix(spdxDoc.SPDXVersion, "SPDX-")
		documentNamespace = spdxDoc.DocumentNamespace
		name = spdxDoc.Name

		// Extract component version from the first package entry
		if len(spdxDoc.Packages) > 0 {
			version = spdxDoc.Packages[0].VersionInfo
		}

		// Extract generation timestamp from creationInfo.created
		if spdxDoc.CreationInfo != nil && spdxDoc.CreationInfo.Created != "" {
			if t, err := time.Parse(time.RFC3339, spdxDoc.CreationInfo.Created); err == nil {
				generatedAt = &t
			} else {
				log.Printf("warning: failed to parse SPDX creationInfo.created %q: %v", spdxDoc.CreationInfo.Created, err)
			}
		}

		rawData = spdxDoc
	} else {
		// Try CycloneDX format
		var cdxDoc CycloneDXDocument
		if err := json.Unmarshal([]byte(sbomJSON), &cdxDoc); err == nil && cdxDoc.BomFormat == "CycloneDX" {
			format = "CycloneDX"
			formatVersion = cdxDoc.SpecVersion
			documentNamespace = cdxDoc.SerialNumber

			if cdxDoc.Metadata != nil && cdxDoc.Metadata.Component != nil {
				name = cdxDoc.Metadata.Component.Name
				version = cdxDoc.Metadata.Component.Version
			} else {
				name = "Unknown"
				version = "1.0"
			}

			// Extract generation timestamp from metadata.timestamp
			if cdxDoc.Metadata != nil && cdxDoc.Metadata.Timestamp != "" {
				if t, err := time.Parse(time.RFC3339, cdxDoc.Metadata.Timestamp); err == nil {
					generatedAt = &t
				} else {
					log.Printf("warning: failed to parse CycloneDX metadata.timestamp %q: %v", cdxDoc.Metadata.Timestamp, err)
				}
			}

			rawData = cdxDoc
		} else {
			return uuid.Nil, fmt.Errorf("failed to parse SBOM: unsupported or malformed format (not valid SPDX or CycloneDX)")
		}
	}

	// If namespace is still empty, generate one
	if documentNamespace == "" {
		documentNamespace = fmt.Sprintf("https://transparenz.local/sbom/%s", uuid.New().String())
	}

	// Create SBOM model - store the raw typed data as JSONB
	var sbomJSONB models.JSONB
	if jsonBytes, err := json.Marshal(rawData); err == nil {
		var dataMap map[string]interface{}
		if err := json.Unmarshal(jsonBytes, &dataMap); err == nil {
			sbomJSONB = models.JSONB(dataMap)
		}
	}

	sbom := models.SBOM{
		Name:              name,
		Version:           version,
		Format:            format,
		FormatVersion:     formatVersion,
		DocumentNamespace: documentNamespace,
		SourcePath:        &sourcePath,
		SBOMJson:          sbomJSONB,
		GeneratedAt:       generatedAt,
	}

	// Begin transaction
	err := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// Save SBOM
		if err := tx.Create(&sbom).Error; err != nil {
			return fmt.Errorf("failed to save SBOM: %w", err)
		}

		// Extract packages and hashes using typed structs
		var extractErr error
		if format == "SPDX" {
			packages, hashes, extractErr = r.extractSPDXPackages(rawData.(SPDXDocument), sbom.ID)
		} else {
			packages, hashes, extractErr = r.extractCycloneDXPackages(rawData.(CycloneDXDocument), sbom.ID)
		}

		if extractErr != nil {
			return fmt.Errorf("failed to extract packages: %w", extractErr)
		}

		if len(packages) > 0 {
			if err := tx.Create(&packages).Error; err != nil {
				return fmt.Errorf("failed to save packages: %w", err)
			}
		}

		// Save package hashes now that packages have DB-assigned IDs.
		// The hashes slice was built with placeholder PackageId values (index-based);
		// reassign them from the saved package slice which now carries real UUIDs.
		if len(hashes) > 0 {
			if err := tx.Create(&hashes).Error; err != nil {
				return fmt.Errorf("failed to save package hashes: %w", err)
			}
		}

		return nil
	})

	if err != nil {
		return uuid.Nil, err
	}

	return sbom.ID, nil
}

// extractSPDXPackages extracts package information and checksums from a typed SPDX document.
// Returns the packages, their associated PackageHash records, and any error.
// PackageHash records reference the Package by index position; callers must ensure
// packages are saved (to populate IDs) before saving hashes.
func (r *SBOMRepository) extractSPDXPackages(doc SPDXDocument, sbomID uuid.UUID) ([]models.Package, []models.PackageHash, error) {
	packages := make([]models.Package, 0, len(doc.Packages))
	var hashes []models.PackageHash

	for _, spdxPkg := range doc.Packages {
		p := models.Package{
			SBOMId: sbomID,
			Name:   spdxPkg.Name,
		}

		if spdxPkg.VersionInfo != "" {
			p.Version = &spdxPkg.VersionInfo
		}

		// Extract PURL from externalRefs
		for _, extRef := range spdxPkg.ExternalRefs {
			if extRef.ReferenceType == "purl" {
				p.PURL = &extRef.ReferenceLocator
			} else if extRef.ReferenceCategory == "SECURITY" && extRef.ReferenceType == "cpe23Type" {
				p.CPE = &extRef.ReferenceLocator
			}
		}

		// Use licenseConcluded, falling back to licenseDeclared if absent or non-informative
		license := spdxPkg.LicenseConcluded
		if license == "" || license == "NOASSERTION" || license == "NONE" {
			license = spdxPkg.LicenseDeclared
		}
		if license == "NOASSERTION" || license == "NONE" {
			license = ""
		}
		if license != "" {
			p.License = &license
		}

		// Use supplier, falling back to originator if absent or non-informative
		supplier := spdxPkg.Supplier
		if supplier == "" || supplier == "NOASSERTION" {
			supplier = spdxPkg.Originator
		}
		if supplier == "NOASSERTION" {
			supplier = ""
		}
		if supplier != "" {
			p.Supplier = &supplier
		}

		if spdxPkg.DownloadLocation != "" && spdxPkg.DownloadLocation != "NOASSERTION" {
			p.DownloadLocation = &spdxPkg.DownloadLocation
		}

		if spdxPkg.Description != "" {
			p.Description = &spdxPkg.Description
		}

		// Assign a UUID now so hashes can reference it before DB insert
		if p.ID == uuid.Nil {
			p.ID = uuid.New()
		}

		// Build PackageHash records for each checksum
		for _, cs := range spdxPkg.Checksums {
			normalized := normalizeHashAlgorithm(cs.Algorithm)
			if normalized == "" || cs.ChecksumValue == "" {
				continue
			}
			hashes = append(hashes, models.PackageHash{
				PackageId: p.ID,
				Algorithm: normalized,
				HashValue: cs.ChecksumValue,
			})
		}

		packages = append(packages, p)
	}

	return packages, hashes, nil
}

// extractCycloneDXPackages extracts package information and hashes from a typed CycloneDX document.
// Returns the packages, their associated PackageHash records, and any error.
// PackageHash records reference the Package by UUID assigned here; callers must ensure
// packages are saved (to populate IDs) before saving hashes.
func (r *SBOMRepository) extractCycloneDXPackages(doc CycloneDXDocument, sbomID uuid.UUID) ([]models.Package, []models.PackageHash, error) {
	packages := make([]models.Package, 0, len(doc.Components))
	var hashes []models.PackageHash

	for _, comp := range doc.Components {
		p := models.Package{
			SBOMId: sbomID,
			Name:   comp.Name,
		}

		if comp.Version != "" {
			p.Version = &comp.Version
		}

		if comp.Purl != "" {
			p.PURL = &comp.Purl
		}

		if comp.CPE != "" {
			p.CPE = &comp.CPE
		}

		// Extract first license
		if len(comp.Licenses) > 0 {
			licenseID := comp.Licenses[0].License.ID
			if licenseID == "" {
				licenseID = comp.Licenses[0].License.Name
			}
			if licenseID != "" {
				p.License = &licenseID
			}
		}

		if comp.Supplier != nil && comp.Supplier.Name != "" {
			p.Supplier = &comp.Supplier.Name
		}

		if comp.Description != "" {
			p.Description = &comp.Description
		}

		// Assign a UUID now so hashes can reference it before DB insert
		if p.ID == uuid.Nil {
			p.ID = uuid.New()
		}

		// Build PackageHash records for each hash entry
		for _, h := range comp.Hashes {
			normalized := normalizeHashAlgorithm(h.Alg)
			if normalized == "" || h.Content == "" {
				continue
			}
			hashes = append(hashes, models.PackageHash{
				PackageId: p.ID,
				Algorithm: normalized,
				HashValue: h.Content,
			})
		}

		packages = append(packages, p)
	}

	return packages, hashes, nil
}

// GetSBOMByNamespace retrieves an SBOM by its document namespace
func (r *SBOMRepository) GetSBOMByNamespace(namespace string) (*models.SBOM, error) {
	var sbom models.SBOM
	err := r.db.Where("document_namespace = ?", namespace).First(&sbom).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrSBOMNotFound
		}
		return nil, fmt.Errorf("failed to get SBOM by namespace: %w", err)
	}
	return &sbom, nil
}

// GetSBOM retrieves an SBOM by ID with all related packages
func (r *SBOMRepository) GetSBOM(ctx context.Context, id uuid.UUID) (*models.SBOM, error) {
	var sbom models.SBOM
	err := r.db.WithContext(ctx).
		Preload("Packages").
		Preload("Scans").
		First(&sbom, "id = ?", id).Error

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrSBOMNotFound
		}
		return nil, fmt.Errorf("failed to get SBOM: %w", err)
	}

	return &sbom, nil
}

// ListSBOMs retrieves a list of SBOMs with pagination
func (r *SBOMRepository) ListSBOMs(ctx context.Context, limit, offset int) ([]models.SBOM, error) {
	var sboms []models.SBOM
	err := r.db.WithContext(ctx).
		Preload("Packages").
		Order("created_at DESC").
		Limit(limit).
		Offset(offset).
		Find(&sboms).Error

	if err != nil {
		return nil, fmt.Errorf("failed to list SBOMs: %w", err)
	}

	return sboms, nil
}

// DeleteSBOM deletes an SBOM and all related data
func (r *SBOMRepository) DeleteSBOM(ctx context.Context, id uuid.UUID) error {
	result := r.db.WithContext(ctx).Delete(&models.SBOM{}, "id = ?", id)
	if result.Error != nil {
		return fmt.Errorf("failed to delete SBOM: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return ErrSBOMNotFound
	}
	return nil
}

// SaveScanResults saves vulnerability scan results for an SBOM using typed structs
// Uses GrypeScanResult for compile-time safety per BSI TR-03183 validation requirements
func (r *SBOMRepository) SaveScanResults(ctx context.Context, sbomID uuid.UUID, scanJSON string) (uuid.UUID, error) {
	var scanData GrypeScanResult
	if err := json.Unmarshal([]byte(scanJSON), &scanData); err != nil {
		return uuid.Nil, fmt.Errorf("failed to parse Grype scan JSON: %w", err)
	}

	// Extract scan metadata with typed access
	scan := models.Scan{
		SBOMId:      sbomID,
		ToolName:    "grype", // Default tool name
		ToolVersion: "unknown",
	}

	// Extract tool version from descriptor if available
	if scanData.Descriptor != nil {
		scan.ToolName = scanData.Descriptor.Name
		scan.ToolVersion = scanData.Descriptor.Version
	}

	// Count total vulnerabilities and severity levels using typed structs
	scan.TotalVulnerabilities = len(scanData.Matches)

	for _, match := range scanData.Matches {
		switch strings.ToUpper(match.Vulnerability.Severity) {
		case "CRITICAL":
			scan.CriticalCount++
		case "HIGH":
			scan.HighCount++
		case "MEDIUM":
			scan.MediumCount++
		case "LOW":
			scan.LowCount++
		}
	}

	// Store the typed scan data as JSONB
	var scanJSONB models.JSONB
	if jsonBytes, err := json.Marshal(scanData); err == nil {
		var dataMap map[string]interface{}
		if err := json.Unmarshal(jsonBytes, &dataMap); err == nil {
			scanJSONB = models.JSONB(dataMap)
		}
	}
	scan.ScanMetadata = scanJSONB

	if err := r.db.WithContext(ctx).Create(&scan).Error; err != nil {
		return uuid.Nil, fmt.Errorf("failed to save scan results: %w", err)
	}

	return scan.ID, nil
}

// GetVulnerabilities retrieves vulnerabilities for an SBOM, optionally filtered by severity
func (r *SBOMRepository) GetVulnerabilities(ctx context.Context, sbomID uuid.UUID, severity string) ([]models.Vulnerability, error) {
	var vulnerabilities []models.Vulnerability

	query := r.db.WithContext(ctx).
		Joins("JOIN package_vulnerabilities ON package_vulnerabilities.vulnerability_id = vulnerabilities.id").
		Joins("JOIN packages ON packages.id = package_vulnerabilities.package_id").
		Where("packages.sbom_id = ?", sbomID)

	if severity != "" {
		query = query.Where("vulnerabilities.severity = ?", strings.ToUpper(severity))
	}

	err := query.Distinct().Find(&vulnerabilities).Error
	if err != nil {
		return nil, fmt.Errorf("failed to get vulnerabilities: %w", err)
	}

	return vulnerabilities, nil
}

// UpdateBSICompliance updates the BSI compliance status and score for an SBOM
func (r *SBOMRepository) UpdateBSICompliance(id uuid.UUID, compliant bool, score float64) error {
	now := time.Now()
	return r.db.Model(&models.SBOM{}).Where("id = ?", id).Updates(map[string]interface{}{
		"bsi_compliant":  compliant,
		"bsi_score":      score,
		"bsi_checked_at": now,
	}).Error
}

// GetSBOMJSON retrieves just the raw SBOM JSON for a given ID (no associations loaded).
func (r *SBOMRepository) GetSBOMJSON(id uuid.UUID) (string, error) {
	var sbom models.SBOM
	if err := r.db.Select("sbom_json").First(&sbom, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return "", ErrSBOMNotFound
		}
		return "", fmt.Errorf("failed to get SBOM JSON: %w", err)
	}
	jsonBytes, err := json.Marshal(sbom.SBOMJson)
	if err != nil {
		return "", fmt.Errorf("failed to marshal SBOM JSON: %w", err)
	}
	return string(jsonBytes), nil
}

// GetSBOMByPrefix finds a single SBOM matching an ID prefix (first 8+ chars of UUID).
// Returns error if ambiguous (multiple matches) or not found.
func (r *SBOMRepository) GetSBOMByPrefix(prefix string) (*models.SBOM, error) {
	var sboms []models.SBOM
	if err := r.db.Where("CAST(id AS TEXT) LIKE ?", prefix+"%").Limit(2).Find(&sboms).Error; err != nil {
		return nil, fmt.Errorf("failed to search by prefix: %w", err)
	}
	if len(sboms) == 0 {
		return nil, fmt.Errorf("no SBOM found with ID prefix %q", prefix)
	}
	if len(sboms) > 1 {
		return nil, fmt.Errorf("ambiguous ID prefix %q matches multiple SBOMs", prefix)
	}
	return &sboms[0], nil
}

// SearchByPackage searches for packages by name across all SBOMs
func (r *SBOMRepository) SearchByPackage(ctx context.Context, packageName string) ([]models.Package, error) {
	var packages []models.Package
	err := r.db.WithContext(ctx).
		Preload("SBOM").
		Where("name ILIKE ?", "%"+packageName+"%").
		Find(&packages).Error

	if err != nil {
		return nil, fmt.Errorf("failed to search packages: %w", err)
	}

	return packages, nil
}
