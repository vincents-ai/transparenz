// SPDX-License-Identifier: AGPL-3.0-or-later OR Commercial
// Copyright (c) 2026 Vincent Palmer

package repository

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/deutschland-stack/transparenz/internal/models"
)

// SBOMRepository handles database operations for SBOMs
type SBOMRepository struct {
	db *gorm.DB
}

// NewSBOMRepository creates a new SBOM repository
func NewSBOMRepository(db *gorm.DB) *SBOMRepository {
	return &SBOMRepository{db: db}
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
	var rawData interface{}

	// Try SPDX format first
	var spdxDoc SPDXDocument
	if err := json.Unmarshal([]byte(sbomJSON), &spdxDoc); err == nil && spdxDoc.SPDXVersion != "" {
		format = "SPDX"
		formatVersion = strings.TrimPrefix(spdxDoc.SPDXVersion, "SPDX-")
		documentNamespace = spdxDoc.DocumentNamespace
		name = spdxDoc.Name

		// Extract version from documentDescribes if available
		if len(spdxDoc.DocumentDescribes) > 0 {
			version = spdxDoc.DocumentDescribes[0]
		} else {
			version = "1.0"
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
	}

	// Begin transaction
	err := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// Save SBOM
		if err := tx.Create(&sbom).Error; err != nil {
			return fmt.Errorf("failed to save SBOM: %w", err)
		}

		// Extract packages using typed structs
		var extractErr error
		if format == "SPDX" {
			packages, extractErr = r.extractSPDXPackages(rawData.(SPDXDocument), sbom.ID)
		} else {
			packages, extractErr = r.extractCycloneDXPackages(rawData.(CycloneDXDocument), sbom.ID)
		}

		if extractErr != nil {
			return fmt.Errorf("failed to extract packages: %w", extractErr)
		}

		if len(packages) > 0 {
			if err := tx.Create(&packages).Error; err != nil {
				return fmt.Errorf("failed to save packages: %w", err)
			}
		}

		return nil
	})

	if err != nil {
		return uuid.Nil, err
	}

	return sbom.ID, nil
}

// extractSPDXPackages extracts package information from typed SPDX document
func (r *SBOMRepository) extractSPDXPackages(doc SPDXDocument, sbomID uuid.UUID) ([]models.Package, error) {
	packages := make([]models.Package, 0, len(doc.Packages))

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

		if spdxPkg.LicenseConcluded != "" && spdxPkg.LicenseConcluded != "NOASSERTION" {
			p.License = &spdxPkg.LicenseConcluded
		}

		if spdxPkg.Supplier != "" && spdxPkg.Supplier != "NOASSERTION" {
			p.Supplier = &spdxPkg.Supplier
		}

		if spdxPkg.DownloadLocation != "" && spdxPkg.DownloadLocation != "NOASSERTION" {
			p.DownloadLocation = &spdxPkg.DownloadLocation
		}

		if spdxPkg.Description != "" {
			p.Description = &spdxPkg.Description
		}

		packages = append(packages, p)
	}

	return packages, nil
}

// extractCycloneDXPackages extracts package information from typed CycloneDX document
func (r *SBOMRepository) extractCycloneDXPackages(doc CycloneDXDocument, sbomID uuid.UUID) ([]models.Package, error) {
	packages := make([]models.Package, 0, len(doc.Components))

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

		packages = append(packages, p)
	}

	return packages, nil
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

// SaveScanResults saves vulnerability scan results for an SBOM
func (r *SBOMRepository) SaveScanResults(ctx context.Context, sbomID uuid.UUID, scanJSON string) (uuid.UUID, error) {
	var scanData map[string]interface{}
	if err := json.Unmarshal([]byte(scanJSON), &scanData); err != nil {
		return uuid.Nil, fmt.Errorf("failed to parse scan JSON: %w", err)
	}

	// Extract scan metadata
	scan := models.Scan{
		SBOMId:      sbomID,
		ToolName:    "grype", // Default tool name
		ToolVersion: "unknown",
	}

	// Parse scan results
	if matches, ok := scanData["matches"].([]interface{}); ok {
		scan.TotalVulnerabilities = len(matches)

		// Count by severity
		for _, match := range matches {
			if m, ok := match.(map[string]interface{}); ok {
				if vuln, ok := m["vulnerability"].(map[string]interface{}); ok {
					if severity, ok := vuln["severity"].(string); ok {
						switch strings.ToUpper(severity) {
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
				}
			}
		}
	}

	scan.ScanMetadata = models.JSONB(scanData)

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
