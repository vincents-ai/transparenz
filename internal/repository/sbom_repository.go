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
func (r *SBOMRepository) SaveSBOM(ctx context.Context, sbomJSON string, sourcePath string) (uuid.UUID, error) {
	// Parse SBOM JSON
	var sbomData map[string]interface{}
	if err := json.Unmarshal([]byte(sbomJSON), &sbomData); err != nil {
		return uuid.Nil, fmt.Errorf("failed to parse SBOM JSON: %w", err)
	}

	// Determine SBOM format (SPDX or CycloneDX)
	format := "SPDX"
	formatVersion := "2.3"
	documentNamespace := ""
	name := "Unknown"
	version := "1.0"

	// Check for SPDX fields
	if spdxVersion, ok := sbomData["spdxVersion"].(string); ok {
		format = "SPDX"
		formatVersion = strings.TrimPrefix(spdxVersion, "SPDX-")
		if ns, ok := sbomData["documentNamespace"].(string); ok {
			documentNamespace = ns
		}
		if n, ok := sbomData["name"].(string); ok {
			name = n
		}
		if v, ok := sbomData["documentDescribes"].([]interface{}); ok && len(v) > 0 {
			if pkgRef, ok := v[0].(string); ok {
				version = pkgRef
			}
		}
	} else if bomFormat, ok := sbomData["bomFormat"].(string); ok && bomFormat == "CycloneDX" {
		format = "CycloneDX"
		if specVersion, ok := sbomData["specVersion"].(string); ok {
			formatVersion = specVersion
		}
		if serialNumber, ok := sbomData["serialNumber"].(string); ok {
			documentNamespace = serialNumber
		}
		if metadata, ok := sbomData["metadata"].(map[string]interface{}); ok {
			if component, ok := metadata["component"].(map[string]interface{}); ok {
				if n, ok := component["name"].(string); ok {
					name = n
				}
				if v, ok := component["version"].(string); ok {
					version = v
				}
			}
		}
	}

	// If namespace is still empty, generate one
	if documentNamespace == "" {
		documentNamespace = fmt.Sprintf("https://transparenz.local/sbom/%s", uuid.New().String())
	}

	// Create SBOM model
	sbom := models.SBOM{
		Name:              name,
		Version:           version,
		Format:            format,
		FormatVersion:     formatVersion,
		DocumentNamespace: documentNamespace,
		SourcePath:        &sourcePath,
		SBOMJson:          models.JSONB(sbomData),
	}

	// Begin transaction
	err := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// Save SBOM
		if err := tx.Create(&sbom).Error; err != nil {
			return fmt.Errorf("failed to save SBOM: %w", err)
		}

		// Parse and save packages
		packages, err := r.extractPackages(sbomData, sbom.ID, format)
		if err != nil {
			return fmt.Errorf("failed to extract packages: %w", err)
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

// extractPackages extracts package information from SBOM JSON
func (r *SBOMRepository) extractPackages(sbomData map[string]interface{}, sbomID uuid.UUID, format string) ([]models.Package, error) {
	var packages []models.Package

	if format == "SPDX" {
		if pkgsData, ok := sbomData["packages"].([]interface{}); ok {
			for _, pkgData := range pkgsData {
				if pkg, ok := pkgData.(map[string]interface{}); ok {
					p := models.Package{
						SBOMId: sbomID,
						Name:   getStringValue(pkg, "name"),
					}

					if v := getStringValue(pkg, "versionInfo"); v != "" {
						p.Version = &v
					}
					if purl := getStringValue(pkg, "externalRefs", "PACKAGE-MANAGER", "purl"); purl != "" {
						p.PURL = &purl
					}
					if cpe := getStringValue(pkg, "externalRefs", "SECURITY", "cpe"); cpe != "" {
						p.CPE = &cpe
					}
					if license := getStringValue(pkg, "licenseConcluded"); license != "" {
						p.License = &license
					}
					if supplier := getStringValue(pkg, "supplier"); supplier != "" {
						p.Supplier = &supplier
					}
					if dl := getStringValue(pkg, "downloadLocation"); dl != "" && dl != "NOASSERTION" {
						p.DownloadLocation = &dl
					}
					if desc := getStringValue(pkg, "description"); desc != "" {
						p.Description = &desc
					}

					packages = append(packages, p)
				}
			}
		}
	} else if format == "CycloneDX" {
		if compsData, ok := sbomData["components"].([]interface{}); ok {
			for _, compData := range compsData {
				if comp, ok := compData.(map[string]interface{}); ok {
					p := models.Package{
						SBOMId: sbomID,
						Name:   getStringValue(comp, "name"),
					}

					if v := getStringValue(comp, "version"); v != "" {
						p.Version = &v
					}
					if purl := getStringValue(comp, "purl"); purl != "" {
						p.PURL = &purl
					}
					if cpe := getStringValue(comp, "cpe"); cpe != "" {
						p.CPE = &cpe
					}
					if licenses, ok := comp["licenses"].([]interface{}); ok && len(licenses) > 0 {
						if lic, ok := licenses[0].(map[string]interface{}); ok {
							if id := getStringValue(lic, "license", "id"); id != "" {
								p.License = &id
							}
						}
					}
					if desc := getStringValue(comp, "description"); desc != "" {
						p.Description = &desc
					}

					packages = append(packages, p)
				}
			}
		}
	}

	return packages, nil
}

// getStringValue is a helper to safely extract string values from nested maps
func getStringValue(data map[string]interface{}, keys ...string) string {
	current := data
	for i, key := range keys {
		if i == len(keys)-1 {
			if val, ok := current[key].(string); ok {
				return val
			}
			return ""
		}
		if next, ok := current[key].(map[string]interface{}); ok {
			current = next
		} else if next, ok := current[key].([]interface{}); ok {
			// Handle array case for externalRefs
			for _, item := range next {
				if itemMap, ok := item.(map[string]interface{}); ok {
					if refType, ok := itemMap["referenceType"].(string); ok && refType == keys[i+1] {
						if val, ok := itemMap["referenceLocator"].(string); ok {
							return val
						}
					}
				}
			}
			return ""
		} else {
			return ""
		}
	}
	return ""
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
