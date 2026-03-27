package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Package represents a software package/component from an SBOM.
// Represents a single software package or component with BSI TR-03183
// required fields including license and supplier information.
type Package struct {
	ID               uuid.UUID      `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	SBOMId           uuid.UUID      `gorm:"type:uuid;not null;index:idx_packages_sbom_id" json:"sbom_id"`
	Name             string         `gorm:"size:255;not null;index:idx_packages_name_version" json:"name"`
	Version          *string        `gorm:"size:100;index:idx_packages_name_version" json:"version,omitempty"`
	PURL             *string        `gorm:"type:text;index:idx_packages_purl" json:"purl,omitempty"`
	CPE              *string        `gorm:"type:text" json:"cpe,omitempty"`
	License          *string        `gorm:"size:255" json:"license,omitempty"`
	Supplier         *string        `gorm:"size:255" json:"supplier,omitempty"`
	DownloadLocation *string        `gorm:"type:text" json:"download_location,omitempty"`
	Homepage         *string        `gorm:"type:text" json:"homepage,omitempty"`
	Description      *string        `gorm:"type:text" json:"description,omitempty"`
	CreatedAt        time.Time      `gorm:"not null;default:now()" json:"created_at"`
	UpdatedAt        time.Time      `gorm:"not null;default:now()" json:"updated_at"`
	DeletedAt        gorm.DeletedAt `gorm:"index" json:"-"`

	// Relationships
	SBOM                   SBOM                   `gorm:"foreignKey:SBOMId" json:"-"`
	Hashes                 []PackageHash          `gorm:"foreignKey:PackageId;constraint:OnDelete:CASCADE" json:"hashes,omitempty"`
	PackageVulnerabilities []PackageVulnerability `gorm:"foreignKey:PackageId;constraint:OnDelete:CASCADE" json:"package_vulnerabilities,omitempty"`
}

// TableName specifies the table name for Package model
func (Package) TableName() string {
	return "packages"
}

// BeforeCreate sets the UUID before creating the record if not already set
func (p *Package) BeforeCreate(tx *gorm.DB) error {
	if p.ID == uuid.Nil {
		p.ID = uuid.New()
	}
	return nil
}
