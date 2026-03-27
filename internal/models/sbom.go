package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// SBOM represents an SBOM metadata record and complete JSON document.
// Stores both SPDX 2.3 and CycloneDX format SBOMs with complete
// JSON documents for full-text search and normalized metadata.
type SBOM struct {
	ID                uuid.UUID      `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	Name              string         `gorm:"size:255;not null;index" json:"name"`
	Version           string         `gorm:"size:50;not null" json:"version"`
	Format            string         `gorm:"size:20;not null;index;check:format IN ('SPDX', 'CycloneDX')" json:"format"`
	FormatVersion     string         `gorm:"size:20;not null" json:"format_version"`
	DocumentNamespace string         `gorm:"type:text;not null;unique" json:"document_namespace"`
	SourcePath        *string        `gorm:"type:text" json:"source_path,omitempty"`
	SBOMJson          JSONB          `gorm:"type:jsonb;not null" json:"sbom_json"`
	CreatedAt         time.Time      `gorm:"not null;default:now();index:idx_sboms_created_at" json:"created_at"`
	UpdatedAt         time.Time      `gorm:"not null;default:now()" json:"updated_at"`
	DeletedAt         gorm.DeletedAt `gorm:"index" json:"-"`

	// Relationships
	Packages []Package `gorm:"foreignKey:SBOMId;constraint:OnDelete:CASCADE" json:"packages,omitempty"`
	Scans    []Scan    `gorm:"foreignKey:SBOMId;constraint:OnDelete:CASCADE" json:"scans,omitempty"`
}

// TableName specifies the table name for SBOM model
func (SBOM) TableName() string {
	return "sboms"
}

// BeforeCreate sets the UUID before creating the record if not already set
func (s *SBOM) BeforeCreate(tx *gorm.DB) error {
	if s.ID == uuid.Nil {
		s.ID = uuid.New()
	}
	return nil
}
