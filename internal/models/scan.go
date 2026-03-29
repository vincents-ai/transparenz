package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Scan represents vulnerability scan history.
// Records historical vulnerability scans performed on SBOMs,
// including scan metadata and summary statistics.
type Scan struct {
	ID                   uuid.UUID      `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	SBOMId               uuid.UUID      `gorm:"type:uuid;not null;index:idx_scans_sbom_id" json:"sbom_id"`
	ScanDate             time.Time      `gorm:"not null;default:now();index:idx_scans_scan_date" json:"scan_date"`
	ToolName             string         `gorm:"size:100;not null;index" json:"tool_name"`
	ToolVersion          string         `gorm:"size:50;not null" json:"tool_version"`
	TotalPackages        int            `gorm:"not null;default:0" json:"total_packages"`
	TotalVulnerabilities int            `gorm:"not null;default:0" json:"total_vulnerabilities"`
	CriticalCount        int            `gorm:"not null;default:0" json:"critical_count"`
	HighCount            int            `gorm:"not null;default:0" json:"high_count"`
	MediumCount          int            `gorm:"not null;default:0" json:"medium_count"`
	LowCount             int            `gorm:"not null;default:0" json:"low_count"`
	ScanDurationSeconds  *int           `gorm:"type:integer" json:"scan_duration_seconds,omitempty"`
	ScanMetadata         JSONB          `gorm:"type:jsonb" json:"scan_metadata,omitempty"`
	CreatedAt            time.Time      `gorm:"not null;default:now()" json:"created_at"`
	DeletedAt            gorm.DeletedAt `gorm:"index" json:"-"`

	// Relationships
	SBOM SBOM `gorm:"foreignKey:SBOMId" json:"-"`
}

// TableName specifies the table name for Scan model
func (Scan) TableName() string {
	return "scans"
}

// BeforeCreate sets the UUID before creating the record if not already set
func (s *Scan) BeforeCreate(tx *gorm.DB) error {
	if s.ID == uuid.Nil {
		s.ID = uuid.New()
	}
	return nil
}

func (s *Scan) HasVulnerabilities() bool {
	return s.TotalVulnerabilities > 0
}

func (s *Scan) GetTotalSeverityCount() int {
	return s.CriticalCount + s.HighCount + s.MediumCount + s.LowCount
}

func (s *Scan) HasCriticalVulnerabilities() bool {
	return s.CriticalCount > 0
}
