package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// PackageHash represents a cryptographic hash for a package.
// Stores cryptographic hashes for packages to ensure integrity,
// as required by BSI TR-03183. Supports multiple hash algorithms.
type PackageHash struct {
	ID        uuid.UUID      `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	PackageId uuid.UUID      `gorm:"type:uuid;not null;index:idx_package_hashes_package_id" json:"package_id"`
	Algorithm string         `gorm:"size:20;not null;index;check:algorithm IN ('SHA1', 'SHA256', 'SHA384', 'SHA512', 'MD5', 'SHA3-256', 'SHA3-384', 'SHA3-512', 'BLAKE2b-256', 'BLAKE2b-384', 'BLAKE2b-512')" json:"algorithm"`
	HashValue string         `gorm:"size:255;not null;index" json:"hash_value"`
	CreatedAt time.Time      `gorm:"not null;default:now()" json:"created_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`

	// Relationships
	Package Package `gorm:"foreignKey:PackageId" json:"-"`
}

// TableName specifies the table name for PackageHash model
func (PackageHash) TableName() string {
	return "package_hashes"
}

// BeforeCreate sets the UUID before creating the record if not already set
func (ph *PackageHash) BeforeCreate(tx *gorm.DB) error {
	if ph.ID == uuid.Nil {
		ph.ID = uuid.New()
	}
	return nil
}
