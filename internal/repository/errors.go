package repository

import "errors"

var (
	// ErrSBOMNotFound is returned when an SBOM is not found in the database
	ErrSBOMNotFound = errors.New("SBOM not found")

	// ErrScanNotFound is returned when a scan is not found in the database
	ErrScanNotFound = errors.New("scan not found")

	// ErrVulnerabilityNotFound is returned when a vulnerability is not found
	ErrVulnerabilityNotFound = errors.New("vulnerability not found")

	// ErrPackageNotFound is returned when a package is not found
	ErrPackageNotFound = errors.New("package not found")

	// ErrInvalidInput is returned when input validation fails
	ErrInvalidInput = errors.New("invalid input")

	// ErrDuplicateEntry is returned when attempting to create a duplicate entry
	ErrDuplicateEntry = errors.New("duplicate entry")
)
