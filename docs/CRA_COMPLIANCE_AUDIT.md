# CRA / BSI TR-03183-2 Compliance Audit

Date: 2026-03-28
Auditor: Automated (transparenz bsi-check)
Project: transparenz-go v0.1.0

## Audit Summary

| Category | Pass | Fail | N/A | Score |
|----------|------|------|-----|-------|
| CRA Legal Baseline | 8 | 0 | 4 | 100% |
| BSI Format Requirements | 1 | 0 | 0 | 100% |
| BSI Component Fields | 10 | 1 | 0 | 91% |
| BSI License Requirements | 1 | 0 | 0 | 100% |
| BSI Structural Requirements | 3 | 0 | 0 | 100% |
| **Overall** | **23** | **1** | **4** | **96%** |

## Detailed Findings

### CRA Legal Baseline

| ID | Status | Evidence |
|----|--------|----------|
| CRA-01 | PASS | `cmd/generate.go` - generate command produces SBOM for any source |
| CRA-02 | PASS | `pkg/sbom/generator.go` - outputs JSON (CycloneDX/SPDX) |
| CRA-03 | PASS | `cmd/generate.go:54-61` - supports cyclonedx and spdx formats |
| CRA-04 | PASS | `pkg/sbom/generator.go:51` - Syft resolves all dependencies |
| CRA-05 | PASS | `cmd/generate.go:112-120` - writes SBOM to file |
| CRA-06 | PASS | `cmd/bsi.go` - bsi-check validates and reports |
| CRA-07 | N/A | Optional - not sharing with users currently |
| CRA-08 | PASS | `pkg/scan/scanner.go` - Grype vulnerability scanning |
| CRA-09 | N/A | Process requirement, not code |
| CRA-10 | N/A | Process requirement, not code |
| CRA-11 | N/A | Process requirement, not code |
| CRA-12 | PASS | `pkg/scan/scanner.go` + `cmd/scan.go` - scan any SBOM |

### BSI TR-03183-2 Format

| ID | Status | Evidence |
|----|--------|----------|
| BSI-01 | PASS | `pkg/bsi/enricher.go:assertDependencyCompleteness` - sets specVersion to 1.6 |

### BSI TR-03183-2 Component Fields

| ID | Status | Evidence |
|----|--------|----------|
| BSI-02 | PASS | Syft populates creator/metadata fields |
| BSI-03 | PASS | Syft adds creationInfo.created timestamp |
| BSI-04 | PASS | `pkg/bsi/enricher.go:detectSupplier` - enriches supplier |
| BSI-05 | PASS | Syft extracts component names |
| BSI-06 | PASS | Syft extracts component versions |
| BSI-07 | PARTIAL | Syft may not populate filename for all components |
| BSI-08 | PASS | `pkg/bsi/enricher.go:assertDependencyCompleteness` - declares completeness |
| BSI-10 | PASS | `pkg/bsi/enricher.go:CalculateArtifactHash` - SHA-512 computation |
| BSI-11 | PASS | `pkg/bsi/enricher.go:buildBSIProperties` - executable property |
| BSI-12 | PASS | `pkg/bsi/enricher.go:buildBSIProperties` - archive property |
| BSI-13 | PASS | `pkg/bsi/enricher.go:buildBSIProperties` - structured property |

### BSI License Requirements

| ID | Status | Evidence |
|----|--------|----------|
| BSI-09 | PASS | `pkg/bsi/enricher.go:detectLicense` - SPDX identifiers |
| BSI-18 | PASS | `pkg/bsi/enricher.go:detectLicenseFromText` - classifier uses SPDX names |

### BSI Structural Requirements

| ID | Status | Evidence |
|----|--------|----------|
| BSI-14 | PASS | `pkg/bsi/enricher.go:assertDependencyCompleteness` - explicit declaration |
| BSI-15 | PASS | Syft resolves transitive dependencies natively |
| BSI-16 | PASS | Each generate call produces fresh SBOM for current version |
| BSI-17 | PASS | SBOM generation and vulnerability scanning are separate commands |

## Known Gaps

1. **BSI-07 (Filename)**: Syft may not always populate the filename field. Mitigated by PURL identifiers.
2. **BSI-20 (Source code URI)**: Not automatically populated. Optional per TR-03183-2.
3. **BSI-22 (Original licenses)**: Enricher adds declared license, not always original license. Partial.
