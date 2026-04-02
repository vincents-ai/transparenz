# BSI TR-03183-2 Compliance Test Coverage

**Generated:** 2026-03-28  
**Project:** transparenz-go (BSI TR-03183-2 Compliant SBOM Generator)  
**Source:** https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TR03183/BSI-TR-03183-2.pdf

---

## BSI TR-03183-2 Requirements Mapping

| Section | Requirement | Feature File | Test Scenarios | Status |
|---------|-------------|--------------|----------------|--------|
| **4.2** | SBOM Format (CycloneDX 1.6+/SPDX 2.3+) | BSI_TR03183_01 | 4 | ✅ Implemented |
| **4.3** | Document Metadata (timestamp, tools) | BSI_TR03183_02 | 4 | ✅ Implemented |
| **4.4** | Primary Component (name, version, type, supplier) | BSI_TR03183_03 | 4 | ✅ Implemented |
| **8.1.1-8.1.5** | Component Fields (name, version, purl, type, supplier) | BSI_TR03183_04 | 5 | ✅ Implemented |
| **8.1.6** | License Identifiers (SPDX format) | BSI_TR03183_05 | 4 | ✅ Implemented |
| **8.1.7** | Cryptographic Hashes (SHA-512 mandatory) | BSI_TR03183_06 | 4 | ✅ Implemented |
| **8.1.8** | Component Properties (executable, archive, structured) | BSI_TR03183_07 | 4 | ✅ Implemented |
| **8.1.9** | Filename | BSI_TR03183_04 | Included | ✅ Implemented |
| **8.1.10** | Dependency Relationships | BSI_TR03183_08 | 4 | ✅ Implemented |
| **9.0** | SBOM Delivery and Updates | BSI_TR03183_10 | 3 | ✅ Implemented |

---

## Feature Files Summary

### BSI TR-03183-2 Specific Tests

| File | Scenarios | Description |
|------|-----------|-------------|
| `BSI_TR03183_01_format_compliance.feature` | 4 | CycloneDX/SPDX format validation |
| `BSI_TR03183_02_document_metadata.feature` | 4 | Timestamp, tools, spec version |
| `BSI_TR03183_03_primary_component.feature` | 4 | Product component requirements |
| `BSI_TR03183_04_component_fields.feature` | 5 | Name, version, purl, type, supplier |
| `BSI_TR03183_05_license_requirements.feature` | 4 | SPDX license identifiers |
| `BSI_TR03183_06_hash_requirements.feature` | 4 | SHA-256/SHA-512 hashes |
| `BSI_TR03183_07_component_properties.feature` | 4 | Executable, archive, structured |
| `BSI_TR03183_08_dependency_relationships.feature` | 4 | Dependency tree completeness |
| `BSI_TR03183_09_bsi_check_report.feature` | 4 | Compliance report validation |
| `BSI_TR03183_10_sbom_delivery.feature` | 3 | File export, versioning |

### Legacy CRA Tests (Enhanced)

| File | Scenarios | Description |
|------|-----------|-------------|
| `01_sbom_generation.feature` | 2 | Basic SBOM generation |
| `02_format_compliance.feature` | 2 | Format validation |
| `03_dependency_coverage.feature` | 2 | Dependency scanning |
| `04_format_version.feature` | 1 | Version checking |
| `05_dependency_completeness.feature` | 2 | Complete dependency tree |
| `06_license_coverage.feature` | 1 | License enrichment |
| `07_component_properties.feature` | 2 | Component metadata |
| `08_sha512_hashes.feature` | 1 | SHA-512 requirement |
| `09_no_vulns_in_sbom.feature` | 1 | VEX separation |
| `10_bsi_check_report.feature` | 2 | BSI compliance report |

---

## EU CRA Article Requirements

| Article | Requirement | Feature File | Status |
|---------|-------------|--------------|--------|
| Art. 10 | Security by design | 01_sbom_generation | ✅ |
| Art. 11(1) | 24h exploit reporting | 13_vulnerability_sla | ✅ (server) |
| Art. 11(7) | Component vulnerability reporting | transparenz-server | ✅ |
| Art. 12 | ENISA vulnerability database | vunnel-eu-cra | ✅ |

---

## Missing Requirements (TODO)

The following BSI TR-03183-2 requirements need implementation:

| Section | Requirement | Priority | Notes |
|---------|-------------|----------|-------|
| 8.1.11 | Scope of delivery (recursive deps) | High | Dependency depth implementation |
| Part 3 | CSAF 2.0 Advisory generation | High | In transparenz-server |
| Part 3 | VEX document generation | Medium | Vulnerability Exploitability eXchange |

---

## Running the Tests

```bash
# Run all BDD tests
cd transparenz-go
go test -v ./tests/...

# Run specific BSI TR-03183 tests
go test -v ./tests/... -run "BSI_TR03183"

# Run with coverage
go test -v -cover ./tests/...
```

---

## Compliance Checklist (BSI TR-03183-2)

```
TR-03183-2 COMPLIANCE CHECKLIST

FORMAT:
[✓] CycloneDX 1.6+ or SPDX 2.3+
[✓] Valid according to schema
[✓] Machine-readable

METADATA:
[✓] Document identifier/serialNumber
[✓] Creation timestamp
[✓] Tool information
[✓] Specification version

PRIMARY COMPONENT:
[✓] Product name
[✓] Product version
[✓] Supplier information
[✓] Unique identifier (purl)

COMPONENTS:
[✓] Name and version
[✓] Supplier information
[✓] Unique identifier (purl)
[✓] License information (SPDX)
[✓] Hash (SHA-512 mandatory; SHA-256 alone is non-compliant)
[✓] Component type
[ ] Filename (partially)
[✓] Properties (executable, archive, structured)

RELATIONSHIPS:
[✓] Dependency relationships defined
[✓] Complete dependency tree

QUALITY:
[✓] All direct dependencies included
[✓] Transitive dependencies included
[✓] Versions accurate and current
[✓] Identifiers valid

VULNERABILITY HANDLING:
[✓] SBOM vulnerability scanning
[✓] SLA tracking (transparenz-server)
[✓] ENISA submission (transparenz-server)
[ ] CSAF 2.0 advisories (planned)
[ ] VEX documents (planned)
```

---

## References

- BSI TR-03183-2: https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TR03183/BSI-TR-03183-2.pdf
- EU Cyber Resilience Act: https://digital-strategy.ec.europa.eu/en/policies/cra-reporting
- CycloneDX Specification: https://cyclonedx.org/specification/overview/
- SPDX Specification: https://spdx.github.io/spdx-spec/v2.3/
