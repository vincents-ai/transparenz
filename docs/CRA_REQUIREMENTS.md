# EU Cyber Resilience Act (CRA) SBOM Requirements

Regulation (EU) 2024/2847 - Effective 11 December 2024, full enforcement 11 December 2027.

## Sources

- EU CRA Regulation 2024/2847 (EUR-Lex)
- BSI TR-03183-2 v2.1.0 (August 2025) - German Federal Office for Information Security
- CRA Evidence, Sbomify, Anchore, FOSSA compliance analysis

---

## Requirement Matrix

### CRA Legal Baseline (Regulation Text)

| ID | Requirement | CRA Reference | Status |
|----|-------------|---------------|--------|
| CRA-01 | SBOM is mandatory for all products with digital elements | Annex I, Part II(1) | Implemented |
| CRA-02 | SBOM must be machine-readable format (not PDF/spreadsheet) | Annex I, Part II(1) | Implemented |
| CRA-03 | SBOM must use commonly used format (CycloneDX or SPDX) | Annex I, Part II(1) | Implemented |
| CRA-04 | SBOM must cover at least top-level dependencies | Annex I, Part II(1) | Implemented |
| CRA-05 | SBOM must be included in technical documentation | Annex VII | Implemented |
| CRA-06 | SBOM must be producible to market surveillance authorities on request | Article 52 | Implemented |
| CRA-07 | If SBOM shared with users, must state where to access it | Annex II, Part I(9) | Optional |
| CRA-08 | Manufacturers must report actively exploited vulns within 24h | Article 14 | Partial (scan cmd) |
| CRA-09 | Support period minimum 5 years | Article 13(8) | N/A (process) |
| CRA-10 | Security updates available for 10 years or support period | Article 13(9) | N/A (process) |
| CRA-11 | Technical documentation retained 10 years minimum | Article 13(13) | N/A (process) |
| CRA-12 | Vulnerability handling throughout support period | Article 13(8) | Implemented |

### BSI TR-03183-2 Technical Requirements

| ID | Requirement | BSI Reference | Status |
|----|-------------|---------------|--------|
| BSI-01 | SBOM format: CycloneDX 1.6+ OR SPDX 2.3+ (JSON/XML) | Section 4 | Implemented |
| BSI-02 | SBOM Creator field (email or URL) | Section 5.2.1 | Implemented |
| BSI-03 | SBOM Timestamp (RFC 3339, UTC recommended) | Section 5.2.1 | Implemented |
| BSI-04 | Component Creator (email or URL per component) | Section 5.2.2 | Implemented |
| BSI-05 | Component Name | Section 5.2.2 | Implemented |
| BSI-06 | Component Version (SemVer/CalVer recommended) | Section 5.2.2 | Implemented |
| BSI-07 | Filename of component | Section 5.2.2 | Partial |
| BSI-08 | Dependencies enumerated with completeness indicated | Section 5.2.2 | Implemented |
| BSI-09 | Distribution Licenses (SPDX identifier/expression) | Section 6.1 | Implemented |
| BSI-10 | SHA-512 hash of deployable component | Section 5.2.2 | Implemented |
| BSI-11 | Executable property (true/false) | Section 5.2.2 | Implemented |
| BSI-12 | Archive property (true/false) | Section 5.2.2 | Implemented |
| BSI-13 | Structured property (true/false) | Section 5.2.2 | Implemented |
| BSI-14 | Dependency completeness MUST be clearly indicated | Section 5.2.2 | Implemented |
| BSI-15 | Recursive dependency resolution to first external component | Section 5.1 | Implemented |
| BSI-16 | Separate SBOM per software version | Section 3.1 | Implemented |
| BSI-17 | SBOMs MUST NOT contain vulnerability info | Section 3.1, 8.1.14 | Compliant |
| BSI-18 | SPDX license identifiers only (not license text) | Section 6.1 | Implemented |
| BSI-19 | Most recent TR-03183 version MUST be used | Section 7 | Compliant |
| BSI-20 | Conditional: Source code URI if available | Section 5.2.3 | Optional |
| BSI-21 | Conditional: Other unique IDs (CPE, PURL) | Section 5.2.4 | Implemented |
| BSI-22 | Conditional: Original licenses | Section 5.2.4 | Implemented |

---

## Detailed Requirement Descriptions

### CRA-01: Mandatory SBOM
All products with digital elements placed on the EU market must have an SBOM.
This is a legal requirement, not optional.

### CRA-02: Machine-Readable Format
The SBOM must be in a structured, machine-parseable format (JSON or XML).
PDFs, images, and spreadsheets do not satisfy this requirement.

### CRA-03: Commonly Used Format
CycloneDX (OWASP) and SPDX (Linux Foundation) are the accepted standards.
CycloneDX preferred for security use cases (native VEX support).

### CRA-04: Top-Level Dependencies Minimum
CRA requires "at least the top-level dependencies".
BSI TR-03183-2 goes further: recursive resolution to first external component.

### CRA-05: Technical Documentation
SBOM must be included in the product's technical file (Annex VII).
Must be available for conformity assessment.

### CRA-06: Authority Access
Market surveillance authorities can request the SBOM on reasoned request.
The SBOM must be retrievable and presentable.

### BSI-01: Format Versioning
- CycloneDX: version 1.6 or higher
- SPDX: version 2.3 or higher
- Only officially released versions are compliant

### BSI-08: Dependency Completeness
For each component, the enumeration of dependencies MUST clearly indicate
whether it is complete or incomplete. This is a mandatory field.

### BSI-10: SHA-512 Hash
BSI TR-03183-2 explicitly mandates SHA-512 checksums.
SHA-256 alone does NOT satisfy this requirement.
The hash must be of the deployed/deployable component.

### BSI-11-13: Component Properties
Each component MUST declare:
- executable: whether it contains executable code
- archive: whether it is a compressed archive
- structured: whether it has structured metadata

### BSI-14: Completeness Assertion
The SBOM must declare whether the dependency graph is complete.
This applies at both SBOM level and per-component level.

### BSI-17: No Vulnerability Info in SBOM
SBOM data is static (component inventory).
Vulnerability info is dynamic and must be communicated via CSAF or VEX.
Embedding vuln data in SBOMs is a compliance violation.

### BSI-18: SPDX License Identifiers
Licenses MUST be referenced by SPDX identifier or expression.
Raw license text is NOT acceptable as a substitute.
If no SPDX identifier exists, use `LicenseRef-scancode-[...]` or `LicenseRef-<entity>-[...]`.

---

## Compliance Deadlines

| Date | Milestone |
|------|-----------|
| 10 Dec 2024 | CRA enters into force |
| 11 Sep 2026 | Vulnerability reporting obligations (24h) |
| 11 Dec 2027 | Full enforcement - all CRA requirements |

## Penalties

- Fines up to EUR 15 million or 2.5% of global annual turnover
- Product recall or withdrawal from EU market
- Non-compliant products cannot carry CE marking
