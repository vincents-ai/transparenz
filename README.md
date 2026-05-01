# transparenz

A CLI tool for generating, enriching, validating, and submitting BSI TR-03183-2 compliant Software Bills of Materials (SBOMs).

## Features

- SBOM generation via the native Syft library (CycloneDX 1.6 JSON, SPDX 2.3 JSON)
- BSI TR-03183-2 enrichment: SHA-512 artifact hashes, supplier detection, license detection, component classification (executable/archive/structured), dependency completeness assertion
- SBOM compliance validation with weighted scoring (`bsi-check`)
- SBOM submission to a remote server endpoint with Bearer token authentication
- PostgreSQL-backed SBOM and vulnerability scan persistence
- Standalone vulnerability scanning via the native Grype library

## Requirements

- Go 1.25+
- PostgreSQL (for `--save` flag and `db` / `list` / `show` / `search` / `delete` commands)
- Grype vulnerability database (downloaded automatically on first `scan` run)

## Installation

```bash
# Install via go install
go install github.com/vincents-ai/transparenz@latest

# Or build from source
git clone https://github.com/vincents-ai/transparenz.git
cd transparenz
go build -o transparenz .
```

## Quick Start

### 1. Generate a BSI-compliant SBOM and save to a file

```bash
transparenz generate . \
  --format cyclonedx \
  --bsi-compliant \
  --binary ./build/myapp \
  --manufacturer "Acme Corp" \
  --manufacturer-url "https://acme.example.com" \
  --output sbom.json
```

### 2. Generate and submit directly to a server

```bash
export TRANSPARENZ_SERVER_URL=https://sbom.example.com/api/sbom
export TRANSPARENZ_TOKEN=my-bearer-token

transparenz generate . \
  --format cyclonedx \
  --bsi-compliant \
  --submit
```

### 3. Generate, persist to database, and scan for vulnerabilities

```bash
# Run database migrations first (once)
transparenz db migrate

# Generate and persist
transparenz generate . --bsi-compliant --save

# List stored SBOMs to get the ID
transparenz list

# Scan the SBOM and save results to the database
transparenz scan sbom.json --save
```

## Commands Reference

### Global Flags

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--config` | `-c` | `$HOME/.transparenz.yaml` | Config file path |
| `--verbose` | `-v` | `false` | Enable verbose output |

---

### `generate [source]`

Generate an SBOM from a source path or container image.

```
transparenz generate [source] [flags]
```

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--format` | `-f` | `spdx` | Output format: `spdx` or `cyclonedx` |
| `--output` | `-o` | stdout | Output file path |
| `--save` | | `false` | Persist SBOM to PostgreSQL database |
| `--bsi-compliant` | `-b` | `false` | Apply BSI TR-03183-2 enrichment (hashes, licenses, suppliers, properties) |
| `--manufacturer` | | | SBOM producer organisation name (also: `TRANSPARENZ_MANUFACTURER`) |
| `--manufacturer-url` | | | SBOM producer organisation URL (also: `TRANSPARENZ_MANUFACTURER_URL`) |
| `--binary` | | | Path to compiled binary for SHA-512 hash injection (requires `--bsi-compliant`) |
| `--submit` | | `false` | Submit generated SBOM to a remote server after generation |
| `--server-url` | | | Remote server endpoint URL (also: `TRANSPARENZ_SERVER_URL`) |
| `--token` | | | Bearer authentication token (also: `TRANSPARENZ_TOKEN`) |
| `--insecure` | | `false` | Skip TLS verification (also: `TRANSPARENZ_INSECURE=true`) |
| `--timeout` | | `30` | HTTP timeout in seconds for submission |

**Examples:**

```bash
transparenz generate .
transparenz generate . --format cyclonedx --output sbom.json
transparenz generate docker:nginx:latest --format spdx
transparenz generate . --bsi-compliant --binary ./build/app --save
```

---

### `enrich [sbom-path]`

Enrich an existing SBOM with BSI TR-03183-2 metadata.

```
transparenz enrich [sbom-path] [flags]
```

Adds to all components: BSI properties (`executable`, `archive`, `structured`), dependency completeness assertion, and bumps CycloneDX `specVersion` to 1.6.

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--output` | `-o` | stdout | Output file path |
| `--artifacts` | | | Directory of compiled binaries for SHA-512 hash computation |
| `--binary` | | | Path to a single compiled binary for SHA-512 hash injection |
| `--manufacturer` | | | SBOM producer organisation name (also: `TRANSPARENZ_MANUFACTURER`) |
| `--manufacturer-url` | | | SBOM producer organisation URL (also: `TRANSPARENZ_MANUFACTURER_URL`) |
| `--submit` | | `false` | Submit enriched SBOM to a remote server after enrichment |
| `--server-url` | | | Remote server endpoint URL (also: `TRANSPARENZ_SERVER_URL`) |
| `--token` | | | Bearer authentication token (also: `TRANSPARENZ_TOKEN`) |
| `--insecure` | | `false` | Skip TLS verification (also: `TRANSPARENZ_INSECURE=true`) |
| `--timeout` | | `30` | HTTP timeout in seconds for submission |

**Examples:**

```bash
transparenz enrich sbom.json -o sbom-enriched.json
transparenz enrich sbom.json --artifacts ./build/ -o sbom-final.json
transparenz enrich sbom.json --binary ./build/app --manufacturer "Acme Corp" -o sbom-final.json
```

---

### `bsi-check [sbom-path]`

Validate an SBOM against BSI TR-03183-2 requirements and output a compliance report.

```
transparenz bsi-check [sbom-path] [flags]
```

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--output` | `-o` | stdout | Output file path for the JSON compliance report |

**Examples:**

```bash
transparenz bsi-check sbom.json
transparenz bsi-check sbom.json --output report.json
```

---

### `submit`

Submit an SBOM to a remote server with Bearer token authentication. Reads from `--file` or stdin. Content-Type is auto-detected from the SBOM content unless overridden.

```
transparenz submit [flags]
```

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--file` | `-f` | stdin | Path to SBOM file to submit |
| `--url` | | | Server endpoint URL (also: `TRANSPARENZ_SERVER_URL`) |
| `--token` | | | Bearer authentication token (also: `TRANSPARENZ_TOKEN`) |
| `--timeout` | | `30` | HTTP timeout in seconds |
| `--insecure` | | `false` | Skip TLS certificate verification |
| `--content-type` | | auto-detect | Override the `Content-Type` header |

**Examples:**

```bash
transparenz submit --file sbom.json --url https://sbom.example.com/api/sbom --token my-token
cat sbom.json | transparenz submit --url https://sbom.example.com/api/sbom --token my-token
```

---

### `scan [sbom-path]`

Scan an SBOM for known vulnerabilities using the native Grype library. Accepts SPDX JSON and CycloneDX JSON input.

```
transparenz scan [sbom-path] [flags]
```

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--output-format` | `-f` | `json` | Output format: `json` or `table` |
| `--output` | `-o` | stdout | Output file path |
| `--severity` | | | Filter results by minimum severity (`Critical`, `High`, `Medium`, `Low`) |
| `--save` | | `false` | Persist scan results to the database (requires SBOM to be saved first) |

**Examples:**

```bash
transparenz scan sbom.json
transparenz scan sbom.json --output-format table
transparenz scan sbom.json --severity Critical --save
transparenz scan sbom.json -f json --output results.json
```

---

### `list`

List SBOMs stored in the database.

```
transparenz list [flags]
```

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--limit` | `-l` | `50` | Maximum number of SBOMs to display |
| `--offset` | `-s` | `0` | Pagination offset |
| `--format` | | `table` | Output format: `table` or `json` |

---

### `show [sbom-id]`

Show details of a stored SBOM, including its package list.

```
transparenz show [sbom-id]
```

---

### `search [package-name]`

Search stored SBOMs by package name.

```
transparenz search [package-name]
```

---

### `delete [sbom-id]`

Delete a stored SBOM and all associated data from the database.

```
transparenz delete [sbom-id] [flags]
```

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--force` | `-f` | `false` | Skip the confirmation prompt |

---

### `db migrate`

Run GORM auto-migrations to create or update the database schema.

```
transparenz db migrate
```

---

### `db export <id>`

Export the raw SBOM JSON from the database. Accepts a full UUID or an 8-character prefix.

```
transparenz db export <id> [flags]
```

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--output` | `-o` | stdout | Output file path |

**Examples:**

```bash
transparenz db export a1b2c3d4
transparenz db export a1b2c3d4-e5f6-7890-abcd-ef1234567890 --output exported.json
```

---

## Environment Variables

| Variable | Used by | Description |
|----------|---------|-------------|
| `DATABASE_URL` | all db commands | PostgreSQL connection string (default: `host=localhost user=shift dbname=transparenz port=5432 sslmode=disable`) |
| `TRANSPARENZ_SERVER_URL` | `generate`, `enrich`, `submit` | Remote server endpoint URL |
| `TRANSPARENZ_TOKEN` | `generate`, `enrich`, `submit` | Bearer authentication token |
| `TRANSPARENZ_MANUFACTURER` | `generate`, `enrich` | SBOM producer organisation name |
| `TRANSPARENZ_MANUFACTURER_URL` | `generate`, `enrich` | SBOM producer organisation URL |
| `TRANSPARENZ_INSECURE` | `generate`, `enrich` | Set to `true` to skip TLS certificate verification |

## BSI TR-03183-2 Compliance

`transparenz` targets the BSI TR-03183-2 technical guideline for Software Bills of Materials as required under the EU Cyber Resilience Act.

**What the tool does:**

- **Format**: Outputs CycloneDX 1.6 JSON (or SPDX 2.3 JSON). The `bsi-check` validator requires CycloneDX 1.6+ or SPDX 2.3+ as a minimum.
- **SHA-512 hashes** (Section 4.3): Computed from compiled binaries via `--binary` (single file) or `--artifacts` (directory scan). SHA-512 is mandatory; SHA-256 alone is non-compliant.
- **Supplier and license enrichment**: Namespace-based supplier detection and SPDX licence normalisation applied to all components.
- **Component classification** (Section 4.1): Each component receives `executable`, `archive`, and `structured` properties.
- **Dependency completeness** (Section 4.2): A `completeness: complete` assertion is injected into the SBOM metadata.
- **Manufacturer identity**: The `metadata.manufacturer` field is populated from `--manufacturer` / `TRANSPARENZ_MANUFACTURER`.

**Compliance scoring (`bsi-check`):**

The validator produces a weighted overall score from six categories:

| Category | Weight | Threshold for compliant |
|----------|--------|------------------------|
| SHA-512 hash coverage | 30% | ≥ 80% of components |
| License coverage | 25% | ≥ 80% of components |
| Supplier coverage | 15% | ≥ 80% of components |
| Component properties | 15% | ≥ 80% of components |
| Dependency completeness | 10% | present |
| Format version | 5% | CycloneDX 1.6+ or SPDX 2.3+ |

An SBOM is marked **compliant** when all six categories individually meet their thresholds.

## Database Setup

`transparenz` uses PostgreSQL via GORM. Set the `DATABASE_URL` environment variable or accept the default connection string.

```bash
# Example: create the database
createdb transparenz

# Run migrations (creates tables)
transparenz db migrate
```

The `--save` flag on `generate` and `scan` requires a running PostgreSQL instance with migrations applied.

## License

This software is dual-licensed:

- **Community Edition**: GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). Free for open-source use, research, public sector, and non-profit organisations. Network use of a modified version requires source disclosure under the AGPL.
- **Commercial License**: Required for closed-source commercial applications, proprietary SaaS, or embedding in non-AGPL-compatible products. Contact `shift@someone.section.me`.

See [LICENSE.md](LICENSE.md) for the full licence text.
