# Transparenz-Go

BSI TR-03183 compliant SBOM generator for Deutschland-Stack - Native Go implementation.

## Week 1-2 Implementation Status

This is the **Week 1-2 CLI Foundation** deliverable of the Go port project.

### Implemented Commands

- **`transparenz generate [source]`** - Generate SBOM using Syft
  - Formats: SPDX JSON, CycloneDX JSON
  - Sources: Directories, files, container images
  - Flags: `--format`, `--output`, `--bsi-compliant` (enrichment stub), `--save` (stub)

- **`transparenz scan [sbom-path]`** - Scan SBOM for vulnerabilities (stub)
  - Full Grype integration pending (Week 3-4)
  - Command structure and interface ready

- **`transparenz bsi-check [sbom-path]`** - BSI TR-03183-2 compliance validation
  - Validates hash coverage (SHA-256/SHA-512)
  - Validates license coverage (SPDX identifiers)
  - Validates supplier/originator coverage
  - Outputs compliance percentage and detailed findings

- **`transparenz list`** - List SBOMs (stub for Week 3-4 database implementation)
- **`transparenz show [id]`** - Show SBOM details (stub)
- **`transparenz search [package]`** - Search packages (stub)
- **`transparenz delete [id]`** - Delete SBOM (stub)

## Quick Start

### Build Binary

```bash
make build
```

This creates `build/transparenz` binary.

### Generate SBOM

```bash
./build/transparenz generate . --format spdx --output sbom.json
```

### Check BSI Compliance

```bash
./build/transparenz bsi-check sbom.json
```

### Run All Demos

```bash
make demo-all
```

## Requirements

- Go 1.22+
- Syft binary in PATH (for Week 1-2 bridge implementation)
- Grype binary in PATH (for future scan implementation)

## Architecture

```
transparenz-go/
├── cmd/
│   ├── root.go           # Root command with Cobra
│   ├── generate.go       # SBOM generation (Syft bridge)
│   ├── scan.go           # Vulnerability scanning (stub)
│   ├── bsi.go            # BSI TR-03183-2 validation
│   ├── db.go             # Database commands (stubs)
│   └── transparenz/
│       └── main.go       # Entry point
├── go.mod
├── Makefile
├── flake.nix             # Nix development environment
└── README.md
```

## Development Roadmap

### ✅ Week 1-2: CLI Foundation (CURRENT)
- [x] Cobra command structure
- [x] Generate command (Syft bridge)
- [x] BSI check command (working validation)
- [x] Scan command (stub interface)
- [x] Database commands (stub interface)
- [x] Makefile build system
- [x] Nix flake for dev environment

### 🚧 Week 3-4: Database Layer with GORM
- [ ] PostgreSQL connection with GORM
- [ ] Models: SBOM, Package, Vulnerability, Scan
- [ ] Repository pattern implementation
- [ ] Implement `--save` flag functionality
- [ ] Implement list/show/search/delete commands

### 🚧 Week 5-6: BSI Compliance Layer
- [ ] Hash enrichment (SHA-256/SHA-512 calculation)
- [ ] License enrichment (SPDX normalization)
- [ ] Supplier enrichment (registry lookups)
- [ ] Full `--bsi-compliant` flag implementation

### 🚧 Week 7: Testing with Godog
- [ ] Port BDD feature files to Godog
- [ ] Integration tests
- [ ] End-to-end tests

### 🚧 Week 8: Distribution
- [ ] GoReleaser configuration
- [ ] GitHub Actions CI/CD
- [ ] Multi-platform binaries
- [ ] Docker images

## Comparison: Python vs Go

| Feature | Python (Current) | Go (Week 1-2) | Go (Final) |
|---------|------------------|---------------|------------|
| CLI Framework | Click | Cobra | Cobra |
| SBOM Generation | subprocess → syft | syft bridge | Native Syft library |
| Vulnerability Scan | subprocess → grype | Stub | Native Grype library |
| Database | SQLAlchemy | Stub | GORM |
| BSI Validation | ✓ | ✓ | ✓ (enhanced) |
| BSI Enrichment | ✓ | Stub | Native Go |
| Deployment | Python + deps | Single binary | Single binary |
| Cold start | ~500ms | ~10ms | ~10ms |

## Success Criteria

- [x] CLI binary compiles successfully
- [x] `transparenz generate .` produces valid SPDX SBOM
- [x] `transparenz bsi-check sbom.json` shows compliance metrics
- [x] All commands have proper help text
- [x] Code follows Go best practices (gofmt)
- [x] Makefile provides easy build/test/demo commands

## Commands Reference

### transparenz generate

```bash
transparenz generate [source] [flags]

Flags:
  -f, --format string      Output format (spdx, cyclonedx) (default "spdx")
  -o, --output string      Output file path (default: stdout)
  -b, --bsi-compliant      Generate BSI TR-03183 compliant SBOM
      --save               Save SBOM to database (requires Week 3-4)
  -v, --verbose            Enable verbose output

Examples:
  transparenz generate .
  transparenz generate . --format cyclonedx --output sbom.json
  transparenz generate docker:nginx:latest --format spdx
```

### transparenz bsi-check

```bash
transparenz bsi-check [sbom-path] [flags]

Flags:
  -o, --output string      Output file path (default: stdout)
  -v, --verbose            Enable verbose output

Example:
  transparenz bsi-check sbom.json
  transparenz bsi-check sbom.json --output report.json
```

### transparenz scan (stub)

```bash
transparenz scan [sbom-path] [flags]

Flags:
  -f, --output-format string   Output format (json, table) (default "json")
  -o, --output string          Output file path (default: stdout)
      --severity string        Filter by severity (Critical, High, Medium, Low)
      --save                   Save scan results to database

Example:
  transparenz scan sbom.json
  transparenz scan sbom.json --output-format table
```

## License

Apache License 2.0

## Engram Task

Part of engram task: `b2dbd457-573e-4da7-a20f-dda485db8c63`

Phase 4 (June-August 2026): Go Port Implementation
