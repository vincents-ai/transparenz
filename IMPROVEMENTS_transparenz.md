# transparenz - Architecture Improvements Tracker

**Last updated:** 2026-05-21

## Completed

### Interface Extraction ✅

The following interfaces are now in place:

| Interface | Location | Constructor |
|-----------|----------|-------------|
| `BSIEnricher` | `pkg/bsi/enricher.go` | `NewEnricher(sourcePath string) BSIEnricher` |
| `SBOMGenerator` | `pkg/sbom/generator.go` | `NewGenerator(verbose bool) SBOMGenerator` |

Both use the return-interface-from-constructor pattern. Internal `enricher`/`generator` structs are unexported.

### BSI TR-03183-2 Compliance ✅

79 BDD scenarios covering all major requirements:
- Format compliance (CycloneDX 1.6, SPDX 2.3)
- Document metadata (timestamp, tools, spec version)
- Primary component (name, version, type, supplier)
- Component fields (name, version, purl, type, supplier)
- License requirements (SPDX identifiers)
- Hash requirements (SHA-512 mandatory)
- Component properties (executable, archive, structured)
- Dependency relationships
- BSI check compliance report
- SBOM delivery and export

### CI Pipeline ✅

Full GitHub Actions CI:
- **lint**: golangci-lint v2.11.4 with Go 1.25
- **build**: compiles all packages
- **test**: unit + integration tests with race detector
- **self-sbom**: generates self-SBOM as artifact

## Planned

### Dependency Injection Container (Priority: Low)

A DI container (`pkg/container.go`) exists but is not yet wired into commands. Current command code constructs dependencies inline. Full DI wiring would improve testability of `cmd/` layer.

### CSAF 2.0 Advisory Generation (Priority: High)

CSAF advisory generation lives in `transparenz-server`, not the CLI. A future `csaf` subcommand could be added.

### VEX Document Generation (Priority: Medium)

Vulnerability Exploitability eXchange (VEX) documents are planned.

### Improved Test Coverage

- `internal/repository` integration tests need database CI service
- Property-based fuzz targets could be expanded
- Enrichment edge cases for non-Go ecosystems (npm, Maven, pip)

## Migration Notes

External consumers using transparenz as a library should use the `BSIEnricher` and `SBOMGenerator` interfaces rather than concrete types.
