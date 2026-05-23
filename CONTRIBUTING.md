# Contributing to Transparenz CLI

Thank you for your interest in contributing! This project provides BSI TR-03183-2 SBOM generation, validation, and submission tooling for EU CRA/NIS2 compliance.

## Prerequisites

- **Go 1.25+** — [go.dev/dl](https://go.dev/dl/)
- **Nix** (optional) — reproducible builds via `nix develop`
- **PostgreSQL 15+** — for database integration tests

## Building

```bash
# Build from source
go build -o transparenz .

# Or via make
make build

# Or with Nix
nix develop --command bash -c "go build -o transparenz ."
```

## Testing

```bash
# Unit tests (all packages)
go test -race ./...

# Via make
make test

# BDD tests (79 scenarios, requires pre-built binary)
go test -race -timeout 20m ./tests/

# Integration tests (requires pre-built binary, gated behind build tag)
go test -race -tags integration ./cmd/

# Property-based tests
go test -race -timeout 180s ./internal/pbt/

# Fuzz tests
make test-fuzz   # (enrichment-engine)

# Test coverage
make test-coverage
```

### Test Categories

| Category | Command | Notes |
|----------|---------|-------|
| Unit | `go test -race ./...` | Covers all packages with race detector |
| BDD | `go test ./tests/` | 79 godog scenarios, ~10 min |
| Integration | `go test -tags integration ./cmd/` | CLI subprocess tests, needs binary |
| PBT | `go test ./internal/pbt/` | Property-based testing |
| Fuzz | `make test-fuzz` | Fuzz targets in enrichment-engine |

## Linting

```bash
# Run golangci-lint
make lint

# Or directly
golangci-lint run --timeout 5m ./...
```

## Project Structure

```
transparenz/
├── cmd/                  # Cobra CLI commands
├── internal/
│   ├── models/           # GORM database models
│   ├── pbt/              # Property-based tests
│   ├── repository/       # Database repository layer
│   └── testutil/         # Test utilities
├── pkg/
│   ├── bsi/              # BSI TR-03183-2 enrichment & validation
│   ├── database/         # PostgreSQL connection management
│   ├── depfetch/         # Pre-scan dependency fetching
│   └── sbom/             # SBOM generation (native Syft library)
├── tests/
│   ├── steps/            # Godog step definitions
│   └── cra_compliance_test.go  # BDD test entry point
└── features/             # Godog feature files
```

## Code Style

- Follow [Effective Go](https://go.dev/doc/effective_go) guidelines
- Cobra commands go in `cmd/` directory
- Business logic goes in `internal/` or `pkg/` packages
- Use `stretchr/testify` for assertions
- BDD tests use `cucumber/godog` with step definitions in `tests/steps/`

## Commit Convention

We use [Conventional Commits](https://www.conventionalcommits.org/) with task references:

```
feat: add CSAF advisory generation [task:<uuid>]
fix: resolve SBOM enrichment edge case [task:<uuid>]
test: add fuzz tests for license detection [task:<uuid>]
docs: update BSI compliance coverage [task:<uuid>]
```

Commits must reference a valid Engram task UUID. Use `engram task create --title "..."` to create one.

## Pull Request Process

1. Create a task: `engram task create --title "Description"`
2. Create a feature branch from `main`
3. Make changes with conventional commits referencing the task
4. Ensure all tests pass: `make test`
5. Ensure lint passes: `make lint`
6. Open a PR against `main`

## License

By contributing, you agree that your contributions will be dual-licensed under AGPL-3.0-or-later and the commercial license terms.
