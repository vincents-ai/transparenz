# Contributing to Transparenz CLI

Thank you for your interest in contributing! This project provides BSI TR-03183-2 SBOM generation, validation, and submission tooling for EU CRA/NIS2 compliance.

## Prerequisites

- **Go 1.25+** — [go.dev/dl](https://go.dev/dl/)
- **Nix** (optional) — reproducible builds via `nix develop`

## Building

```bash
go build -o transparenz ./cmd/transparenz
```

## Testing

```bash
# Unit tests
go test ./...

# Integration tests (requires pre-built binary)
make test-integration

# Comparison tests
make compare
```

## Commit Convention

We use [Conventional Commits](https://www.conventionalcommits.org/).

## Code Style

- Follow [Effective Go](https://go.dev/doc/effective_go) guidelines
- Cobra commands go in `cmd/` directory
- Business logic goes in `internal/` packages
- Use `testify` for assertions

## License

By contributing, you agree that your contributions will be licensed under the AGPL-3.0 license.
