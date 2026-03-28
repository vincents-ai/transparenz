# Contributing to Transparenz

Thank you for your interest in contributing to Transparenz! This document outlines the process for contributing to this project.

## Dual License Model

Transparenz is distributed under a dual-license model:
- **Community Edition:** GNU AGPL-3.0-or-later (free and open-source)
- **Enterprise Edition:** Commercial License (for proprietary use)

## Contributor License Agreement (CLA)

To maintain our ability to offer Transparenz under both licenses, we require all contributors to sign a Contributor License Agreement (CLA) before we can accept their contributions.

### Why a CLA?

The CLA allows us to:
1. Offer Transparenz under both AGPL-3.0-or-later and commercial licenses
2. Protect the project and all its users from legal issues
3. Ensure that contributions can be freely distributed under both license options
4. Maintain the long-term sustainability of the project

### What the CLA Means

By signing the CLA, you:
- Grant us a license to use your contributions under both the AGPL-3.0-or-later and our commercial license
- Confirm that you have the right to make the contribution
- Confirm that your contribution is your original work

You retain full copyright to your contributions and can use them however you wish.

## How to Contribute

### 1. Sign the CLA

Before submitting your first contribution:

1. Read the [Contributor License Agreement](CLA.md)
2. Add your signature to the CLA by running:
   ```bash
   echo '{"name": "Your Name", "email": "your.email@example.com", "github": "yourusername", "date": "'$(date -I)'", "signature": "I agree to the CLA"}' >> cla-signatures.json
   ```
3. Include the CLA signature update in your first pull request

### 2. Development Workflow

1. **Fork the repository** on GitHub
2. **Clone your fork** locally:
   ```bash
   git clone https://github.com/YOUR-USERNAME/transparenz-go.git
   cd transparenz-go
   ```
3. **Create a feature branch**:
   ```bash
   git checkout -b feature/your-feature-name
   ```
4. **Make your changes** following our coding standards (see below)
5. **Test your changes**:
   ```bash
   make test
   make build
   ```
6. **Commit your changes** with clear, descriptive commit messages
7. **Push to your fork**:
   ```bash
   git push origin feature/your-feature-name
   ```
8. **Open a Pull Request** on GitHub

### 3. Pull Request Guidelines

- Ensure all tests pass
- Add tests for new features
- Update documentation as needed
- Follow Go best practices and conventions
- Use clear, descriptive commit messages
- Reference any related issues

## Coding Standards

### Go Code Style

- Follow standard Go conventions (`gofmt`, `go vet`)
- Write idiomatic Go code
- Add comments for exported functions and types
- Keep functions focused and concise

### Testing

- Write unit tests for new functionality
- Ensure test coverage doesn't decrease
- Run `make test` before submitting

### Documentation

- Update README.md for user-facing changes
- Add godoc comments for exported APIs
- Update command help text as needed

## BSI TR-03183-2 Compliance

When working on SBOM generation or validation features:
- Ensure compliance with BSI TR-03183-2 requirements
- Maintain hash coverage (SHA-256/SHA-512)
- Validate license SPDX identifiers
- Include supplier/originator metadata

## EU Cyber Resilience Act (CRA)

This project aims to align with EU CRA requirements:
- Security-by-design principles
- Vulnerability disclosure procedures
- SBOM generation and maintenance
- Incident reporting capabilities

## Questions?

If you have questions about contributing, the CLA, or anything else:
- Open an issue on GitHub
- Contact the maintainers: shift@someone.section.me

## Code of Conduct

Be respectful, inclusive, and professional in all interactions. We're building software for the public good.

## License

By contributing to this project, you agree that your contributions will be licensed under the terms specified in the CLA, enabling dual-licensing under both AGPL-3.0-or-later and our commercial license.
