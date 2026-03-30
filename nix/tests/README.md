# NixOS Integration Tests for Transparenz Go

This directory contains NixOS integration tests for the Transparenz Go SBOM generator.

## Available Tests

### 1. CLI Tests (`transparenz-go-test.nix`)
Tests basic CLI functionality including:
- Help and version commands
- SBOM generation in SPDX and CycloneDX formats
- BSI-compliant generation
- Verbose mode

**Run:**
```bash
nix run .#hydraJobs.tests.transparenz-go-cli.x86_64-linux
```

### 2. Database Integration (`database-integration.nix`)
Tests PostgreSQL integration:
- Database connectivity
- Schema migrations
- CRUD operations
- Multi-node setup (db + client)

**Run:**
```bash
nix run .#hydraJobs.tests.transparenz-go-database.x86_64-linux
```

### 3. BSI Compliance (`bsi-compliance.nix`)
Validates BSI TR-03183-2 compliance:
- CycloneDX 1.6 schema validation
- SPDX 2.3 compliance
- Required metadata fields
- Component properties

**Run:**
```bash
nix run .#hydraJobs.tests.transparenz-go-bsi-compliance.x86_64-linux
```

### 4. Vulnerability Sync (`vulnz-integration.nix`)
Tests vulnz service integration:
- Database download
- Multi-provider merge validation
- CLI sync and check commands

**Run:**
```bash
nix run .#hydraJobs.tests.transparenz-go-vulnz.x86_64-linux
```

### 5. End-to-End (`e2e-test.nix`)
Complete pipeline test:
- PostgreSQL setup
- SBOM generation
- Syft integration
- Grype vulnerability scanning
- Full CLI command validation

**Run:**
```bash
nix run .#hydraJobs.tests.transparenz-go-e2e.x86_64-linux
```

## Running All Tests

### With Flakes
```bash
# List all tests
nix flake show

# Run all tests
nix build .#hydraJobs.tests

# Run specific test
nix build .#hydraJobs.tests.transparenz-go-e2e.x86_64-linux
```

### With NixOS Test Runner
```bash
# Run a specific test
nix-build -A hydraJobs.tests.transparenz-go-cli.x86_64-linux
./result/bin/nixos-test

# Or directly
nix run nixpkgs#nixosTests.transparenz-go-cli
```

## Development

### Prerequisites
- Nix 2.18+ with flakes enabled
- Virtualization support for NixOS tests (KVM/QEMU)

### Adding New Tests

1. Create a new `.nix` file in this directory
2. Follow the NixOS test module pattern:
   ```nix
   { system ? builtins.currentSystem }:
   let
     pkgs = import <nixpkgs> { inherit system; };
   in
   pkgs.nixosTest ({
     name = "my-new-test";
     nodes.machine = { pkgs, ... }: {
       environment.systemPackages = [ pkgs.transparenz-go ];
     };
     testScript = ''
       machine.succeed("transparenz --help");
     '';
   })
   ```

3. Add to `flake.nix` hydraJobs.tests:
   ```nix
   my-new-test = import ./nix/tests/my-new-test.nix { system = system; };
   ```

### Test Structure

Each test should:
- Be self-contained
- Use `start_all()` to initialize VMs
- Use `machine.succeed()` for passing tests
- Use `machine.fail()` for expected failures
- Clean up resources in testScript

## Notes

- Tests require NixOS test environment (QEMU/KVM)
- Some tests may take several minutes to complete
- Database tests create temporary PostgreSQL instances
- E2E tests require network access for vulnerability feeds
