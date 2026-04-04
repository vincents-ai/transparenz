{ lib, pkgs }:

let
  inherit (lib) genAttrs mapAttrs' nameValuePair;
in

rec {
  list = pkgs.runCommand "list-tests" { } ''
    echo "Available NixOS Integration Tests for Transparenz Go:"
    echo ""
    echo "1. CLI Tests (transparenz-go-cli)"
    echo "   - Basic CLI functionality"
    echo "   - Help and version commands"
    echo "   - SBOM generation in multiple formats"
    echo ""
    echo "2. Database Integration (transparenz-go-database)"
    echo "   - PostgreSQL connectivity"
    echo "   - Database migrations"
    echo "   - CRUD operations"
    echo ""
    echo "3. BSI Compliance (transparenz-go-bsi-compliance)"
    echo "   - BSI TR-03183-2 schema validation"
    echo "   - CycloneDX 1.6 compliance"
    echo "   - SPDX 2.3 compliance"
    echo ""
    echo "4. End-to-End (transparenz-go-e2e)"
    echo "   - Full pipeline test"
    echo "   - PostgreSQL + CLI + SBOM + Vulnerability scan"
    echo ""
    echo "Run tests with:"
    echo "  nix run .#hydraJobs.tests.transparenz-go-cli.x86_64-linux"
    echo "  nix run .#hydraJobs.tests.transparenz-go-bsi-compliance.x86_64-linux"
    echo ""
    echo "Or use flakes:"
    echo "  nix flake show"
    echo "  nix build .#hydraJobs.tests.transparenz-go-e2e.x86_64-linux"
    touch $out
  '';

  all-tests = 
    let
      tests = {
        "transparenz-go-cli" = import ./transparenz-go-test.nix;
        "transparenz-go-database" = import ./database-integration.nix;
        "transparenz-go-bsi-compliance" = import ./bsi-compliance.nix;
        "transparenz-go-e2e" = import ./e2e-test.nix;
      };
    in
    genAttrs (name: tests.${name}) (attrNames tests);
}
