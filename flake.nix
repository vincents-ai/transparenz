{
  description = "Transparenz SBOM Generator (Go Native)";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
      in
      {
        packages.default = pkgs.buildGoModule {
          pname = "transparenz";
          version = "0.1.0";
          src = ./.;
          
          vendorHash = null;
          
          ldflags = [ 
            "-s" 
            "-w" 
            "-X main.version=0.1.0" 
          ];

          # Build root package (main.go at repo root)
          # subPackages = [ "cmd/transparenz" ] — does not exist, entry is ./
          
          meta = with pkgs.lib; {
            description = "BSI TR-03183 compliant SBOM generator (Native Go)";
            license = licenses.agpl3Plus;
            maintainers = [ ];
          };
        };

        packages.sbom = pkgs.stdenv.mkDerivation {
          name = "transparenz-sbom";
          src = ./.;

          # Single binary - no jq, no external tools needed
          nativeBuildInputs = [ self.packages.${system}.default ];

          buildPhase = ''
            # Generate BSI TR-03183-2 compliant SBOM
            # The transparenz binary handles everything:
            #   - CycloneDX 1.6 output
            #   - Component properties: executable, archive, structured
            #   - Dependency completeness assertion
            #   - License enrichment
            #   - Supplier enrichment
            transparenz generate . \
              --format cyclonedx \
              --bsi-compliant \
              --output transparenz-sbom.json
          '';

          installPhase = ''
            mkdir -p $out
            cp transparenz-sbom.json $out/
          '';
        };

        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            go_1_23
            gopls
            gotools
            golangci-lint
            postgresql_15
            syft
            grype
            git
          ];

          shellHook = ''
            echo "Transparenz Go Dev Environment"
            echo "Go: $(go version)"
            echo "PostgreSQL: $(postgres --version | head -1)"
            echo "Syft: $(syft version 2>/dev/null || echo 'installing...')"
            echo "Grype: $(grype version 2>/dev/null || echo 'installing...')"
            echo ""
            echo "BSI TR-03183-2 Compliant SBOM Generation:"
            echo "  nix build .#sbom          - Generate BSI-compliant CycloneDX 1.6 SBOM"
            echo "  transparenz generate . --bsi-compliant --format cyclonedx"
            echo ""
            echo "CLI Commands:"
            echo "  transparenz generate <source>"
            echo "  transparenz enrich <sbom>"
            echo "  transparenz scan <sbom>"
            echo "  transparenz bsi-check <sbom>"
          '';
        };

        hydraJobs.tests = {
          # CLI integration tests
          transparenz-go-cli = import ./nix/tests/transparenz-go-test.nix { system = system; };
          
          # Database integration tests (PostgreSQL)
          transparenz-go-database = import ./nix/tests/database-integration.nix { system = system; };
          
          # BSI TR-03183-2 compliance tests
          transparenz-go-bsi-compliance = import ./nix/tests/bsi-compliance.nix { system = system; };
          
          # Vulnerability database sync tests
          transparenz-go-vulnz = import ./nix/tests/vulnz-integration.nix { system = system; };
          
          # End-to-end tests
          transparenz-go-e2e = import ./nix/tests/e2e-test.nix { system = system; };
          
          # Quick smoke test
          sbom-generation = pkgs.runCommand "sbom-generation-test" {
            nativeBuildInputs = [ pkgs.transparenz-go pkgs.jq ];
          } ''
            mkdir -p $out
            transparenz --help | grep -q "SBOM generator"
            transparenz version | grep -q "0.1.0"
            transparenz generate --help | grep -q "Generate SBOM"
            touch $out/success
          '';
        };
      }
    );
}
