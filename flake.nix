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
          
          subPackages = [ "cmd/transparenz" ];
          
          meta = with pkgs.lib; {
            description = "BSI TR-03183 compliant SBOM generator (Native Go)";
            license = licenses.agpl3Plus;
            maintainers = [ ];
          };
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
            echo "Week 1-2: CLI Foundation with Cobra"
            echo "  - Root command: transparenz --help"
            echo "  - Generate: transparenz generate <source>"
            echo "  - Scan: transparenz scan <sbom>"
            echo "  - BSI Check: transparenz bsi-check <sbom>"
            echo "  - Database: list, show, search, delete (stubs)"
          '';
        };
      }
    );
}
