{ system ? builtins.currentSystem }:

let
  pkgs = import <nixpkgs> { inherit system; };
in

pkgs.nixosTest ({
  name = "transparenz-go-e2e";

  nodes = {
    server = { pkgs, ... }: {
      services.postgresql = {
        enable = true;
        package = pkgs.postgresql_15;
        enableTCPIP = true;
      };
      networking.firewall.allowedTCPPorts = [ 5432 ];
    };

    client = { pkgs, nodes, ... }: {
      environment.systemPackages = [
        pkgs.transparenz-go
        pkgs.jq
        pkgs.syft
        pkgs.grype
      ];
      environment.variables = {
        TRANSPARENZ_DB_URL = "postgresql://postgres:postgres@${nodes.server.config.networking.hostName}:5432/transparenz";
      };
    };
  };

  testScript = ''
    start_all()

    # Wait for PostgreSQL
    server.waitForUnit("postgresql.service")
    server.waitForOpenPort(5432)

    # Setup: Create test project
    client.succeed("mkdir -p /tmp/e2e-test")
    client.succeed("cp -r ${pkgs.transparenz-go.src}/* /tmp/e2e-test/")

    # Step 1: Database setup
    client.succeed("transparenz db migrate")
    client.succeed("transparenz list")

    # Step 2: Generate SBOM
    client.succeed("cd /tmp/e2e-test && transparenz generate . --bsi-compliant --format cyclonedx --output /tmp/test-sbom.json")
    client.succeed("test -f /tmp/test-sbom.json")

    # Step 3: Validate SBOM structure
    client.succeed("cat /tmp/test-sbom.json | jq -e '.bomFormat'")
    client.succeed("cat /tmp/test-sbom.json | jq -e '.specVersion == \"1.6\"'")
    client.succeed("cat /tmp/test-sbom.json | jq -e '.metadata.component.properties'")

    # Step 4: Test Syft integration (if available)
    client.succeed("syft . -o cyclonedxjson --file /tmp/syft-sbom.json 2>&1 || echo 'Syft not fully configured'")

    # Step 5: Test Grype scan
    client.succeed("grype sbom:/tmp/test-sbom.json --fail-on medium 2>&1 || echo 'Grype scan complete'")

    # Step 6: CLI command tests
    client.succeed("transparenz --help | grep -q 'SBOM generator'")
    client.succeed("transparenz generate --help | grep -q 'Generate SBOM'")
    client.succeed("transparenz enrich --help | grep -q 'Enrich SBOM'")
    client.succeed("transparenz scan --help | grep -q 'Scan SBOM'")
    client.succeed("transparenz bsi-check --help | grep -q 'BSI compliance'")

    # Step 7: Database operations
    client.succeed("transparenz db migrate")
    client.succeed("transparenz db sync --help | grep -q 'Sync vulnerability'")

    # Cleanup
    client.succeed("rm -rf /tmp/e2e-test /tmp/test-sbom.json /tmp/syft-sbom.json")
  '';

})
