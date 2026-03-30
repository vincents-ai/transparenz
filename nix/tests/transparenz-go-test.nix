{ system ? builtins.currentSystem }:

let
  pkgs = import <nixpkgs> { inherit system; };
in

pkgs.nixosTest ({
  name = "transparenz-go-cli-tests";

  nodes.machine = { pkgs, ... }: {
    environment.systemPackages = [
      pkgs.transparenz-go
      pkgs.jq
    ];

    environment.variables = {
      TRANSPARENZ_TEST_DIR = "/tmp/transparenz-test";
    };
  };

  testScript = ''
    start_all()

    # Test 1: CLI help command works
    machine.succeed("transparenz --help | grep -q 'SBOM generator'")

    # Test 2: CLI version command works
    machine.succeed("transparenz version | grep -q '0.1.0'")

    # Test 3: Generate command help works
    machine.succeed("transparenz generate --help | grep -q 'Generate SBOM'")

    # Test 4: Generate SPDX SBOM
    machine.succeed("mkdir -p /tmp/transparenz-test")
    machine.succeed("cp -r ${pkgs.transparenz-go.src}/* /tmp/transparenz-test/")

    machine.succeed("cd /tmp/transparenz-test && transparenz generate . --format spdx --output /tmp/sbom-spdx.json 2>&1")

    # Test 5: Verify SPDX JSON output is valid
    machine.succeed("test -f /tmp/sbom-spdx.json")
    machine.succeed("cat /tmp/sbom-spdx.json | jq -e '.spdxVersion'")

    # Test 6: Generate CycloneDX SBOM
    machine.succeed("cd /tmp/transparenz-test && transparenz generate . --format cyclonedx --output /tmp/sbom-cyclonedx.json 2>&1")

    # Test 7: Verify CycloneDX JSON output is valid
    machine.succeed("test -f /tmp/sbom-cyclonedx.json")
    machine.succeed("cat /tmp/sbom-cyclonedx.json | jq -e '.bomFormat'")

    # Test 8: BSI compliant generation
    machine.succeed("cd /tmp/transparenz-test && transparenz generate . --bsi-compliant --format cyclonedx --output /tmp/sbom-bsi.json 2>&1")

    # Test 9: Verify BSI output has required fields
    machine.succeed("cat /tmp/sbom-bsi.json | jq -e '.metadata.component.properties'")

    # Test 10: Verbose mode works
    machine.succeed("cd /tmp/transparenz-test && transparenz --verbose generate . --format spdx --output /tmp/sbom-verbose.json 2>&1 | grep -q 'Generating SBOM'")
  '';
})
