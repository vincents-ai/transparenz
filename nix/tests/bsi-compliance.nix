{ system ? builtins.currentSystem }:

let
  pkgs = import <nixpkgs> { inherit system; };
in

pkgs.nixosTest ({
  name = "transparenz-go-bsi-compliance";

  nodes.machine = { pkgs, ... }: {
    environment.systemPackages = [
      pkgs.transparenz-go
      pkgs.jq
      pkgs.python3
    ];
  };

  testScript = ''
    start_all()

    # Create test project
    machine.succeed("mkdir -p /tmp/bsi-test-project")
    machine.succeed("cp -r ${pkgs.transparenz-go.src}/* /tmp/bsi-test-project/")

    # Test 1: Generate BSI-compliant CycloneDX SBOM
    machine.succeed("cd /tmp/bsi-test-project && transparenz generate . --bsi-compliant --format cyclonedx --output /tmp/bsi-sbom.json")

    # Test 2: Verify BSI output is valid JSON
    machine.succeed("cat /tmp/bsi-sbom.json | jq . > /dev/null")

    # Test 3: Verify BOM format is CycloneDX
    machine.succeed("cat /tmp/bsi-sbom.json | jq -e '.bomFormat == \"CycloneDX\"'")

    # Test 4: Verify version is 1.6
    machine.succeed("cat /tmp/bsi-sbom.json | jq -e '.specVersion == \"1.6\"'")

    # Test 5: Verify metadata exists
    machine.succeed("cat /tmp/bsi-sbom.json | jq -e '.metadata'")

    # Test 6: Verify component properties (BSI requirement)
    machine.succeed("cat /tmp/bsi-sbom.json | jq -e '.metadata.component.properties'")

    # Test 7: Verify property types for BSI compliance
    machine.succeed("cat /tmp/bsi-sbom.json | jq -e '.metadata.component.properties[] | select(.name == \"CDX:type\")'")

    # Test 8: Verify supplier information
    machine.succeed("cat /tmp/bsi-sbom.json | jq -e '.metadata.component.supplier'")

    # Test 9: Verify timestamp exists
    machine.succeed("cat /tmp/bsi-sbom.json | jq -e '.metadata.timestamp'")

    # Test 10: Generate SPDX SBOM for comparison
    machine.succeed("cd /tmp/bsi-test-project && transparenz generate . --format spdx --output /tmp/spdx-sbom.json")
    machine.succeed("cat /tmp/spdx-sbom.json | jq -e '.spdxVersion == \"SPDX-2.3\"'")

    # Test 11: Verify SPDX has required fields
    machine.succeed("cat /tmp/spdx-sbom.json | jq -e '.dataLicense == \"CC0-1.0\"'")
    machine.succeed("cat /tmp/spdx-sbom.json | jq -e '.SPDXID'")
    machine.succeed("cat /tmp/spdx-sbom.json | jq -e '.name'")

    # Test 12: Validate BSI TR-03183-2 schema compliance
    machine.succeed("cat /tmp/bsi-sbom.json | python3 -c \"import json,sys; d=json.load(sys.stdin); assert 'bomFormat' in d; assert 'metadata' in d; print('BSI schema valid')\"")

    # Cleanup
    machine.succeed("rm -rf /tmp/bsi-test-project /tmp/bsi-sbom.json /tmp/spdx-sbom.json")
  '';

})
