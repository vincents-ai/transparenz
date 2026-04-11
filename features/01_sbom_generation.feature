Feature: CRA-01 SBOM Generation is Mandatory
  As a product manufacturer
  I need to generate an SBOM for my software product
  So that I comply with EU CRA Annex I, Part II(1)

  Background:
    Given the transparenz binary is built

  Scenario: Generate CycloneDX SBOM for a Go project
    When I run "transparenz generate /test-project --format cyclonedx --no-fetch"
    Then the command succeeds
    And the output is valid JSON
    And the JSON has field "bomFormat" equal to "CycloneDX"

  Scenario: Generate SPDX SBOM for a Go project
    When I run "transparenz generate /test-project --format spdx --no-fetch"
    Then the command succeeds
    And the output is valid JSON
    And the JSON has field "spdxVersion" starting with "SPDX-"

  Scenario: SBOM is machine-readable JSON not PDF
    When I run "transparenz generate /test-project --format cyclonedx --no-fetch"
    Then the command succeeds
    And the output is valid JSON
    And the output is not a PDF

  Scenario: Generate BSI-compliant SBOM
    When I run "transparenz generate /test-project --format cyclonedx --no-fetch --bsi-compliant"
    Then the command succeeds
    And the output is valid JSON
    And the JSON has field "bomFormat" equal to "CycloneDX"

  Scenario: SBOM written to output file
    When I run "transparenz generate /test-project --format cyclonedx --no-fetch -o sbom.json"
    Then the command succeeds
    And the JSON has field "bomFormat" equal to "CycloneDX"
