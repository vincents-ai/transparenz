Feature: CRA-02 SBOM Uses Commonly Used Format
  As a product manufacturer
  I need the SBOM in CycloneDX or SPDX format
  So that it meets CRA Annex I, Part II(1) commonly used format requirement

  Background:
    Given the transparenz binary is built

  Scenario: CycloneDX format is supported
    When I run "transparenz generate /test-project --format cyclonedx"
    Then the command succeeds
    And the JSON has field "bomFormat" equal to "CycloneDX"

  Scenario: SPDX format is supported
    When I run "transparenz generate /test-project --format spdx"
    Then the command succeeds
    And the JSON has field "spdxVersion" containing "SPDX"
