Feature: BSI-TR03183-01 SBOM Format Compliance
  As a product manufacturer
  I need to generate SBOMs in compliant formats
  So that it meets BSI TR-03183-2 Section 4.2 format requirements

  Background:
    Given the transparenz binary is built

  Scenario: CycloneDX format is valid
    When I run "transparenz generate /test-project --format cyclonedx"
    Then the command succeeds
    And the JSON has field "bomFormat" equal to "CycloneDX"
    And the JSON has field "specVersion" with value starting with "1."
    And the output is valid JSON

  Scenario: SPDX format is valid
    When I run "transparenz generate /test-project --format spdx"
    Then the command succeeds
    And the JSON has field "spdxVersion"
    And the output is valid JSON

  Scenario: CycloneDX includes serialNumber (UUID)
    When I run "transparenz generate /test-project --format cyclonedx"
    Then the command succeeds
    And the JSON has field "serialNumber" starting with "urn:uuid:"

  Scenario: SBOM is machine-readable (not PDF)
    When I run "transparenz generate /test-project --format cyclonedx"
    Then the command succeeds
    And the output is valid JSON
    And the output is not a PDF
    And the output is not HTML
