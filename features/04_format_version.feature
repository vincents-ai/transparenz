Feature: BSI-01 Format Version Compliance
  As a product manufacturer
  I need the SBOM in CycloneDX 1.6+ or SPDX 3.0.1+
  So that it meets BSI TR-03183-2 Section 4 format requirements

  Background:
    Given the transparenz binary is built

  Scenario: CycloneDX specVersion is 1.6 after BSI enrichment
    When I run "transparenz generate /test-project --format cyclonedx --no-fetch --bsi-compliant"
    Then the command succeeds
    And the JSON has field "specVersion" equal to "1.6"

  Scenario: CycloneDX format has specVersion
    When I run "transparenz generate /test-project --format cyclonedx --no-fetch"
    Then the command succeeds
    And the JSON has field "specVersion" with non-empty string

  Scenario: BSI check validates format version compliance
    When I run "transparenz generate /test-project --format cyclonedx --no-fetch --bsi-compliant -o sbom.json"
    And I run "transparenz bsi-check sbom.json"
    Then the command succeeds
    And the JSON report has field "format_compliant" with boolean
    And the JSON report has field "format_version" with string

  Scenario: BSI check report has format_compliant true for BSI-compliant SBOM
    When I run "transparenz generate /test-project --format cyclonedx --no-fetch --bsi-compliant -o sbom.json"
    And I run "transparenz bsi-check sbom.json"
    Then the command succeeds
    And the JSON report has field "format_compliant" equal to "true"
