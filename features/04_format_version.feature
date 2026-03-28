Feature: BSI-01 Format Version Compliance
  As a product manufacturer
  I need the SBOM in CycloneDX 1.6+ or SPDX 3.0.1+
  So that it meets BSI TR-03183-2 Section 4 format requirements

  Background:
    Given the transparenz binary is built

  Scenario: CycloneDX specVersion is 1.6 after BSI enrichment
    When I run "transparenz generate /test-project --format cyclonedx --bsi-compliant"
    Then the command succeeds
    And the JSON has field "specVersion" equal to "1.6"
