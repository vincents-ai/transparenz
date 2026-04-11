Feature: BSI-TR03183-10 SBOM Delivery and Updates
  As a product manufacturer
  I need SBOM delivery mechanisms
  So that it meets BSI TR-03183-2 Section 9 delivery requirements

  Background:
    Given the transparenz binary is built

  Scenario: SBOM can be exported to file
    When I run "transparenz generate /test-project --format cyclonedx --no-fetch --bsi-compliant -o sbom.json"
    Then the command succeeds
    And the JSON has field "bomFormat" equal to "CycloneDX"

  Scenario: SBOM includes version for tracking
    When I run "transparenz generate /test-project --format cyclonedx --no-fetch --bsi-compliant -o sbom.json"
    Then the command succeeds
    And the JSON has field "version" with number

  Scenario: Exported SBOM can be validated with bsi-check
    When I run "transparenz generate /test-project --format cyclonedx --no-fetch --bsi-compliant -o sbom.json"
    And I run "transparenz bsi-check sbom.json"
    Then the command succeeds
    And the JSON report has field "overall_score" with number

  Scenario: SBOM can be enriched after generation
    When I run "transparenz generate /test-project --format cyclonedx --no-fetch -o sbom.json"
    And I run "transparenz enrich sbom.json -o sbom-enriched.json"
    Then the command succeeds
    And the JSON has field "bomFormat" equal to "CycloneDX"
