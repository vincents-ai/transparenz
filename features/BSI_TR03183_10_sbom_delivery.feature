Feature: BSI-TR03183-10 SBOM Delivery and Updates
  As a product manufacturer
  I need SBOM delivery mechanisms
  So that it meets BSI TR-03183-2 Section 9 delivery requirements

  Background:
    Given the transparenz binary is built

  Scenario: SBOM can be exported to file
    When I run "transparenz generate /test-project --format cyclonedx --bsi-compliant -o sbom.json"
    Then the command succeeds
    And the file sbom.json exists
    And the file sbom.json contains valid JSON

  Scenario: SBOM includes version for tracking
    When I run "transparenz generate /test-project --format cyclonedx --bsi-compliant -o sbom.json"
    Then the command succeeds
    And the JSON has field "version" with number
    And the version is incremented on regeneration

  Scenario: SBOM can be generated for artifacts
    Given a test binary exists in the artifacts directory
    When I run "transparenz generate artifacts/ --format cyclonedx --bsi-compliant"
    Then the command succeeds
    And the JSON components array is non-empty
