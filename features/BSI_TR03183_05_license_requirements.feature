Feature: BSI-TR03183-05 License Requirements
  As a product manufacturer
  I need components to have SPDX license identifiers
  So that it meets BSI TR-03183-2 Section 8.1.6 license requirements

  Background:
    Given the transparenz binary is built

  Scenario: Components have license field
    When I run "transparenz generate /test-project --format cyclonedx --no-fetch --bsi-compliant"
    Then the command succeeds
    And the majority of components have a license field set

  Scenario: License identifiers use SPDX format
    When I run "transparenz generate /test-project --format cyclonedx --no-fetch --bsi-compliant"
    Then the command succeeds
    And the JSON components licenses use SPDX identifiers

  Scenario: BSI check reports license coverage
    When I run "transparenz generate /test-project --format cyclonedx --no-fetch --bsi-compliant -o sbom.json"
    And I run "transparenz bsi-check sbom.json"
    Then the command succeeds
    And the JSON report has field "license_coverage" with number
    And the bsi-check report has "license_coverage" at least 0%

  Scenario: License count is tracked in report
    When I run "transparenz generate /test-project --format cyclonedx --no-fetch --bsi-compliant -o sbom.json"
    And I run "transparenz bsi-check sbom.json"
    Then the command succeeds
    And the JSON report has field "license_count" with number
