Feature: BSI-TR03183-05 License Requirements
  As a product manufacturer
  I need components to have SPDX license identifiers
  So that it meets BSI TR-03183-2 Section 8.1.6 license requirements

  Background:
    Given the transparenz binary is built

  Scenario: Components have license field
    When I run "transparenz generate /test-project --format cyclonedx --bsi-compliant"
    Then the command succeeds
    And the JSON components array has all items with field "licenses"

  Scenario: License identifiers use SPDX format
    When I run "transparenz generate /test-project --format cyclonedx --bsi-compliant"
    Then the command succeeds
    And the JSON components licenses use SPDX identifiers (Apache-2.0, MIT, BSD-3-Clause, etc.)

  Scenario: Majority of components have identified licenses
    When I run "transparenz generate /test-project --format cyclonedx --bsi-compliant"
    Then the command succeeds
    And at least 40% of components have non-empty licenses array

  Scenario: License field is not NOASSERTION
    When I run "transparenz generate /test-project --format cyclonedx --bsi-compliant"
    Then the command succeeds
    And fewer than 80% of components have "NOASSERTION" as license
