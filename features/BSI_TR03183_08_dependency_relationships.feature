Feature: BSI-TR03183-08 Dependency Relationships
  As a product manufacturer
  I need complete dependency relationships
  So that it meets BSI TR-03183-2 Section 8.1.10 relationship requirements

  Background:
    Given the transparenz binary is built

  Scenario: SBOM includes dependencies section
    When I run "transparenz generate /test-project --format cyclonedx --no-fetch --bsi-compliant"
    Then the command succeeds
    And the JSON field "dependencies" is a non-empty array

  Scenario: Dependencies reference components by purl
    When I run "transparenz generate /test-project --format cyclonedx --no-fetch --bsi-compliant"
    Then the command succeeds
    And the JSON dependencies have items with "ref" field starting with "pkg:"

  Scenario: Primary component depends on libraries
    When I run "transparenz generate /test-project --format cyclonedx --no-fetch --bsi-compliant"
    Then the command succeeds
    And the primary component has at least one dependency

  Scenario: BSI-compliant SBOM has completeness assertion
    When I run "transparenz generate /test-project --format cyclonedx --no-fetch --bsi-compliant"
    Then the command succeeds
    And the JSON metadata has property "completeness" with value "complete"
