Feature: BSI-TR03183-08 Dependency Relationships
  As a product manufacturer
  I need complete dependency relationships
  So that it meets BSI TR-03183-2 Section 8.1.10 relationship requirements

  Background:
    Given the transparenz binary is built

  Scenario: SBOM includes dependencies section
    When I run "transparenz generate /test-project --format cyclonedx --bsi-compliant"
    Then the command succeeds
    And the JSON has field "dependencies" with array

  Scenario: Dependencies reference components by purl
    When I run "transparenz generate /test-project --format cyclonedx --bsi-compliant"
    Then the command succeeds
    And the JSON dependencies have items with "ref" field starting with "pkg:"
    And the JSON dependencies have items with "dependsOn" array

  Scenario: Primary component depends on libraries
    When I run "transparenz generate /test-project --format cyclonedx --bsi-compliant"
    Then the command succeeds
    And the primary component has at least one dependency

  Scenario: Dependency tree is complete
    When I run "transparenz generate /test-project --format cyclonedx --bsi-compliant"
    Then the command succeeds
    And the bsi-check report has "dependency_complete" equal to true
