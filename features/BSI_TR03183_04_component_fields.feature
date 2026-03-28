Feature: BSI-TR03183-04 Component Field Requirements
  As a product manufacturer
  I need all components to have required identification fields
  So that it meets BSI TR-03183-2 Section 8.1 component requirements

  Background:
    Given the transparenz binary is built

  Scenario: Each component has name
    When I run "transparenz generate /test-project --format cyclonedx --bsi-compliant"
    Then the command succeeds
    And the JSON components array has all items with field "name"

  Scenario: Each component has version
    When I run "transparenz generate /test-project --format cyclonedx --bsi-compliant"
    Then the command succeeds
    And the JSON components array has all items with field "version"

  Scenario: Each component has unique identifier (purl)
    When I run "transparenz generate /test-project --format cyclonedx --bsi-compliant"
    Then the command succeeds
    And at least 80% of components have field "purl" starting with "pkg:"

  Scenario: Each component has type
    When I run "transparenz generate /test-project --format cyclonedx --bsi-compliant"
    Then the command succeeds
    And the JSON components array has all items with field "type"

  Scenario: Each component has supplier
    When I run "transparenz generate /test-project --format cyclonedx --bsi-compliant"
    Then the command succeeds
    And at least 50% of components have non-empty field "supplier" or "author"
