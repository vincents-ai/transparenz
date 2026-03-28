Feature: BSI-TR03183-07 Component Properties
  As a product manufacturer
  I need components to have executable, archive, and structured properties
  So that it meets BSI TR-03183-2 Section 8.1.8 properties requirements

  Background:
    Given the transparenz binary is built

  Scenario: Components have executable property
    When I run "transparenz generate /test-project --format cyclonedx --bsi-compliant"
    Then the command succeeds
    And the JSON components have property "bsi:executable" with value "executable" or "non-executable"

  Scenario: Components have archive property
    When I run "transparenz generate /test-project --format cyclonedx --bsi-compliant"
    Then the command succeeds
    And the JSON components have property "bsi:archive" with value "archive" or "no archive"

  Scenario: Components have structured property
    When I run "transparenz generate /test-project --format cyclonedx --bsi-compliant"
    Then the command succeeds
    And the JSON components have property "bsi:structured" with value "structured" or "unstructured"

  Scenario: Property coverage meets BSI threshold
    When I run "transparenz generate /test-project --format cyclonedx --bsi-compliant"
    Then the command succeeds
    And the bsi-check report has "property_coverage" at least 60%
