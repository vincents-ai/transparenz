Feature: BSI-TR03183-03 Primary Component Requirements
  As a product manufacturer
  I need the primary component to have required fields
  So that it meets BSI TR-03183-2 Section 4.4 primary component requirements

  Background:
    Given the transparenz binary is built

  Scenario: Primary component has name
    When I run "transparenz generate /test-project --format cyclonedx --bsi-compliant"
    Then the command succeeds
    And the JSON metadata has field "component" with object
    And the JSON metadata component has field "name" with non-empty string

  Scenario: Primary component has version
    When I run "transparenz generate /test-project --format cyclonedx --bsi-compliant"
    Then the command succeeds
    And the JSON metadata has field "component" with object
    And the JSON metadata component has field "version" with non-empty string

  Scenario: Primary component has type
    When I run "transparenz generate /test-project --format cyclonedx --bsi-compliant"
    Then the command succeeds
    And the JSON metadata component has field "type" with non-empty string
    And the type is one of: application, library, framework, operating-system, device, firmware

  Scenario: Primary component has supplier
    When I run "transparenz generate /test-project --format cyclonedx --bsi-compliant"
    Then the command succeeds
    And the JSON metadata component has non-empty field "supplier" or "author"
