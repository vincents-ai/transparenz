Feature: BSI-TR03183-03 Primary Component Requirements
  As a product manufacturer
  I need the primary component to have required fields
  So that it meets BSI TR-03183-2 Section 4.4 primary component requirements

  Background:
    Given the transparenz binary is built

  Scenario: Primary component has name
    When I run "transparenz generate /test-project --format cyclonedx --no-fetch --bsi-compliant"
    Then the command succeeds
    And the JSON metadata component has field "name" with non-empty string

  Scenario: Primary component has version
    When I run "transparenz generate /test-project --format cyclonedx --no-fetch --bsi-compliant"
    Then the command succeeds
    And the JSON metadata component has field "version" with non-empty string

  Scenario: Primary component has type in allowed values
    When I run "transparenz generate /test-project --format cyclonedx --no-fetch --bsi-compliant"
    Then the command succeeds
    And the JSON metadata component has field "type" with non-empty string
    And the JSON metadata component has field "type" with value in: application, library, framework, operating-system, device, firmware, container
