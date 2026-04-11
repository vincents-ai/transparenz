Feature: BSI-11 Component Properties (Executable, Archive, Structured)
  As a product manufacturer
  I need every component to declare executable, archive, and structured properties
  So that it meets BSI TR-03183-2 Section 5.2.2 requirement

  Background:
    Given the transparenz binary is built

  Scenario: Components have executable property
    When I run "transparenz generate /test-project --format cyclonedx --no-fetch --bsi-compliant"
    Then the command succeeds
    And every component has property "executable"

  Scenario: Components have archive property
    When I run "transparenz generate /test-project --format cyclonedx --no-fetch --bsi-compliant"
    Then the command succeeds
    And every component has property "archive"

  Scenario: Components have structured property
    When I run "transparenz generate /test-project --format cyclonedx --no-fetch --bsi-compliant"
    Then the command succeeds
    And every component has property "structured"

  Scenario: BSI check reports property coverage
    When I run "transparenz generate /test-project --format cyclonedx --no-fetch --bsi-compliant -o sbom.json"
    And I run "transparenz bsi-check sbom.json"
    Then the command succeeds
    And the JSON report has field "property_coverage" with number
    And the bsi-check report has "property_coverage" at least 0%
