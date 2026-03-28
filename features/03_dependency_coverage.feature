Feature: CRA-03 SBOM Covers Dependencies
  As a product manufacturer
  I need the SBOM to list all dependencies including transitive
  So that it meets CRA minimum top-level dependency and BSI recursive requirements

  Background:
    Given the transparenz binary is built

  Scenario: SBOM contains multiple components
    When I run "transparenz generate /test-project --format cyclonedx"
    Then the command succeeds
    And the JSON field "components" is a non-empty array

  Scenario: Components have names and versions
    When I run "transparenz generate /test-project --format cyclonedx"
    Then the command succeeds
    And every component has a "name" field
    And every component has a "version" field
