Feature: BSI-08 Dependency Completeness Assertion
  As a product manufacturer
  I need the SBOM to declare dependency graph completeness
  So that it meets BSI TR-03183-2 Section 5.2.2 requirement

  Background:
    Given the transparenz binary is built

  Scenario: CycloneDX SBOM has completeness property
    When I run "transparenz generate /test-project --format cyclonedx --bsi-compliant"
    Then the command succeeds
    And the JSON metadata has property "completeness" with value "complete"

  Scenario: CycloneDX SBOM has completeness scope property
    When I run "transparenz generate /test-project --format cyclonedx --bsi-compliant"
    Then the command succeeds
    And the JSON metadata has property "completeness:scope" with value "transitive"
