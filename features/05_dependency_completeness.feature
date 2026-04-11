Feature: BSI-08 Dependency Completeness Assertion
  As a product manufacturer
  I need the SBOM to declare dependency graph completeness
  So that it meets BSI TR-03183-2 Section 5.2.2 requirement

  Background:
    Given the transparenz binary is built

  Scenario: CycloneDX SBOM has completeness property
    When I run "transparenz generate /test-project --format cyclonedx --no-fetch --bsi-compliant"
    Then the command succeeds
    And the JSON metadata has property "completeness" with value "complete"

  Scenario: CycloneDX SBOM has completeness scope property
    When I run "transparenz generate /test-project --format cyclonedx --no-fetch --bsi-compliant"
    Then the command succeeds
    And the JSON metadata has property "completeness:scope" with value "transitive"

  Scenario: BSI check validates dependency completeness
    When I run "transparenz generate /test-project --format cyclonedx --no-fetch --bsi-compliant -o sbom.json"
    And I run "transparenz bsi-check sbom.json"
    Then the command succeeds
    And the JSON report has field "dependency_complete" with boolean

  Scenario: Non-BSI SBOM lacks completeness assertion in report
    When I run "transparenz generate /test-project --format cyclonedx --no-fetch -o sbom.json"
    And I run "transparenz bsi-check sbom.json"
    Then the command succeeds
    And the JSON report has field "dependency_complete" equal to "false"
