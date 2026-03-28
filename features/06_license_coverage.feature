Feature: BSI-09 License Coverage (SPDX Identifiers)
  As a product manufacturer
  I need all components to have SPDX license identifiers
  So that it meets BSI TR-03183-2 Section 6.1 and CRA license verification

  Background:
    Given the transparenz binary is built

  Scenario: BSI-compliant SBOM has license enrichment
    When I run "transparenz generate /test-project --format cyclonedx --bsi-compliant"
    Then the command succeeds
    And the majority of components have a license field set
