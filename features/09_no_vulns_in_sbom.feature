Feature: BSI-17 No Vulnerability Information in SBOM
  As a product manufacturer
  I need vulnerability data separate from the SBOM
  So that it meets BSI TR-03183-2 Section 3.1 and 8.1.14

  Background:
    Given the transparenz binary is built

  Scenario: Generated SBOM does not contain vulnerability fields
    When I run "transparenz generate /test-project --format cyclonedx --no-fetch --bsi-compliant"
    Then the command succeeds
    And the JSON does not have field "vulnerabilities"

  Scenario: BSI-compliant SBOM does not contain vulns field
    When I run "transparenz generate /test-project --format cyclonedx --no-fetch --bsi-compliant"
    Then the command succeeds
    And the JSON does not have field "vulns"

  Scenario: SPDX SBOM does not contain vulnerability fields
    When I run "transparenz generate /test-project --format spdx --no-fetch"
    Then the command succeeds
    And the JSON does not have field "vulnerabilities"
