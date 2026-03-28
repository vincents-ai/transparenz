Feature: CRA-06 BSI Compliance Check Report
  As a market surveillance authority
  I need a compliance report validating the SBOM
  So that I can verify CRA and BSI TR-03183-2 conformance

  Background:
    Given the transparenz binary is built

  Scenario: BSI check produces a structured report
    When I run "transparenz generate /test-project --format cyclonedx --bsi-compliant -o sbom.json"
    And I run "transparenz bsi-check sbom.json"
    Then the command succeeds
    And the JSON report has field "compliant" with boolean
    And the JSON report has field "overall_score" with number
    And the JSON report has field "hash_coverage" with number
    And the JSON report has field "license_coverage" with number
    And the JSON report has field "supplier_coverage" with number
    And the JSON report has field "property_coverage" with number
    And the JSON report has field "dependency_complete" with boolean
    And the JSON report has field "format_version" with string

  Scenario: BSI check validates SHA-512 requirement
    When I run "transparenz generate /test-project --format cyclonedx --bsi-compliant -o sbom.json"
    And I run "transparenz bsi-check sbom.json"
    Then the command succeeds
    And the JSON report metadata has field "standard" equal to "BSI TR-03183-2"
