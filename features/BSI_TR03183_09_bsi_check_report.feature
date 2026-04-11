Feature: BSI-TR03183-09 BSI Check Report
  As a product manufacturer
  I need a BSI compliance check report
  So that it meets BSI TR-03183-2 verification requirements

  Background:
    Given the transparenz binary is built

  Scenario: bsi-check produces structured report
    When I run "transparenz generate /test-project --format cyclonedx --no-fetch --bsi-compliant -o sbom.json"
    And I run "transparenz bsi-check sbom.json"
    Then the command succeeds
    And the JSON report has field "compliant" with boolean
    And the JSON report has field "overall_score" with number

  Scenario: Report includes all coverage metrics
    When I run "transparenz generate /test-project --format cyclonedx --no-fetch --bsi-compliant -o sbom.json"
    And I run "transparenz bsi-check sbom.json"
    Then the command succeeds
    And the JSON report has field "hash_coverage" with number
    And the JSON report has field "license_coverage" with number
    And the JSON report has field "supplier_coverage" with number
    And the JSON report has field "property_coverage" with number

  Scenario: Report identifies incomplete dependencies
    When I run "transparenz generate /test-project --format cyclonedx --no-fetch --bsi-compliant -o sbom.json"
    And I run "transparenz bsi-check sbom.json"
    Then the command succeeds
    And the JSON report has field "dependency_complete" with boolean

  Scenario: Report references BSI standard
    When I run "transparenz generate /test-project --format cyclonedx --no-fetch --bsi-compliant -o sbom.json"
    And I run "transparenz bsi-check sbom.json"
    Then the command succeeds
    And the JSON report metadata has field "standard" equal to "BSI TR-03183-2"
