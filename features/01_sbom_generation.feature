Feature: CRA-01 SBOM Generation is Mandatory
  As a product manufacturer
  I need to generate an SBOM for my software product
  So that I comply with EU CRA Annex I, Part II(1)

  Background:
    Given the transparenz binary is built

  Scenario: Generate SBOM for a Go project
    When I run "transparenz generate /test-project --format cyclonedx"
    Then the command succeeds
    And the output is valid JSON
    And the JSON has field "bomFormat" equal to "CycloneDX"

  Scenario: SBOM is machine-readable JSON
    When I run "transparenz generate /test-project --format cyclonedx"
    Then the command succeeds
    And the output is valid JSON
    And the output is not a PDF
