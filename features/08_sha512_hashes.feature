Feature: BSI-10 SHA-512 Hash Support
  As a product manufacturer
  I need SHA-512 checksums for deployable components
  So that it meets BSI TR-03183-2 Section 5.2.2 hash requirement

  Background:
    Given the transparenz binary is built

  Scenario: BSI checker validates SHA-512 as mandatory
    Given an SBOM file exists with SHA-256 only hashes
    When I run "transparenz bsi-check sbom.json"
    Then the command succeeds
    And the report flags SHA-256-only as non-compliant
