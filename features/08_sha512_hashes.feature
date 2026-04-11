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

  Scenario: BSI check reports hash coverage for SHA-256-only SBOM
    Given an SBOM file exists with SHA-256 only hashes
    When I run "transparenz bsi-check sbom.json"
    Then the command succeeds
    And the JSON report has field "hash_coverage" with number
    And the JSON report has field "hash_sha256_only" with number

  Scenario: Enrichment adds SHA-512 hashes from artifacts
    Given a test binary exists in the artifacts directory
    When I run "transparenz generate /test-project --format cyclonedx --no-fetch -o sbom.json"
    And I run "transparenz enrich sbom.json --binary artifacts/test-binary -o sbom-enriched.json"
    Then the command succeeds
    And the enriched SBOM has SHA-512 hashes

  Scenario: BSI-compliant SBOM passes hash coverage check
    When I run "transparenz generate /test-project --format cyclonedx --no-fetch --bsi-compliant -o sbom.json"
    And I run "transparenz bsi-check sbom.json"
    Then the command succeeds
    And the JSON report has field "hash_coverage" with number
