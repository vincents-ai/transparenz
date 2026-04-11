Feature: BSI-TR03183-06 Hash Requirements
  As a product manufacturer
  I need components to have cryptographic hashes
  So that it meets BSI TR-03183-2 Section 8.1.7 hash requirements

  Background:
    Given the transparenz binary is built

  Scenario: BSI-compliant SBOM includes hash metadata
    When I run "transparenz generate /test-project --format cyclonedx --no-fetch --bsi-compliant"
    Then the command succeeds
    And the JSON has field "metadata" with object

  Scenario: BSI check reports hash coverage
    When I run "transparenz generate /test-project --format cyclonedx --no-fetch --bsi-compliant -o sbom.json"
    And I run "transparenz bsi-check sbom.json"
    Then the command succeeds
    And the JSON report has field "hash_coverage" with number
    And the JSON report has field "hash_sha512_count" with number

  Scenario: SHA-256-only is flagged as non-compliant
    Given an SBOM file exists with SHA-256 only hashes
    When I run "transparenz bsi-check sbom.json"
    Then the command succeeds
    And the JSON report has field "hash_sha256_only" with number
    And the report flags SHA-256-only as non-compliant

  Scenario: Enrichment adds SHA-512 from artifacts directory
    Given a test binary exists in the artifacts directory
    When I run "transparenz generate /test-project --format cyclonedx --no-fetch -o sbom.json"
    And I run "transparenz enrich sbom.json --binary artifacts/test-binary -o sbom-enriched.json"
    Then the command succeeds
    And the enriched SBOM has SHA-512 hashes
