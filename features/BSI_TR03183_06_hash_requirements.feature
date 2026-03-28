Feature: BSI-TR03183-06 Hash Requirements
  As a product manufacturer
  I need components to have cryptographic hashes
  So that it meets BSI TR-03183-2 Section 8.1.7 hash requirements

  Background:
    Given the transparenz binary is built

  Scenario: Components have hashes field
    When I run "transparenz generate /test-project --format cyclonedx --bsi-compliant"
    Then the command succeeds
    And the JSON components array has all items with field "hashes"

  Scenario: Hashes include SHA-256 or stronger
    When I run "transparenz generate /test-project --format cyclonedx --bsi-compliant"
    Then the command succeeds
    And at least 80% of components have SHA-256 or stronger hashes

  Scenario: BSI-compliant mode includes SHA-512
    When I run "transparenz generate /test-project --format cyclonedx --bsi-compliant"
    Then the command succeeds
    And the JSON has field "metadata" with object
    And the JSON metadata has property "standard" equal to "BSI TR-03183-2"
    And at least 50% of components have SHA-512 hashes

  Scenario: Hash content is non-empty hex string
    When I run "transparenz generate /test-project --format cyclonedx --bsi-compliant"
    Then the command succeeds
    And the JSON components have hashes with non-empty "content" field
