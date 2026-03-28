Feature: BSI-TR03183-02 Document Metadata Requirements
  As a product manufacturer
  I need document metadata with required fields
  So that it meets BSI TR-03183-2 Section 4.3 metadata requirements

  Background:
    Given the transparenz binary is built

  Scenario: Document has creation timestamp
    When I run "transparenz generate /test-project --format cyclonedx"
    Then the command succeeds
    And the JSON metadata has field "timestamp" with non-empty string
    And the timestamp follows ISO 8601 format

  Scenario: Document has tool information
    When I run "transparenz generate /test-project --format cyclonedx"
    Then the command succeeds
    And the JSON metadata has field "tools" with non-empty array

  Scenario: Tool info includes name and version
    When I run "transparenz generate /test-project --format cyclonedx"
    Then the command succeeds
    And the JSON metadata tools array has object with "name" field
    And the JSON metadata tools array has object with "version" field

  Scenario: Document has specification version
    When I run "transparenz generate /test-project --format cyclonedx"
    Then the command succeeds
    And the JSON has field "specVersion" with non-empty string
