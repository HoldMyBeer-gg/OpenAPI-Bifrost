Feature: OpenAPI Specification Parsing
  As a security tester
  I want to parse OpenAPI specifications
  So that I can identify and test API endpoints in Burp Suite

  Scenario: Parse a valid OpenAPI 3.0 specification
    Given I have a valid OpenAPI specification with 3 endpoints
    When I parse the specification
    Then I should get 3 API endpoints
    And each endpoint should have a valid HTTP method
    And each endpoint should have a valid path

  Scenario: Parse an empty specification
    Given I have an empty specification
    When I parse the specification
    Then I should get 0 endpoints
    And I should receive an error message containing "empty"

  Scenario: Parse invalid JSON content
    Given I have invalid JSON content "{ invalid }"
    When I parse the specification
    Then I should get 0 endpoints
    And I should receive error messages

  Scenario: Parse OpenAPI specification with path parameters
    Given I have an OpenAPI specification with path parameters
    When I parse the specification
    Then I should get endpoints with parameter definitions
    And parameters should include "id" of type "path"

  Scenario: Parse OpenAPI specification with query parameters
    Given I have an OpenAPI specification with query parameters
    When I parse the specification
    Then I should get endpoints with parameter definitions
    And parameters should include query parameters

  Scenario: Parse OpenAPI specification from YAML format
    Given I have a valid OpenAPI YAML specification
    When I parse the specification
    Then I should get API endpoints
    And the specification format should be correctly detected
