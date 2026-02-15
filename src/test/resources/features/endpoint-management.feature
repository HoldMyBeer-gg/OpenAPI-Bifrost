Feature: API Endpoint Management
  As a security tester
  I want to manage and view API endpoints
  So that I can organize my testing workflow

  Scenario: Create a new API endpoint
    Given I want to create an endpoint
    When I create an endpoint with method "GET" and path "/api/users"
    Then the endpoint should have a unique ID
    And the endpoint should store the HTTP method
    And the endpoint should store the path

  Scenario: Endpoint with parameters
    Given I create an endpoint with parameters
    When I add a parameter "userId" of type "path"
    And I add a parameter "limit" of type "query"
    Then the endpoint should contain 2 parameters
    And I should be able to retrieve parameter details

  Scenario: Compare endpoint properties
    Given I have two endpoints with the same method and path
    Then they should have matching methods and paths

  Scenario: Endpoint with different methods are not equal
    Given I have a first endpoint with method "GET" and path "/users"
    And I have a second endpoint with method "POST" and path "/users"
    When I compare the endpoints
    Then they should have different methods
