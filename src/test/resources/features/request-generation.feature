Feature: HTTP Request Generation
  As a security tester
  I want to generate HTTP requests from API endpoints
  So that I can test them through Burp Suite

  Scenario: Generate a simple GET request
    Given I have an endpoint with method "GET" and path "/users"
    And the endpoint base URL is "https://api.test.com"
    When I generate an HTTP request
    Then the request should contain "GET /users HTTP/1.1"
    And the request should contain "Host: api.test.com"

  Scenario: Generate a POST request with JSON body
    Given I have an endpoint with method "POST" and path "/users"
    And the endpoint base URL is "https://api.test.com"
    When I generate an HTTP request
    Then the request should contain "POST /users HTTP/1.1"
    And the request should contain "Content-Type: application/json"
    And the request should contain a JSON body

  Scenario: Substitute path parameters in request
    Given I have an endpoint with path "/users/{id}"
    And the endpoint has a path parameter "id" with value "123"
    When I generate an HTTP request
    Then the request path should contain "/users/123"
    And the path should not contain any braces

  Scenario: Override base URL for request generation
    Given I have an endpoint with base URL "https://spec.example.com"
    And I want to override the base URL with "https://target.example.com"
    When I generate an HTTP request
    Then the request should contain "Host: target.example.com"

  Scenario: Generate request with query parameters
    Given I have an endpoint with query parameters
    And the query parameter "limit" has value "10"
    And the query parameter "offset" has value "0"
    When I generate an HTTP request
    Then the request path should contain "?limit=10&offset=0"

  Scenario: Handle multiple path parameters
    Given I have an endpoint with path "/users/{id}/posts/{postId}"
    And the endpoint has a path parameter "id" with value "42"
    When I generate an HTTP request
    Then the request path should contain "/users/42/posts/"
    And all curly braces should be replaced with default values
