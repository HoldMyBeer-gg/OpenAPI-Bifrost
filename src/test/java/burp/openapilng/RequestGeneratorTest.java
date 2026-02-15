package burp.openapilng;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link RequestGenerator}.
 *
 * @author jabberwock
 * @since 1.0
 * Copyright (c) 2026 jabberwock
 */
class RequestGeneratorTest {

    private RequestGenerator generator;

    @BeforeEach
    void setUp() {
        generator = new RequestGenerator();
    }

    @Test
    void buildRequestBytes_simpleGet() {
        var ep = new ApiEndpoint(1, "https", "GET", "https://api.test.com", "/users", List.of(), "");
        byte[] raw = generator.buildRequestBytes(ep, null);
        String req = new String(raw, StandardCharsets.UTF_8);
        assertTrue(req.contains("GET /users HTTP/1.1"));
        assertTrue(req.contains("Host: api.test.com"));
    }

    @Test
    void buildRequestBytes_baseUrlOverride() {
        var ep = new ApiEndpoint(1, "https", "GET", "https://spec.example.com", "/users", List.of(), "");
        byte[] raw = generator.buildRequestBytes(ep, "https://target.example.com");
        String req = new String(raw, StandardCharsets.UTF_8);
        assertTrue(req.contains("Host: target.example.com"));
    }

    @Test
    void buildRequestBytes_pathParamsSubstituted() {
        var params = List.of(new ApiEndpoint.ParameterInfo("id", "path", "1"));
        var ep = new ApiEndpoint(1, "https", "GET", "https://api.test.com", "/users/{id}", params, "");
        byte[] raw = generator.buildRequestBytes(ep, null);
        assertTrue(new String(raw, StandardCharsets.UTF_8).contains("/users/1"));
    }

    @Test
    void buildRequestBytes_postWithBody() {
        var ep = new ApiEndpoint(1, "https", "POST", "https://api.test.com", "/users", List.of(), "");
        byte[] raw = generator.buildRequestBytes(ep, null);
        String req = new String(raw, StandardCharsets.UTF_8);
        assertTrue(req.contains("Content-Type: application/json"));
        assertTrue(req.contains("{}"));
    }

    @Test
    void buildInsertionPointRanges_getNoParams_returnsEmpty() {
        var ep = new ApiEndpoint(1, "https", "GET", "https://api.test.com", "/users", List.of(), "");
        byte[] raw = generator.buildRequestBytes(ep, null);
        var ranges = generator.buildInsertionPointRanges(raw, ep);
        assertTrue(ranges.isEmpty());
    }

    @Test
    void substitutePathParams_remainingBracesReplaced() {
        var ep = new ApiEndpoint(1, "https", "GET", "https://api.test.com", "/users/{id}/posts/{postId}",
                List.of(new ApiEndpoint.ParameterInfo("id", "path", "1")), "");
        byte[] raw = generator.buildRequestBytes(ep, null);
        String s = new String(raw, StandardCharsets.UTF_8);
        assertTrue(s.contains("/users/1/posts/1"));
    }

    @Test
    void buildRequestBytes_queryParams() {
        var params = List.of(
                new ApiEndpoint.ParameterInfo("limit", "query", "10"),
                new ApiEndpoint.ParameterInfo("offset", "query", "0")
        );
        var ep = new ApiEndpoint(1, "https", "GET", "https://api.test.com", "/users", params, "");
        byte[] raw = generator.buildRequestBytes(ep, null);
        String req = new String(raw, StandardCharsets.UTF_8);
        assertTrue(req.contains("limit=10"));
        assertTrue(req.contains("offset=0"));
        assertTrue(req.contains("&"));
    }

    @Test
    void buildRequestBytes_putWithBody() {
        var ep = new ApiEndpoint(1, "https", "PUT", "https://api.test.com", "/users/1", List.of(), "");
        byte[] raw = generator.buildRequestBytes(ep, null);
        String req = new String(raw, StandardCharsets.UTF_8);
        assertTrue(req.contains("PUT /users/1 HTTP/1.1"));
        assertTrue(req.contains("Content-Type: application/json"));
        assertTrue(req.contains("{}"));
    }

    @Test
    void buildRequestBytes_patchWithBody() {
        var ep = new ApiEndpoint(1, "https", "PATCH", "https://api.test.com", "/users/1", List.of(), "");
        byte[] raw = generator.buildRequestBytes(ep, null);
        String req = new String(raw, StandardCharsets.UTF_8);
        assertTrue(req.contains("PATCH /users/1 HTTP/1.1"));
        assertTrue(req.contains("Content-Type: application/json"));
    }

    @Test
    void buildRequestBytes_nonStandardPort() {
        var ep = new ApiEndpoint(1, "https", "GET", "https://api.test.com:8443", "/api", List.of(), "");
        byte[] raw = generator.buildRequestBytes(ep, null);
        String req = new String(raw, StandardCharsets.UTF_8);
        assertTrue(req.contains("Host: api.test.com:8443"));
    }

    @Test
    void buildRequestBytes_httpDefaultPort() {
        var ep = new ApiEndpoint(1, "http", "GET", "http://api.test.com", "/api", List.of(), "");
        byte[] raw = generator.buildRequestBytes(ep, null);
        String req = new String(raw, StandardCharsets.UTF_8);
        assertTrue(req.contains("Host: api.test.com"));
        assertFalse(req.contains(":80"));
    }

    @Test
    void buildRequestBytes_emptyServer_usesLocalhost() {
        var ep = new ApiEndpoint(1, "https", "GET", "", "/api", List.of(), "");
        byte[] raw = generator.buildRequestBytes(ep, null);
        String req = new String(raw, StandardCharsets.UTF_8);
        assertTrue(req.contains("Host: localhost"));
    }

    @Test
    void buildRequestBytes_serverWithTrailingSlash() {
        var ep = new ApiEndpoint(1, "https", "GET", "https://api.test.com/", "/users", List.of(), "");
        byte[] raw = generator.buildRequestBytes(ep, null);
        String req = new String(raw, StandardCharsets.UTF_8);
        assertTrue(req.contains("GET /users HTTP/1.1"));
        assertFalse(req.contains("//users"));
    }
}
