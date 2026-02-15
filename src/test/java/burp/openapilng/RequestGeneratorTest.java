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
}
