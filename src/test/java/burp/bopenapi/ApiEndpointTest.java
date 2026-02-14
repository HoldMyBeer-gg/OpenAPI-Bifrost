package burp.bopenapi;

import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link ApiEndpoint} and {@link ApiEndpoint.ParameterInfo}.
 *
 * @author jabberwock
 * @since 1.0
 * Copyright (c) 2026 jabberwock
 */
class ApiEndpointTest {

    @Test
    void constructor_nullValues_useDefaults() {
        var ep = new ApiEndpoint(1, null, null, null, null, null, null);
        assertEquals("https", ep.getScheme());
        assertEquals("GET", ep.getMethod());
        assertEquals("", ep.getServer());
        assertEquals("/", ep.getPath());
        assertTrue(ep.getParameters().isEmpty());
        assertEquals("", ep.getDescription());
    }

    @Test
    void constructor_validValues_preserved() {
        var params = List.of(new ApiEndpoint.ParameterInfo("id", "path", "1"));
        var ep = new ApiEndpoint(1, "http", "POST", "https://api.test.com", "/users", params, "Create user");
        assertEquals(1, ep.getIndex());
        assertEquals("http", ep.getScheme());
        assertEquals("POST", ep.getMethod());
        assertEquals("https://api.test.com", ep.getServer());
        assertEquals("/users", ep.getPath());
        assertEquals(1, ep.getParameters().size());
        assertEquals("Create user", ep.getDescription());
    }

    @Test
    void parameterInfo_nullPlaceholder_usesEmpty() {
        var p = new ApiEndpoint.ParameterInfo("x", "query", null);
        assertEquals("", p.getPlaceholderValue());
    }
}
