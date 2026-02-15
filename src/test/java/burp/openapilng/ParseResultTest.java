package burp.openapilng;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link OpenAPIParser.ParseResult}.
 *
 * @author jabberwock
 * @since 1.0
 * Copyright (c) 2026 jabberwock
 */
class ParseResultTest {

    @Test
    void parseResult_getters() {
        var endpoints = List.of(new ApiEndpoint(1, "https", "GET", "https://api.test.com", "/", List.of(), ""));
        var messages = List.of("warning");
        var result = new OpenAPIParser.ParseResult(endpoints, messages, "https://api.test.com");
        assertEquals(endpoints, result.getEndpoints());
        assertEquals(messages, result.getMessages());
        assertEquals("https://api.test.com", result.getDefaultServer());
    }
}
