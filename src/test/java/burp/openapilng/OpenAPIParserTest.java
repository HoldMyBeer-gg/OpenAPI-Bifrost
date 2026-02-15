package burp.openapilng;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link OpenAPIParser}.
 *
 * @author jabberwock
 * @since 1.0
 * Copyright (c) 2026 jabberwock
 */
class OpenAPIParserTest {

    private OpenAPIParser parser;

    @BeforeEach
    void setUp() {
        parser = new OpenAPIParser();
    }

    @Test
    void parse_emptyContent_returnsError() {
        var result = parser.parse("test", null);
        assertTrue(result.getEndpoints().isEmpty());
        assertFalse(result.getMessages().isEmpty());
        assertTrue(result.getMessages().get(0).contains("empty"));
    }

    @Test
    void parse_blankContent_returnsError() {
        var result = parser.parse("test", "   ");
        assertTrue(result.getEndpoints().isEmpty());
        assertTrue(result.getMessages().stream().anyMatch(m -> m.contains("empty")));
    }

    @Test
    void parse_invalidJson_returnsError() {
        var result = parser.parse("test", "{ invalid }");
        assertTrue(result.getEndpoints().isEmpty());
        assertFalse(result.getMessages().isEmpty());
    }

    @Test
    void parse_validOpenAPI_returnsEndpoints() throws Exception {
        String json = readResource("openapi-petstore.json");
        var result = parser.parse("petstore.json", json);
        assertFalse(result.getEndpoints().isEmpty());
        assertEquals("https://petstore.example.com/v1", result.getDefaultServer());
        assertEquals(3, result.getEndpoints().size());
        var ep = result.getEndpoints().get(0);
        assertEquals("GET", ep.getMethod());
        assertEquals("/pets", ep.getPath());
        assertEquals("https", ep.getScheme());
    }

    @Test
    void parse_pathParamsExtracted() throws Exception {
        String json = readResource("openapi-petstore.json");
        var result = parser.parse("test", json);
        var petsId = result.getEndpoints().stream()
                .filter(e -> e.getPath().contains("{id}"))
                .findFirst().orElseThrow();
        assertEquals(1, petsId.getParameters().size());
        assertEquals("id", petsId.getParameters().get(0).getName());
        assertEquals("path", petsId.getParameters().get(0).getLocation());
    }

    @Test
    void parse_queryParamsExtracted() throws Exception {
        String json = readResource("openapi-petstore.json");
        var result = parser.parse("test", json);
        var listPets = result.getEndpoints().stream()
                .filter(e -> e.getPath().equals("/pets") && "GET".equals(e.getMethod()))
                .findFirst().orElseThrow();
        assertEquals(1, listPets.getParameters().size());
        assertEquals("query", listPets.getParameters().get(0).getLocation());
    }

    @Test
    void parse_serverUrlNormalized() {
        String json = """
            {"openapi":"3.0","info":{"title":"x","version":"1"},"servers":[{"url":"https://api.example.com/"}],"paths":{"/":{"get":{}}}}
            """;
        var result = parser.parse("test", json);
        assertEquals("https://api.example.com", result.getDefaultServer());
    }

    @Test
    void parse_noServers_returnsEmptyServer() {
        String json = """
            {"openapi":"3.0","info":{"title":"x","version":"1"},"paths":{"/health":{}}}
            """;
        var result = parser.parse("test", json);
        assertTrue(result.getEndpoints().isEmpty());
        assertEquals("", result.getDefaultServer());
    }

    @Test
    void parse_yamlSpec_returnsEndpoints() throws Exception {
        String yaml = readResource("openapi-sample.yaml");
        var result = parser.parse("pasted", yaml);
        assertFalse(result.getEndpoints().isEmpty(), "Expected endpoints; messages: " + result.getMessages());
        assertEquals("https://api.example.com", result.getDefaultServer());
        assertTrue(result.getEndpoints().stream().anyMatch(e -> e.getPath().equals("/serviceability") && "GET".equals(e.getMethod())));
        assertTrue(result.getEndpoints().stream().anyMatch(e -> e.getPath().equals("/address/check/v1") && "POST".equals(e.getMethod())));
    }

    @Test
    void parse_yamlWithLeadingShellPrompt_stripsAndParses() throws Exception {
        String yaml = readResource("openapi-sample.yaml");
        String withPrompt = "anon@MBPC:/mnt/d$ cat openapi.json\n" + yaml;
        var result = parser.parse("pasted", withPrompt);
        assertFalse(result.getEndpoints().isEmpty(), "Expected endpoints; messages: " + result.getMessages());
        assertEquals("https://api.example.com", result.getDefaultServer());
    }

    private String readResource(String name) throws Exception {
        try (InputStream is = OpenAPIParserTest.class.getResourceAsStream("/" + name)) {
            assert is != null : "Resource not found: " + name;
            return new String(is.readAllBytes(), StandardCharsets.UTF_8);
        }
    }
}
