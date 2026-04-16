package burp.openapibifrost;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

class AuthConfigTest {

    @Test
    void empty_reportsEverythingAbsent() {
        AuthConfig a = AuthConfig.empty();
        assertTrue(a.isEmpty());
        assertFalse(a.hasBearer());
        assertFalse(a.hasApiKey());
        assertFalse(a.hasBasic());
    }

    @Test
    void bearerToken_whitespaceStripped() {
        AuthConfig a = new AuthConfig("  eyJhbGciOi.JI UzI1NiJ9 \n.signature \r\n", null, null, null, null, null);
        assertTrue(a.hasBearer());
        assertEquals("eyJhbGciOi.JIUzI1NiJ9.signature", a.bearerToken());
    }

    @Test
    void apiKey_requiresBothValueAndName() {
        assertFalse(new AuthConfig(null, "secret", "", null, null, null).hasApiKey());
        assertFalse(new AuthConfig(null, "", "X-API-Key", null, null, null).hasApiKey());
        assertTrue(new AuthConfig(null, "secret", "X-API-Key", null, null, null).hasApiKey());
    }

    @Test
    void apiKeyLocation_defaultsToHeader() {
        AuthConfig a = new AuthConfig(null, "s", "X", null, null, null);
        assertEquals(AuthConfig.ApiKeyLocation.HEADER, a.apiKeyLocation());
    }

    @Test
    void basic_encodesUserPassAsBase64() {
        AuthConfig a = new AuthConfig(null, null, null, null, "admin", "hunter2");
        String expected = "Basic " + Base64.getEncoder().encodeToString("admin:hunter2".getBytes(StandardCharsets.UTF_8));
        assertEquals(expected, a.basicAuthorizationHeaderValue());
        assertTrue(a.hasBasic());
    }

    @Test
    void basic_emptyPassStillEncodesColon() {
        AuthConfig a = new AuthConfig(null, null, null, null, "admin", "");
        assertTrue(a.basicAuthorizationHeaderValue().startsWith("Basic "));
        String decoded = new String(Base64.getDecoder().decode(a.basicAuthorizationHeaderValue().substring(6)),
                StandardCharsets.UTF_8);
        assertEquals("admin:", decoded);
    }
}
