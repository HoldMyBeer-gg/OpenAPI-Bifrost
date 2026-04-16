package burp.openapibifrost;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Immutable auth credentials applied to every generated request. Supports bearer
 * tokens, API keys (header/query/cookie), and HTTP Basic. An empty instance
 * adds no auth.
 */
public final class AuthConfig {

    public enum ApiKeyLocation { HEADER, QUERY, COOKIE }

    private final String bearerToken;
    private final String apiKeyValue;
    private final String apiKeyName;
    private final ApiKeyLocation apiKeyLocation;
    private final String basicUser;
    private final String basicPass;

    public AuthConfig(String bearerToken,
                      String apiKeyValue, String apiKeyName, ApiKeyLocation apiKeyLocation,
                      String basicUser, String basicPass) {
        this.bearerToken = stripWhitespace(bearerToken);
        this.apiKeyValue = trim(apiKeyValue);
        this.apiKeyName = trim(apiKeyName);
        this.apiKeyLocation = apiKeyLocation != null ? apiKeyLocation : ApiKeyLocation.HEADER;
        this.basicUser = trim(basicUser);
        this.basicPass = basicPass != null ? basicPass : "";
    }

    public static AuthConfig empty() {
        return new AuthConfig(null, null, null, null, null, null);
    }

    public boolean hasBearer() {
        return !bearerToken.isEmpty();
    }

    public boolean hasApiKey() {
        return !apiKeyValue.isEmpty() && !apiKeyName.isEmpty();
    }

    public boolean hasBasic() {
        return !basicUser.isEmpty();
    }

    public boolean isEmpty() {
        return !hasBearer() && !hasApiKey() && !hasBasic();
    }

    public String bearerToken() { return bearerToken; }
    public String apiKeyValue() { return apiKeyValue; }
    public String apiKeyName() { return apiKeyName; }
    public ApiKeyLocation apiKeyLocation() { return apiKeyLocation; }
    public String basicUser() { return basicUser; }
    public String basicPass() { return basicPass; }

    public String basicAuthorizationHeaderValue() {
        String raw = basicUser + ":" + basicPass;
        return "Basic " + Base64.getEncoder().encodeToString(raw.getBytes(StandardCharsets.UTF_8));
    }

    private static String stripWhitespace(String s) {
        return s == null ? "" : s.replaceAll("\\s+", "");
    }

    private static String trim(String s) {
        return s == null ? "" : s.trim();
    }
}
