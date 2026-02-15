package burp.openapilng;

import burp.api.montoya.core.Range;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.intruder.HttpRequestTemplate;
import burp.api.montoya.intruder.HttpRequestTemplateGenerationOptions;

import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Builds {@link HttpRequest} and {@link HttpRequestTemplate} from {@link ApiEndpoint}s.
 * Handles path/query param substitution, insertion point ranges for Scanner, and
 * Intruder templates with auto-marked insertion points.
 *
 * @author jabberwock
 * @since 1.0
 * Copyright (c) 2026 jabberwock
 */
public class RequestGenerator {

    private static final String PATH_PARAM_PLACEHOLDER = "1";
    private static final String BODY_PLACEHOLDER = "{}";

    /**
     * Builds raw HTTP request bytes for the given endpoint. Uses UTF-8 encoding.
     * Intended for testing. Does not sanitize content; payloads may include security-test
     * data (e.g. SQLi, XSS).
     *
     * @param endpoint the endpoint to build a request for
     * @param baseUrlOverride optional base URL to use instead of the endpoint's server
     * @return raw HTTP request bytes
     */
    byte[] buildRequestBytes(ApiEndpoint endpoint, String baseUrlOverride) {
        String requestStr = buildRequestString(endpoint, baseUrlOverride);
        return requestStr.getBytes(StandardCharsets.UTF_8);
    }

    private String buildRequestString(ApiEndpoint endpoint, String baseUrlOverride) {
        String server = (baseUrlOverride != null && !baseUrlOverride.isBlank())
                ? baseUrlOverride
                : endpoint.getServer();
        if (server == null || server.isEmpty()) {
            server = "https://localhost";
        }
        server = server.endsWith("/") ? server.substring(0, server.length() - 1) : server;

        String path = substitutePathParams(endpoint.getPath(), endpoint.getParameters());
        StringBuilder query = new StringBuilder();
        for (ApiEndpoint.ParameterInfo p : endpoint.getParameters()) {
            if ("query".equals(p.getLocation())) {
                if (query.length() > 0) query.append("&");
                query.append(p.getName()).append("=").append(p.getPlaceholderValue());
            }
        }
        String pathWithQuery = path + (query.length() > 0 ? "?" + query : "");

        boolean hasBody = "POST".equalsIgnoreCase(endpoint.getMethod())
                || "PUT".equalsIgnoreCase(endpoint.getMethod())
                || "PATCH".equalsIgnoreCase(endpoint.getMethod());

        StringBuilder request = new StringBuilder();
        request.append(endpoint.getMethod()).append(" ").append(pathWithQuery).append(" HTTP/1.1\r\n");
        try {
            URI uri = new URI(server);
            String host = uri.getHost();
            int port = uri.getPort();
            boolean secure = "https".equalsIgnoreCase(uri.getScheme());
            if (port <= 0) port = secure ? 443 : 80;
            request.append("Host: ").append(host);
            if ((secure && port != 443) || (!secure && port != 80)) {
                request.append(":").append(port);
            }
            request.append("\r\n");
        } catch (URISyntaxException e) {
            request.append("Host: localhost\r\n");
        }
        request.append("User-Agent: OpenAPI-NG/1.0\r\n");
        if (hasBody) {
            request.append("Content-Type: application/json\r\n");
            request.append("Content-Length: 2\r\n");
        }
        request.append("\r\n");
        if (hasBody) {
            request.append(BODY_PLACEHOLDER);
        }

        return request.toString();
    }

    /**
     * Builds a Montoya {@link HttpRequest} for the given endpoint.
     *
     * @param endpoint the endpoint to build a request for
     * @param baseUrlOverride optional base URL; if null/blank, uses endpoint server
     * @return the constructed HttpRequest
     */
    public HttpRequest buildRequest(ApiEndpoint endpoint, String baseUrlOverride) {
        String requestStr = buildRequestString(endpoint, baseUrlOverride);
        String server = (baseUrlOverride != null && !baseUrlOverride.isBlank())
                ? baseUrlOverride
                : (endpoint.getServer() != null && !endpoint.getServer().isEmpty() ? endpoint.getServer() : "https://localhost");
        server = server.endsWith("/") ? server.substring(0, server.length() - 1) : server;
        return HttpRequest.httpRequest(HttpService.httpService(server), requestStr);
    }

    /**
     * Builds an Intruder template with insertion points auto-marked at URL, cookie,
     * and body parameter values using {@code REPLACE_BASE_PARAMETER_VALUE_WITH_OFFSETS}.
     *
     * @param endpoint the endpoint to build a template for
     * @param baseUrlOverride optional base URL override
     * @return the HttpRequestTemplate ready for Intruder
     */
    public HttpRequestTemplate buildIntruderTemplate(ApiEndpoint endpoint, String baseUrlOverride) {
        HttpRequest request = buildRequest(endpoint, baseUrlOverride);
        return HttpRequestTemplate.httpRequestTemplate(
                request,
                HttpRequestTemplateGenerationOptions.REPLACE_BASE_PARAMETER_VALUE_WITH_OFFSETS
        );
    }

    /**
     * Builds insertion point ranges for Audit Scanner based on OpenAPI parameter definitions.
     * Returns ranges for path params, query params, and the request body (for POST/PUT/PATCH).
     *
     * @param request the HTTP request (used to resolve byte offsets)
     * @param endpoint the endpoint with parameter definitions
     * @return list of ranges where the scanner should inject payloads
     */
    public List<Range> buildInsertionPointRanges(HttpRequest request, ApiEndpoint endpoint) {
        return buildInsertionPointRanges(request.toByteArray().getBytes(), endpoint);
    }

    /**
     * Package-visible for testing without Montoya {@link HttpRequest}.
     *
     * @param raw raw request bytes
     * @param endpoint endpoint with parameter definitions
     * @return list of insertion point ranges
     */
    List<Range> buildInsertionPointRanges(byte[] raw, ApiEndpoint endpoint) {
        List<Range> ranges = new ArrayList<>();
        String rawStr = new String(raw, StandardCharsets.UTF_8);

        // Find path parameter placeholder positions (e.g. "1" in /users/1)
        String path = substitutePathParams(endpoint.getPath(), endpoint.getParameters());
        for (ApiEndpoint.ParameterInfo p : endpoint.getParameters()) {
            if ("path".equals(p.getLocation())) {
                String placeholder = p.getPlaceholderValue();
                if (placeholder == null || placeholder.isEmpty()) placeholder = PATH_PARAM_PLACEHOLDER;
                int idx = rawStr.indexOf(placeholder);
                if (idx >= 0) {
                    ranges.add(Range.range(idx, idx + placeholder.length()));
                }
            }
        }

        // Query params: find name=value positions
        for (ApiEndpoint.ParameterInfo p : endpoint.getParameters()) {
            if ("query".equals(p.getLocation())) {
                String search = p.getName() + "=" + p.getPlaceholderValue();
                int idx = rawStr.indexOf(search);
                if (idx >= 0) {
                    int valueStart = idx + p.getName().length() + 1;
                    ranges.add(Range.range(valueStart, valueStart + p.getPlaceholderValue().length()));
                }
            }
        }

        // Body placeholder
        if ("POST".equalsIgnoreCase(endpoint.getMethod())
                || "PUT".equalsIgnoreCase(endpoint.getMethod())
                || "PATCH".equalsIgnoreCase(endpoint.getMethod())) {
            int bodyIdx = rawStr.indexOf("\r\n\r\n");
            if (bodyIdx >= 0) {
                bodyIdx += 4;
                int bodyEnd = rawStr.length();
                if (bodyEnd > bodyIdx) {
                    ranges.add(Range.range(bodyIdx, bodyEnd));
                }
            }
        }

        return ranges;
    }

    private String substitutePathParams(String path, List<ApiEndpoint.ParameterInfo> params) {
        String result = path;
        for (ApiEndpoint.ParameterInfo p : params) {
            if ("path".equals(p.getLocation())) {
                String placeholder = p.getPlaceholderValue();
                if (placeholder == null || placeholder.isEmpty()) placeholder = PATH_PARAM_PLACEHOLDER;
                result = result.replace("{" + p.getName() + "}", placeholder);
            }
        }
        // Replace any remaining {param} with 1
        result = Pattern.compile("\\{[^}]+\\}").matcher(result).replaceAll(PATH_PARAM_PLACEHOLDER);
        return result;
    }
}
