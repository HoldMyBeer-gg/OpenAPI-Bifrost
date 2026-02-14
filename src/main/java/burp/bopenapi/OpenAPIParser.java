package burp.bopenapi;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.PathItem;
import io.swagger.v3.oas.models.parameters.Parameter;
import io.swagger.v3.oas.models.servers.Server;
import io.swagger.v3.parser.OpenAPIV3Parser;
import io.swagger.v3.parser.core.models.SwaggerParseResult;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Parses OpenAPI 2.0 (Swagger) and 3.x specifications into {@link ApiEndpoint} lists.
 * Uses Swagger Parser for JSON and YAML. Strips leading shell prompts from pasted content.
 *
 * @author jabberwock
 * @since 1.0
 * Copyright (c) 2026 jabberwock
 */
public class OpenAPIParser {

    public ParseResult parse(String location, String specContent) {
        List<ApiEndpoint> endpoints = new ArrayList<>();
        List<String> errors = new ArrayList<>();
        String defaultServer = "";

        if (specContent == null || specContent.isBlank()) {
            errors.add("Spec content is empty");
            return new ParseResult(endpoints, errors, defaultServer);
        }

        String cleaned = stripLeadingShellPrompt(specContent.trim());
        SwaggerParseResult parseResult = new OpenAPIV3Parser().readContents(cleaned, null, null);
        OpenAPI openAPI = parseResult.getOpenAPI();

        if (openAPI == null) {
            if (parseResult.getMessages() != null && !parseResult.getMessages().isEmpty()) {
                errors.addAll(parseResult.getMessages());
            } else {
                errors.add("Failed to parse OpenAPI spec");
            }
            return new ParseResult(endpoints, errors, defaultServer);
        }

        if (parseResult.getMessages() != null) {
            errors.addAll(parseResult.getMessages());
        }

        defaultServer = resolveDefaultServer(openAPI);

        Map<String, PathItem> paths = openAPI.getPaths();
        if (paths == null) {
            return new ParseResult(endpoints, errors, defaultServer);
        }

        int index = 1;
        for (Map.Entry<String, PathItem> pathEntry : paths.entrySet()) {
            String path = pathEntry.getKey();
            PathItem pathItem = pathEntry.getValue();
            if (pathItem == null) continue;

            Map<PathItem.HttpMethod, Operation> operations = pathItem.readOperationsMap();
            if (operations == null) continue;

            for (Map.Entry<PathItem.HttpMethod, Operation> opEntry : operations.entrySet()) {
                PathItem.HttpMethod httpMethod = opEntry.getKey();
                Operation operation = opEntry.getValue();
                if (operation == null) continue;

                String method = httpMethod.name();
                String scheme = extractScheme(defaultServer);
                String server = defaultServer;
                String description = operation.getSummary() != null ? operation.getSummary()
                        : (operation.getDescription() != null ? operation.getDescription() : "");

                List<ApiEndpoint.ParameterInfo> params = new ArrayList<>();
                if (operation.getParameters() != null) {
                    for (Parameter p : operation.getParameters()) {
                        if (p == null) continue;
                        String paramName = p.getName();
                        String paramIn = p.getIn() != null ? p.getIn().toLowerCase() : "query";
                        String placeholder = "1";
                        if ("query".equals(paramIn) || "header".equals(paramIn) || "cookie".equals(paramIn)) {
                            placeholder = "";
                        }
                        params.add(new ApiEndpoint.ParameterInfo(paramName, paramIn, placeholder));
                    }
                }

                ApiEndpoint endpoint = new ApiEndpoint(index++, scheme, method, server, path, params, description);
                endpoints.add(endpoint);
            }
        }

        return new ParseResult(endpoints, errors, defaultServer);
    }

    private String resolveDefaultServer(OpenAPI openAPI) {
        List<Server> servers = openAPI.getServers();
        if (servers != null && !servers.isEmpty()) {
            Server s = servers.get(0);
            if (s != null && s.getUrl() != null && !s.getUrl().isBlank()) {
                return normalizeServerUrl(s.getUrl());
            }
        }

        return "";
    }

    private String normalizeServerUrl(String url) {
        if (url == null) return "";
        url = url.trim();
        if (url.endsWith("/")) {
            url = url.substring(0, url.length() - 1);
        }
        return url;
    }

    /**
     * Strips leading lines that look like shell prompts or commands (e.g.
     * {@code anon@MBPC:/mnt/d$ cat openapi.json}) until the first line matching
     * {@code openapi:}, {@code swagger:}, or a JSON opening brace.
     *
     * @param content raw pasted content
     * @return content starting from the first OpenAPI/Swagger line, or original if none found
     */
    private static String stripLeadingShellPrompt(String content) {
        if (content == null || content.isEmpty()) return content;
        String[] lines = content.split("\\r?\\n");
        for (int i = 0; i < lines.length; i++) {
            String line = lines[i].trim();
            if (line.startsWith("openapi:") || line.startsWith("swagger:") || line.startsWith("{")) {
                return String.join("\n", java.util.Arrays.copyOfRange(lines, i, lines.length));
            }
        }
        return content;
    }

    private String extractScheme(String serverUrl) {
        if (serverUrl == null || serverUrl.isBlank()) return "https";
        try {
            URI uri = new URI(serverUrl);
            String scheme = uri.getScheme();
            return scheme != null ? scheme : "https";
        } catch (URISyntaxException e) {
            return "https";
        }
    }

    /**
     * Result of parsing an OpenAPI specification. Contains the parsed endpoints,
     * any warning or error messages from the parser, and the default server URL.
     */
    public static class ParseResult {
        private final List<ApiEndpoint> endpoints;
        private final List<String> messages;
        private final String defaultServer;

        public ParseResult(List<ApiEndpoint> endpoints, List<String> messages, String defaultServer) {
            this.endpoints = endpoints;
            this.messages = messages;
            this.defaultServer = defaultServer;
        }

        public List<ApiEndpoint> getEndpoints() {
            return endpoints;
        }

        public List<String> getMessages() {
            return messages;
        }

        public String getDefaultServer() {
            return defaultServer;
        }
    }
}
