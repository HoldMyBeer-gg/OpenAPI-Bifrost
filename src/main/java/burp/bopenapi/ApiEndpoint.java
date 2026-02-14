package burp.bopenapi;

import java.util.ArrayList;
import java.util.List;

/**
 * Immutable model for a single API endpoint parsed from an OpenAPI specification.
 * Holds HTTP method, path, server, parameters, and optional description.
 *
 * @author jabberwock
 * @since 1.0
 * Copyright (c) 2026 jabberwock
 */
public class ApiEndpoint {
    private final int index;
    private final String scheme;
    private final String method;
    private final String server;
    private final String path;
    private final List<ParameterInfo> parameters;
    private final String description;

    public ApiEndpoint(int index, String scheme, String method, String server, String path,
                       List<ParameterInfo> parameters, String description) {
        this.index = index;
        this.scheme = scheme != null ? scheme : "https";
        this.method = method != null ? method : "GET";
        this.server = server != null ? server : "";
        this.path = path != null ? path : "/";
        this.parameters = parameters != null ? parameters : new ArrayList<>();
        this.description = description != null ? description : "";
    }

    public int getIndex() {
        return index;
    }

    public String getScheme() {
        return scheme;
    }

    public String getMethod() {
        return method;
    }

    public String getServer() {
        return server;
    }

    public String getPath() {
        return path;
    }

    public List<ParameterInfo> getParameters() {
        return parameters;
    }

    public String getDescription() {
        return description;
    }

    /**
     * Describes a single parameter (path, query, header, or cookie) for an endpoint.
     * Used for insertion point computation and display.
     */
    public static class ParameterInfo {
        private final String name;
        private final String location; // "path", "query", "header", "cookie"
        private final String placeholderValue;

        public ParameterInfo(String name, String location, String placeholderValue) {
            this.name = name;
            this.location = location;
            this.placeholderValue = placeholderValue != null ? placeholderValue : "";
        }

        public String getName() {
            return name;
        }

        public String getLocation() {
            return location;
        }

        public String getPlaceholderValue() {
            return placeholderValue;
        }
    }
}
