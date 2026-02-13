package com.nur.security.access;

import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.server.PathContainer;
import org.springframework.stereotype.Component;
import org.springframework.web.util.pattern.PathPattern;
import org.springframework.web.util.pattern.PathPatternParser;
import java.util.List;

@Component
public class EndpointAccessProvider {

    private static final List<String> PUBLIC_PATHS = List.of(
            "/swagger-ui/**",
            "/v3/api-docs/**",
            "/actuator/**"
    );

    private static final PathPatternParser PARSER = new PathPatternParser();

    @Value("${server.servlet.context-path:}")
    private String contextPath;

    private List<PathPattern> publicPatterns;

    @PostConstruct
    public void init() {
        publicPatterns = PUBLIC_PATHS.stream()
                .map(PARSER::parse)
                .toList();
    }

    public boolean isPublicEndpoint(String requestURI) {
        String normalized = removeContextPath(requestURI);
        PathContainer container = PathContainer.parsePath(normalized);
        return publicPatterns.stream()
                .anyMatch(p -> p.matches(container));
    }

    private String removeContextPath(String uri) {
        if (contextPath == null || contextPath.isBlank()) return uri;
        if (uri.startsWith(contextPath)) {
            return uri.substring(contextPath.length());
        }
        return uri;
    }

    public String[] getPublicPathsArray() {
        return PUBLIC_PATHS.toArray(new String[0]);
    }
}
