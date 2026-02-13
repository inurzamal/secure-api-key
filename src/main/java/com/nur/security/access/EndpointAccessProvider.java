package com.nur.security.access;

import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.server.PathContainer;
import org.springframework.stereotype.Component;
import org.springframework.web.util.pattern.PathPattern;
import org.springframework.web.util.pattern.PathPatternParser;

import java.util.ArrayList;
import java.util.List;

@Slf4j
@Component
public class EndpointAccessProvider {

    private static final List<String> PROTECTED_PATHS = List.of("/api/**", "/kafka/**");

    private static final List<String> PUBLIC_PATHS = List.of(
            "/swagger-ui/**",
            "/v3/api-docs/**",
            "/actuator/**"
    );

    private static final PathPatternParser pathPatternParser = new PathPatternParser();

    @Value("${server.servlet.context-path:}")
    private String contextPath;

    List<PathPattern> publicPatterns = new ArrayList<>();

    @PostConstruct
    public void initialize() {

        String basePath = (contextPath == null || contextPath.isEmpty())? "" : contextPath;

        publicPatterns = PUBLIC_PATHS.stream()
                .map(path -> pathPatternParser.parse(basePath + path))
                .toList();

        log.info("Initialized public endpoint patterns with contextPath={}", contextPath);
    }

    public boolean doesNotRequireAuthentication(String requestURI) {
        PathContainer pathContainer = PathContainer.parsePath(requestURI);
        return publicPatterns.stream()
                .anyMatch(pattern -> pattern.matches(pathContainer));
    }

    public String[] getProtectedPathsArray() {
        return PROTECTED_PATHS.stream()
                .map(path -> (contextPath == null || contextPath.isEmpty() ? "" : contextPath) + path)
                .toArray(String[]::new);
    }

}
