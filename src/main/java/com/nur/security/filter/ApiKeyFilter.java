package com.nur.security.filter;

import com.nur.config.properties.SecurityProperties;
import com.nur.security.constants.SecurityConstants;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.jspecify.annotations.NonNull;
import org.springframework.http.MediaType;
import org.springframework.http.server.PathContainer;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.pattern.PathPattern;
import org.springframework.web.util.pattern.PathPatternParser;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Collections;
import java.util.List;

@RequiredArgsConstructor
public class ApiKeyFilter extends OncePerRequestFilter {

    private static final PathPatternParser PARSER = new PathPatternParser();

    private static final List<PathPattern> PUBLIC_PATTERNS =
            SecurityConstants.PUBLIC_MATCHERS.stream().map(PARSER::parse).toList();

    private final SecurityProperties securityProperties;

    @Override
    protected void doFilterInternal(HttpServletRequest request, @NonNull HttpServletResponse response, @NonNull FilterChain chain)
            throws ServletException, IOException {

        if (isPublic(request.getServletPath())) {
            chain.doFilter(request, response);
            return;
        }

        try {
            String apiKey = request.getHeader(SecurityConstants.API_KEY_HEADER);

            if (apiKey == null || !apiKey.equals(securityProperties.apiKey())) {
                throw new BadCredentialsException("Invalid or missing API key");
            }

            var auth = new UsernamePasswordAuthenticationToken(
                    SecurityConstants.API_KEY_PRINCIPAL,
                    null,
                    Collections.emptyList()
            );

            SecurityContextHolder.getContext().setAuthentication(auth);
            chain.doFilter(request, response);

        } catch (Exception ex) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            try (PrintWriter writer = response.getWriter()) {
                writer.print("{\"error\":\"" + ex.getMessage() + "\"}");
            }
        }
    }

    private boolean isPublic(String path) {
        PathContainer pathContainer = PathContainer.parsePath(path);
        return PUBLIC_PATTERNS.stream().anyMatch(pattern -> pattern.matches(pathContainer));
    }
}

