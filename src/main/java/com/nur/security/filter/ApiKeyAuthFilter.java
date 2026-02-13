package com.nur.security.filter;

import com.nur.security.access.EndpointAccessProvider;
import com.nur.security.auth.ApiKeyAuthenticator;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.GenericFilterBean;

import java.io.IOException;
import java.io.PrintWriter;

@Component
@RequiredArgsConstructor
public class ApiKeyAuthFilter extends GenericFilterBean {

    private final ApiKeyAuthenticator keyAuthenticator;
    private final EndpointAccessProvider accessProvider;

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain filterChain)
            throws IOException, ServletException {

        HttpServletRequest httpRequest = (HttpServletRequest) request;

        if (accessProvider.doesNotRequireAuthentication(httpRequest.getRequestURI())) {
            filterChain.doFilter(request, response);
            return;
        }

        try {
            Authentication auth = keyAuthenticator.validateApiKey(httpRequest);
            SecurityContextHolder.getContext().setAuthentication(auth);
            filterChain.doFilter(request, response);
        } catch (Exception ex) {
            sendErrorResponse((HttpServletResponse) response, ex.getMessage());
        }
    }

    private void sendErrorResponse(HttpServletResponse response, String errorMessage) throws IOException {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        try (PrintWriter writer = response.getWriter()) {
            writer.print("{\"error\":\"" + errorMessage + "\"}");
            writer.flush();
        }
    }
}
