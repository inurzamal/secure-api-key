package com.nur.security.auth;

import com.nur.config.properties.SecurityProperties;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class ApiKeyAuthenticator {

    private static final String API_KEY_HEADER = "X-API-KEY";
    private final SecurityProperties securityProperties;

    public Authentication validateApiKey(HttpServletRequest request) {

        String providedKey = request.getHeader(API_KEY_HEADER);

        if (providedKey == null || !providedKey.equals(securityProperties.apiKey())) {
            throw new BadCredentialsException("Invalid or missing API key");
        }

        return new ApiKeyAuthentication(providedKey, AuthorityUtils.NO_AUTHORITIES);
    }
}
