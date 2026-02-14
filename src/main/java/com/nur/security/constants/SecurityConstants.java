package com.nur.security.constants;

import java.util.List;

public final class SecurityConstants {

    private SecurityConstants() {}

    public static final String API_KEY_HEADER = "X-API-KEY";
    public static final String API_KEY_PRINCIPAL = "api-key-user";

    public static final List<String> PUBLIC_MATCHERS = List.of(
            "/swagger-ui/**",
            "/v3/api-docs/**",
            "/actuator/**"
    );
}
