package com.nur.security.constants;

import lombok.experimental.UtilityClass;
import java.util.List;

@UtilityClass
public class SecurityConstants {

    public static final String API_KEY_HEADER = "X-API-KEY";

    public static final List<String> PUBLIC_PATHS = List.of(
            "/swagger-ui/**",
            "/v3/api-docs/**",
            "/actuator/**"
    );
}
