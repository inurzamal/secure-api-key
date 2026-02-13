package com.nur.config.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "auth")
public record SecurityProperties(
        String apiKey
) {
    public SecurityProperties {
            if (apiKey == null || apiKey.isBlank()) {
                throw new IllegalArgumentException("API key cannot be null or blank");
            }
    }
}
