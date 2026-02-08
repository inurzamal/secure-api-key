package com.nur.config.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "security.api-key")
public record ApiKeyProperties(
        String headerName,
        String value
) {
}


