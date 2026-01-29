package com.ride.authservice.props;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "auth.multi-jwt")
public record MultiJwtProps(
        String serviceIssuer,
        String userIssuer
) {
}
