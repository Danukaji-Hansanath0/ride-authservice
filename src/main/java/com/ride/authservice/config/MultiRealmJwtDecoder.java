package com.ride.authservice.config;

import com.ride.authservice.props.MultiJwtProps;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

/**
 * Custom JWT decoder that supports multiple Keycloak realms.
 * This allows the auth-service to accept tokens from both:
 * - user-authentication realm (for end users - used for update-profile, update-email)
 * - service-authentication realm (for service-to-service communication)
 */
@Component
@Slf4j
public class MultiRealmJwtDecoder implements JwtDecoder {

    private final List<JwtDecoder> decoders;
    private final MultiJwtProps multiJwtProps;

    public MultiRealmJwtDecoder(MultiJwtProps multiJwtProps) {
        this.multiJwtProps = multiJwtProps;
        this.decoders = new ArrayList<>();

        // User realm decoder (for end users updating their profiles)
        String userRealmIssuer = multiJwtProps.userIssuer();
        JwtDecoder userDecoder = createDecoder(userRealmIssuer);
        decoders.add(userDecoder);

        // Service realm decoder (for service-to-service communication)
        String serviceRealmIssuer = multiJwtProps.serviceIssuer();
        JwtDecoder serviceDecoder = createDecoder(serviceRealmIssuer);
        decoders.add(serviceDecoder);

        log.info("MultiRealmJwtDecoder initialized for auth-service with {} realm(s)", decoders.size());
        log.info("  - User realm: {}", userRealmIssuer);
        log.info("  - Service realm: {}", serviceRealmIssuer);
    }

    private JwtDecoder createDecoder(String issuerUri) {
        NimbusJwtDecoder decoder = JwtDecoders.fromIssuerLocation(issuerUri);

        // Add issuer validator
        OAuth2TokenValidator<Jwt> validator = JwtValidators.createDefaultWithIssuer(issuerUri);
        decoder.setJwtValidator(validator);

        return decoder;
    }

    @Override
    public Jwt decode(String token) throws JwtException {
        List<Exception> exceptions = new ArrayList<>();
        JwtException tokenExpiredException = null;

        // Try each decoder
        for (JwtDecoder decoder : decoders) {
            try {
                Jwt jwt = decoder.decode(token);
                log.debug("✅ Successfully decoded JWT from issuer: {}", jwt.getIssuer());
                return jwt;
            } catch (JwtException e) {
                log.debug("❌ Failed to decode with decoder: {}", e.getMessage());
                exceptions.add(e);

                // Check if this is a token expiration error
                if (e.getMessage() != null && e.getMessage().contains("expired")) {
                    tokenExpiredException = e;
                }
            }
        }

        // If token is expired, throw that specific error
        if (tokenExpiredException != null) {
            log.error("JWT token has expired");
            throw tokenExpiredException;
        }

        // If all decoders failed for other reasons, throw the first exception
        log.error("Failed to decode JWT with any of the configured decoders. Tried {} realm(s)", decoders.size());
        throw new JwtException("Unable to decode JWT with any configured realm: " + exceptions.getFirst().getMessage(), exceptions.getFirst());
    }
}
