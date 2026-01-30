package com.ride.authservice.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.header.writers.XXssProtectionHeaderWriter;

/**
 * Security Configuration for Auth Service
 * Supports dual JWT authentication from both user-authentication and service-authentication realms
 *
 * @author Ride Platform Team
 * @version 1.0.0
 * @since 2026-01-26
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
public class SecurityConfig {

    private final MultiRealmJwtDecoder multiRealmJwtDecoder;

    public SecurityConfig(MultiRealmJwtDecoder multiRealmJwtDecoder) {
        this.multiRealmJwtDecoder = multiRealmJwtDecoder;
    }

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                .headers(headers -> headers
                        .contentTypeOptions(Customizer.withDefaults())
                        .xssProtection(xss -> xss.headerValue(XXssProtectionHeaderWriter.HeaderValue.ENABLED))
                        .frameOptions(HeadersConfigurer.FrameOptionsConfig::deny)
                        .contentSecurityPolicy(csp -> csp
                                .policyDirectives("default-src 'self'; frame-ancestors 'none'; form-action 'self'")
                        )
                        .httpStrictTransportSecurity(hsts -> hsts
                                .includeSubDomains(true)
                                .maxAgeInSeconds(31536000)
                        )
                )
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/actuator/**", "/public/**").permitAll()
                        // Swagger UI endpoints
                        .requestMatchers("/swagger-ui/**", "/swagger-ui.html").permitAll()
                        .requestMatchers("/v3/api-docs/**", "/v3/api-docs.yaml").permitAll()
                        .requestMatchers("/swagger-resources/**", "/webjars/**").permitAll()
                        // OAuth2 callback endpoints (must be public for Keycloak to redirect)
                        .requestMatchers("/api/v1/auth/oauth2/callback/**").permitAll()
                        // Auth endpoints - public
                        .requestMatchers(HttpMethod.POST, "/api/v1/auth/register").permitAll()
                        .requestMatchers(HttpMethod.POST, "/api/v1/auth/login").permitAll()
                        .requestMatchers(HttpMethod.POST, "/api/v1/auth/refresh", "/api/v1/auth/refresh-token").permitAll()
                        .requestMatchers(HttpMethod.POST, "/api/v1/auth/password-reset").permitAll()
                        .requestMatchers(HttpMethod.GET, "/api/v1/auth/verify-email/**").permitAll()
                        .requestMatchers(HttpMethod.GET, "/api/v1/auth/send-verification-email/**").permitAll()
                        .requestMatchers("/api/v1/auth/login/google/mobile", "/api/v1/auth/google/callback/mobile").permitAll()
                        // Protected endpoints - require JWT authentication
                        .requestMatchers(HttpMethod.PUT, "/api/v1/auth/update-email").authenticated()
                        .requestMatchers(HttpMethod.PUT, "/api/v1/auth/update-profile").authenticated()
                        .anyRequest().authenticated()
                )
                .oauth2ResourceServer(oauth -> oauth
                        .jwt(jwt -> jwt.decoder(multiRealmJwtDecoder))
                );
        return http.build();
    }
}
