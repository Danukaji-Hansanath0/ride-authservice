package com.ride.authservice.service.impl;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ride.authservice.dto.LoginResponse;
import com.ride.authservice.service.KeycloakOAuth2AdminServiceApp;
import com.ride.authservice.service.SecurityEventLogger;
import io.github.resilience4j.circuitbreaker.annotation.CircuitBreaker;
import io.github.resilience4j.retry.annotation.Retry;
import lombok.extern.slf4j.Slf4j;
import org.jspecify.annotations.NonNull;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

@Slf4j
@Service
@SuppressWarnings({"unused"})
public class KeycloakOAuth2AdminServiceAppImpl implements KeycloakOAuth2AdminServiceApp {

    private final String keycloakAuthUrl;
    private final String clientId;
    private final String clientSecret; // optional
    private final RestTemplate restTemplate;
    private final String keycloakTokenUrl;
    private final SecurityEventLogger securityEventLogger;
    private final ObjectMapper objectMapper;

    public KeycloakOAuth2AdminServiceAppImpl(
            @Value("${keycloak.admin.auth2-client.auth-url}") String keycloakAuthUrl,
            @Value("${keycloak.admin.auth2-client.client-id}") String clientId,
            @Value("${keycloak.admin.auth2-client.client-secret:}") String clientSecret, // blank = public client
            RestTemplate restTemplate,
            @Value("${keycloak.admin.token-url}") String keycloakTokenUrl,
            SecurityEventLogger securityEventLogger,
            ObjectMapper objectMapper
    ) {
        this.clientId = clientId;
        this.clientSecret = clientSecret == null ? "" : clientSecret;
        this.keycloakAuthUrl = keycloakAuthUrl;
        this.restTemplate = restTemplate;
        this.keycloakTokenUrl = keycloakTokenUrl;
        this.securityEventLogger = securityEventLogger;
        this.objectMapper = objectMapper;
    }

    @Override
    public String getGoogleLoginUrlForMobile(String codeChallenge, String redirectUri, String state) {
        // IMPORTANT: redirectUri must be EXACTLY the same later during token exchange.
        // Also it MUST be allowed in Keycloak Client -> Valid Redirect URIs.
        String url = UriComponentsBuilder.fromUriString(keycloakAuthUrl)
                .queryParam("client_id", clientId)
                .queryParam("redirect_uri", redirectUri)
                .queryParam("response_type", "code")
                .queryParam("scope", "openid") // ensures id_token
                .queryParam("kc_idp_hint", "google")
                .queryParam("code_challenge", codeChallenge)
                .queryParam("code_challenge_method", "S256")
                .queryParam("state", state)
                // encode everything properly (redirect_uri especially)
                .encode(StandardCharsets.UTF_8)
                .build()
                .toUriString();

        log.info("Generated Google login URL (PKCE) for clientId={}", clientId);
        return url;
    }

    @Override
    @CircuitBreaker(name = "keycloak", fallbackMethod = "exchangeCodeFallback")
    @Retry(name = "keycloak")
    public LoginResponse exchangeGoogleCodeForTokenMobile(String code, String codeVerifier, String redirectUri) {
        log.info("Exchanging authorization code for tokens (clientId={})", clientId);

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "authorization_code");
        form.add("client_id", clientId);
        form.add("code", code);
        form.add("redirect_uri", redirectUri);
        form.add("code_verifier", codeVerifier);

        // If client is confidential, Keycloak requires client_secret or basic auth.
        if (!clientSecret.isBlank()) {
            form.add("client_secret", clientSecret);
        }

        try {
            return getLoginResponse(headers, form);
        } catch (HttpClientErrorException e) {
            log.error("HTTP error during token exchange: {} - {}", e.getStatusCode(), e.getResponseBodyAsString());
            securityEventLogger.logOAuth2Error("google", e.getMessage(), "server");

            if (e.getStatusCode() == HttpStatus.BAD_REQUEST) {
                throw new RuntimeException("Invalid authorization code / redirect_uri / verifier (400)", e);
            }
            if (e.getStatusCode() == HttpStatus.UNAUTHORIZED) {
                throw new RuntimeException("Client authentication failed (401). Check client_secret / client type", e);
            }
            throw new RuntimeException("Token exchange failed: " + e.getMessage(), e);

        } catch (RestClientException e) {
            log.error("Rest client error during token exchange: {}", e.getMessage(), e);
            securityEventLogger.logKeycloakError("token_exchange", e.getMessage(), "server");
            throw new RuntimeException("Failed to communicate with Keycloak: " + e.getMessage(), e);

        } catch (Exception e) {
            log.error("Unexpected error during token exchange: {}", e.getMessage(), e);
            securityEventLogger.logKeycloakError("token_exchange", e.getMessage(), "server");
            throw new RuntimeException("Token exchange failed: " + e.getMessage(), e);
        }
    }

    private LoginResponse exchangeCodeFallback(String code, String codeVerifier, String redirectUri, @NonNull Exception ex) {
        log.error("Circuit breaker activated - Keycloak unavailable: {}", ex.getMessage());
        securityEventLogger.logKeycloakError("circuit_breaker_open", ex.getMessage(), "server");
        throw new RuntimeException("Authentication service temporarily unavailable.", ex);
    }

    private @NonNull LoginResponse getLoginResponse(HttpHeaders headers, MultiValueMap<String, String> form) {
        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(form, headers);

        try {
            ResponseEntity<String> tokenResponse = restTemplate.exchange(
                    keycloakTokenUrl,
                    HttpMethod.POST,
                    request,
                    String.class
            );

            if (tokenResponse.getStatusCode() != HttpStatus.OK || tokenResponse.getBody() == null) {
                throw new RuntimeException("Failed token response. Status=" + tokenResponse.getStatusCode());
            }

            JsonNode tokenJson = objectMapper.readTree(tokenResponse.getBody());

            String accessToken = tokenJson.path("access_token").asText(null);
            String refreshToken = tokenJson.path("refresh_token").asText(null);
            long expiresIn = tokenJson.path("expires_in").asLong(0);
            long refreshExpiresIn = tokenJson.path("refresh_expires_in").asLong(0);
            String tokenType = tokenJson.path("token_type").asText("Bearer");
            String scope = tokenJson.path("scope").asText("");

            // OIDC: id_token often present when scope includes openid
            String idToken = tokenJson.path("id_token").asText("");

            if (accessToken == null) {
                throw new RuntimeException("Keycloak token response missing access_token");
            }

            // Extract user details from id_token if present
            String firstName = "";
            String lastName = "";
            String email = "";
            String userId = "";

            if (idToken != null && !idToken.isBlank() && idToken.contains(".")) {
                JsonNode claims = decodeJwtPayload(idToken);
                // Keycloak often uses:
                // sub = userId, preferred_username, email, given_name, family_name
                userId = claims.path("sub").asText("");
                email = claims.path("email").asText("");
                firstName = claims.path("given_name").asText("");
                lastName = claims.path("family_name").asText("");

                // Fallbacks if Google/Keycloak mapping differs
                if (firstName.isBlank()) firstName = claims.path("name").asText("");
            }

            return new LoginResponse(
                    accessToken,
                    refreshToken,
                    expiresIn,
                    refreshExpiresIn,
                    tokenType,
                    scope,
                    firstName,
                    lastName,
                    email,
                    userId,
                    "OFFLINE",
                    false
            );

        } catch (Exception e) {
            log.error("Token exchange request failed: {}", e.getMessage(), e);
            throw new RuntimeException("Token exchange request failed: " + e.getMessage(), e);
        }
    }

    private JsonNode decodeJwtPayload(String jwt) {
        // jwt = header.payload.signature
        String[] parts = jwt.split("\\.");
        if (parts.length < 2) throw new IllegalArgumentException("Invalid JWT");

        byte[] decoded = Base64.getUrlDecoder().decode(parts[1]);
        String json = new String(decoded, StandardCharsets.UTF_8);

        try {
            return objectMapper.readTree(json);
        } catch (Exception e) {
            throw new RuntimeException("Failed to parse id_token payload", e);
        }
    }
}
