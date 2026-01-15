package com.ride.authservice.service;

import com.fasterxml.jackson.databind.JsonNode;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import reactor.core.publisher.Mono;
import reactor.util.retry.Retry;

import java.time.Duration;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Service for obtaining and managing service-to-service authentication tokens
 * using Keycloak client credentials flow
 */
@Service
@Slf4j
public class ServiceTokenService {

    private final WebClient webClient;
    private final String tokenUrl;
    private final String clientId;
    private final String clientSecret;

    // Token cache: key = clientId, value = TokenInfo
    private final ConcurrentHashMap<String, TokenInfo> tokenCache = new ConcurrentHashMap<>();

    public ServiceTokenService(
            @Qualifier("genericWebClient") WebClient webClient,
            @Value("${keycloak.admin.service-realm.token-url}") String tokenUrl,
            @Value("${keycloak.admin.service-realm.client-id}") String clientId,
            @Value("${keycloak.admin.service-realm.client-secret}") String clientSecret) {
        this.webClient = webClient;
        this.tokenUrl = tokenUrl;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        log.info("ServiceTokenService initialized with token URL: {}", tokenUrl);
    }

    /**
     * Get a valid access token for service-to-service communication
     * Uses caching to avoid unnecessary token requests
     *
     * @return Mono containing the access token
     */
    public Mono<String> getAccessToken() {
        TokenInfo cachedToken = tokenCache.get(clientId);

        // Check if cached token is still valid (with 30 second buffer)
        if (cachedToken != null && !cachedToken.isExpired(30)) {
            log.debug("Using cached token for client: {}", clientId);
            return Mono.just(cachedToken.token);
        }

        log.info("Requesting new access token for client: {}", clientId);
        return requestNewToken()
                .doOnSuccess(token -> log.info("Successfully obtained new access token"))
                .doOnError(error -> log.error("Failed to obtain access token", error));
    }

    /**
     * Request a new token from Keycloak using client credentials flow
     */
    private Mono<String> requestNewToken() {
        return webClient.post()
                .uri(tokenUrl)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(BodyInserters.fromFormData("grant_type", "client_credentials")
                        .with("client_id", clientId)
                        .with("client_secret", clientSecret))
                .retrieve()
                .bodyToMono(JsonNode.class)
                .retryWhen(Retry.backoff(3, Duration.ofSeconds(1))
                        .maxBackoff(Duration.ofSeconds(5))
                        .filter(throwable -> !(throwable instanceof WebClientResponseException.Unauthorized)))
                .map(jsonNode -> {
                    String token = jsonNode.get("access_token").asText();
                    int expiresIn = jsonNode.has("expires_in")
                            ? jsonNode.get("expires_in").asInt()
                            : 300; // Default 5 minutes

                    // Cache the token
                    tokenCache.put(clientId, new TokenInfo(token, expiresIn));

                    return token;
                })
                .onErrorResume(WebClientResponseException.class, ex -> {
                    log.error("Failed to obtain token. Status: {}, Response: {}",
                            ex.getStatusCode(), ex.getResponseBodyAsString());
                    return Mono.error(new RuntimeException("Failed to obtain service token: " + ex.getMessage()));
                })
                .onErrorResume(ex -> {
                    log.error("Unexpected error obtaining token", ex);
                    return Mono.error(new RuntimeException("Failed to obtain service token: " + ex.getMessage()));
                });
    }

    /**
     * Invalidate the cached token (useful for testing or manual refresh)
     */
    public void invalidateToken() {
        tokenCache.remove(clientId);
        log.info("Token cache invalidated for client: {}", clientId);
    }

    /**
     * Inner class to store token information with expiration
     */
    private static class TokenInfo {
        private final String token;
        private final long expirationTime;

        public TokenInfo(String token, int expiresInSeconds) {
            this.token = token;
            // Store expiration time in milliseconds
            this.expirationTime = System.currentTimeMillis() + (expiresInSeconds * 1000L);
        }

        /**
         * Check if token is expired
         * @param bufferSeconds Additional seconds to consider token expired before actual expiration
         */
        public boolean isExpired(int bufferSeconds) {
            long bufferMillis = bufferSeconds * 1000L;
            return System.currentTimeMillis() >= (expirationTime - bufferMillis);
        }
    }
}

