package com.ride.authservice.service;

import com.ride.authservice.dto.UserProfileRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import reactor.core.publisher.Mono;

/**
 * Client for communicating with User Service using service-to-service authentication
 */
@Service
@Slf4j
public class UserServiceClientWebClient {

    private final WebClient userServiceWebClient;
    private final ServiceTokenService serviceTokenService;

    public UserServiceClientWebClient(
            @Qualifier("userServiceWebClient") WebClient userServiceWebClient,
            ServiceTokenService serviceTokenService) {
        this.userServiceWebClient = userServiceWebClient;
        this.serviceTokenService = serviceTokenService;
    }

    /**
     * Create user profile with service authentication
     * @param userRequest User profile data
     */
    public void createUserProfile(UserProfileRequest userRequest) {
        createUserProfileReactive(userRequest)
                .doOnSuccess(response -> log.info("User profile created successfully for email: {}", userRequest.getEmail()))
                .doOnError(error -> log.error("Error creating user profile for email: {}", userRequest.getEmail(), error))
                .subscribe();
    }

    /**
     * Create user profile with service authentication (reactive)
     * @param userRequest User profile data
     * @return Mono with response
     */
    public Mono<String> createUserProfileReactive(UserProfileRequest userRequest) {
        return serviceTokenService.getAccessToken()
                .flatMap(token ->
                    userServiceWebClient.post()
                            .uri("/api/v1/users")
                            .contentType(MediaType.APPLICATION_JSON)
                            .headers(headers -> headers.setBearerAuth(token))
                            .bodyValue(userRequest)
                            .retrieve()
                            .bodyToMono(String.class)
                            .doOnSuccess(response ->
                                log.info("Successfully created user profile for: {}", userRequest.getEmail()))
                            .onErrorResume(WebClientResponseException.class, ex -> {
                                log.error("Failed to create user profile. Status: {}, Response: {}",
                                        ex.getStatusCode(), ex.getResponseBodyAsString());
                                return Mono.error(ex);
                            })
                );
    }

    /**
     * Get user profile by email with service authentication
     * @param email User email
     * @return Mono with user data
     */
    public Mono<String> getUserProfile(String email) {
        return serviceTokenService.getAccessToken()
                .flatMap(token ->
                    userServiceWebClient.get()
                            .uri(uriBuilder -> uriBuilder
                                    .path("/api/v1/users/profile/{email}")
                                    .build(email))
                            .headers(headers -> headers.setBearerAuth(token))
                            .retrieve()
                            .bodyToMono(String.class)
                            .doOnSuccess(response ->
                                log.debug("Successfully retrieved user profile for: {}", email))
                            .onErrorResume(WebClientResponseException.NotFound.class, ex -> {
                                log.warn("User profile not found for email: {}", email);
                                return Mono.empty();
                            })
                            .onErrorResume(WebClientResponseException.class, ex -> {
                                log.error("Failed to get user profile. Status: {}, Response: {}",
                                        ex.getStatusCode(), ex.getResponseBodyAsString());
                                return Mono.error(ex);
                            })
                );
    }

    /**
     * Update user profile with service authentication
     * @param email User email
     * @param userRequest Updated user data
     * @return Mono with response
     */
    public Mono<String> updateUserProfile(String email, UserProfileRequest userRequest) {
        return serviceTokenService.getAccessToken()
                .flatMap(token ->
                    userServiceWebClient.put()
                            .uri(uriBuilder -> uriBuilder
                                    .path("/api/v1/users/{email}")
                                    .build(email))
                            .contentType(MediaType.APPLICATION_JSON)
                            .headers(headers -> headers.setBearerAuth(token))
                            .bodyValue(userRequest)
                            .retrieve()
                            .bodyToMono(String.class)
                            .doOnSuccess(response ->
                                log.info("Successfully updated user profile for: {}", email))
                            .onErrorResume(WebClientResponseException.class, ex -> {
                                log.error("Failed to update user profile. Status: {}, Response: {}",
                                        ex.getStatusCode(), ex.getResponseBodyAsString());
                                return Mono.error(ex);
                            })
                );
    }

    /**
     * Delete user profile with service authentication
     * @param email User email
     * @return Mono with response
     */
    public Mono<Void> deleteUserProfile(String email) {
        return serviceTokenService.getAccessToken()
                .flatMap(token ->
                    userServiceWebClient.delete()
                            .uri(uriBuilder -> uriBuilder
                                    .path("/api/v1/users/{email}")
                                    .build(email))
                            .headers(headers -> headers.setBearerAuth(token))
                            .retrieve()
                            .bodyToMono(Void.class)
                            .doOnSuccess(response ->
                                log.info("Successfully deleted user profile for: {}", email))
                            .onErrorResume(WebClientResponseException.class, ex -> {
                                log.error("Failed to delete user profile. Status: {}, Response: {}",
                                        ex.getStatusCode(), ex.getResponseBodyAsString());
                                return Mono.error(ex);
                            })
                );
    }
}

