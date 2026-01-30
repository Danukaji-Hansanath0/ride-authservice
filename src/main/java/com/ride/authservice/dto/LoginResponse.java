package com.ride.authservice.dto;

/**
 * Login response DTO.
 * @param accessToken
 * @param refreshToken
 * @param expiresIn
 * @param refreshExpiresIn
 * @param tokenType
 * @param scope
 * @param firstName
 * @param lastName
 * @param email
 * @param userId
 */

public record LoginResponse(
        String accessToken,
        String refreshToken,
        long expiresIn,
        long refreshExpiresIn,
        String tokenType,
        String scope,
        String firstName,
        String lastName,
        String email,
        String userId, //this user id represent the user-service user id its not the keycloak user id
        String userAvailability,
        boolean isAvtive
) {}
