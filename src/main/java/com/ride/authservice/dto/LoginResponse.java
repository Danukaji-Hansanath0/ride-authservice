// java
// File: 'auth-service/src/main/java/com/ride/authservice/dto/LoginResponse.java'
package com.ride.authservice.dto;

public record LoginResponse(
        String accessToken,
        String refreshToken,
        long expiresIn,
        long refreshExpiresIn,
        String tokenType,
        String scope
) {}
