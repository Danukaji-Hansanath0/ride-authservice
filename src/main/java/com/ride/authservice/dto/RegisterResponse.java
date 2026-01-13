package com.ride.authservice.dto;

import java.time.Instant;

public record RegisterResponse(
        String userId,
        String email,
        String firstName,
        String lastName,
        boolean emailVerified,
        Instant createdAt,
        String status
) {}

