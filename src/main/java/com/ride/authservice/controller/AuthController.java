package com.ride.authservice.controller;

import com.ride.authservice.dto.*;
import com.ride.authservice.service.KeycloakAdminService;
import com.ride.authservice.util.JwtUtil;
import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/**
 * Controller for handling authentication-related operations.
 * Provides endpoints for user registration, login, token refresh, email verification, and password reset.
 */
@RestController
@RequestMapping("/api")
@AllArgsConstructor
@Slf4j
public class AuthController {

    private final KeycloakAdminService keycloakAdminService;
    private final JwtUtil jwtUtil;

    /**
     * Handles user registration requests.
     *
     * @param request The registration request containing user details.
     * @return A ResponseEntity containing the registration response.
     */
    @PostMapping("/auth/register")
    public ResponseEntity<RegisterResponse> register(@Valid @RequestBody RegisterRequest request) {
        log.info(
                "Received registration request for email: {}, firstName: {}, lastName: {}",
                request.email(),
                request.firstName(),
                request.lastName()
        );
        RegisterResponse response = keycloakAdminService.registerUser(request);
        return ResponseEntity.status(201).body(response);
    }

    /**
     * Handles user login requests.
     *
     * @param request The login request containing user credentials.
     * @return A ResponseEntity containing the login response.
     */
    @PostMapping("/auth/login")
    public ResponseEntity<LoginResponse> login(@Valid @RequestBody @NonNull LoginRequest request) {
        log.info(
                "Received login request for email: {}",
                request.email()
        );
        LoginResponse response = keycloakAdminService.loginUser(request);
        return ResponseEntity.status(200).body(response);
    }

    /**
     * Handles token refresh requests.
     *
     * @param refreshToken The refresh token to generate a new access token.
     * @return A ResponseEntity containing the new login response.
     */
    @PostMapping("/auth/refresh-token")
    public ResponseEntity<LoginResponse> refreshToken(@RequestBody @NonNull String refreshToken) {
        log.info(
                "Received token refresh request"
        );
        LoginResponse response = keycloakAdminService.refreshToken(refreshToken);
        return ResponseEntity.status(200).body(response);
    }

    /**
     * Checks if a user's email is verified.
     *
     * @param userId The ID of the user.
     * @return A ResponseEntity containing the email verification status.
     */
    @GetMapping("/auth/verify-email/{userId}")
    public ResponseEntity<Boolean> isEmailVerified(@PathVariable String userId) {
        log.info(
                "Received email verification status request for userId: {}",
                userId
        );
        boolean isVerified = keycloakAdminService.isUserEmailVerified(userId);
        return ResponseEntity.status(200).body(isVerified);
    }

    /**
     * Sends a verification email to the user.
     *
     * @param userId The ID of the user.
     * @return A ResponseEntity indicating the operation status.
     */
    @GetMapping("/auth/send-verification-email/{userId}")
    public ResponseEntity<Void> sendVerificationEmail(@PathVariable String userId) {
        log.info(
                "Received send verification email request for userId: {}",
                userId
        );
        keycloakAdminService.sendVerificationEmail(userId);
        return ResponseEntity.status(200).build();
    }

    /**
     * Sends a password reset email to the user.
     *
     * @param userId The ID of the user.
     * @return A ResponseEntity indicating the operation status.
     */
    @GetMapping("/auth/password-reset")
    public ResponseEntity<Void> sendPasswordResetEmail(
            @RequestHeader("Authorization") String authHeader,
            @RequestBody PasswordChangeRequest passwordChangeRequest
    ) {
        log.info(
                "Received password reset email request for userId: {}",
                userId
        );
        keycloakAdminService.sendPasswordResetEmail(userId);
        return ResponseEntity.status(200).build();
    }

    /**
     * Updates user's email address after verifying password.
     * Extracts user ID from JWT token in Authorization header.
     *
     * @param authHeader The Authorization header containing the JWT token
     * @param request The email change request containing new email and password for verification
     * @return A ResponseEntity containing the email update response
     */
    @PutMapping("/auth/update-email")
    public ResponseEntity<EmailUpdatedResponse> updateEmail(
            @RequestHeader("Authorization") String authHeader,
            @RequestBody EmailChangeRequest request
    ) {
        log.info("Received email update request from {} to {}", request.getEmail(), request.getNewEmail());

        try {
            // Extract user ID from JWT token
            String userId = jwtUtil.extractUserIdFromToken(authHeader);
            EmailUpdatedResponse response = keycloakAdminService.changeUserEmail(request);

            if (response.isSuccess()) {
                log.info("Email successfully updated for user: {}", userId);
                return ResponseEntity.ok(response);
            } else {
                log.warn("Email update failed: {}", response.getMessage());
                return ResponseEntity.status(400).body(response);
            }

        } catch (IllegalArgumentException e) {
            log.error("Error extracting user ID from token: {}", e.getMessage());
            EmailUpdatedResponse errorResponse = new EmailUpdatedResponse(
                    null,
                    request.getNewEmail(),
                    "Invalid or expired authentication token.",
                    false
            );
            return ResponseEntity.status(401).body(errorResponse);
        } catch (Exception e) {
            log.error("Unexpected error during email update: {}", e.getMessage(), e);
            EmailUpdatedResponse errorResponse = new EmailUpdatedResponse(
                    null,
                    request.getNewEmail(),
                    "An error occurred while updating email: " + e.getMessage(),
                    false
            );
            return ResponseEntity.status(500).body(errorResponse);
        }
    }

    @PutMapping("/auth/change-email")
    public ResponseEntity<EmailUpdatedResponse> changeEmail(@RequestBody EmailChangeRequest request) {
        log.info(
                "Received email change request for email: {}",
                request.getEmail()
        );
        EmailUpdatedResponse response = keycloakAdminService.changeUserEmail(request);
        return ResponseEntity.status(200).body(response);
    }
}