package com.ride.authservice.util;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.Base64;

/**
 * Utility class for JWT token operations.
 * Provides methods to extract user information from JWT tokens.
 */
@Component
@Slf4j
public class JwtUtil {

    private final ObjectMapper objectMapper = new ObjectMapper();

    /**
     * Extracts the user ID (subject) from a JWT access token.
     *
     * @param token The JWT access token (with or without "Bearer " prefix)
     * @return The user ID (sub claim) from the token
     * @throws IllegalArgumentException if token is invalid or user ID cannot be extracted
     */
    public String extractUserIdFromToken(String token) {
        try {
            // Remove "Bearer " prefix if present
            String cleanToken = token.startsWith("Bearer ") ? token.substring(7) : token;

            // Split the token into parts (header.payload.signature)
            String[] parts = cleanToken.split("\\.");
            if (parts.length != 3) {
                throw new IllegalArgumentException("Invalid JWT token format");
            }

            // Decode the payload (second part)
            String payload = new String(Base64.getUrlDecoder().decode(parts[1]));

            // Parse JSON and extract subject (user ID)
            JsonNode jsonNode = objectMapper.readTree(payload);
            String userId = jsonNode.path("sub").asText();

            if (userId == null || userId.isEmpty()) {
                throw new IllegalArgumentException("User ID (sub) not found in token");
            }

            log.debug("Extracted user ID from token: {}", userId);
            return userId;

        } catch (Exception e) {
            log.error("Error extracting user ID from token: {}", e.getMessage());
            throw new IllegalArgumentException("Failed to extract user ID from token: " + e.getMessage(), e);
        }
    }

    /**
     * Extracts the email from a JWT access token.
     *
     * @param token The JWT access token (with or without "Bearer " prefix)
     * @return The email from the token, or null if not present
     */
    public String extractEmailFromToken(String token) {
        try {
            String cleanToken = token.startsWith("Bearer ") ? token.substring(7) : token;
            String[] parts = cleanToken.split("\\.");
            if (parts.length != 3) {
                return null;
            }

            String payload = new String(Base64.getUrlDecoder().decode(parts[1]));
            JsonNode jsonNode = objectMapper.readTree(payload);
            return jsonNode.path("email").asText(null);

        } catch (Exception e) {
            log.error("Error extracting email from token: {}", e.getMessage());
            return null;
        }
    }

    /**
     * Extracts the username from a JWT access token.
     *
     * @param token The JWT access token (with or without "Bearer " prefix)
     * @return The username (preferred_username claim) from the token, or null if not present
     */
    public String extractUsernameFromToken(String token) {
        try {
            String cleanToken = token.startsWith("Bearer ") ? token.substring(7) : token;
            String[] parts = cleanToken.split("\\.");
            if (parts.length != 3) {
                return null;
            }

            String payload = new String(Base64.getUrlDecoder().decode(parts[1]));
            JsonNode jsonNode = objectMapper.readTree(payload);
            return jsonNode.path("preferred_username").asText(null);

        } catch (Exception e) {
            log.error("Error extracting username from token: {}", e.getMessage());
            return null;
        }
    }

    /**
     * Validates if a token is properly formatted.
     *
     * @param token The JWT token to validate
     * @return true if the token has a valid JWT format, false otherwise
     */
    public boolean isValidTokenFormat(String token) {
        try {
            String cleanToken = token.startsWith("Bearer ") ? token.substring(7) : token;
            String[] parts = cleanToken.split("\\.");
            return parts.length == 3;
        } catch (Exception e) {
            return false;
        }
    }
}

