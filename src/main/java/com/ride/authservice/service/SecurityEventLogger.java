package com.ride.authservice.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

/**
 * Service for logging security-related events with structured JSON logging.
 * Provides a centralized way to track authentication failures, rate limits, suspicious activity, etc.
 */
@Slf4j
@Service
public class SecurityEventLogger {

    private final ObjectMapper objectMapper = new ObjectMapper();

    public void logFailedAuthAttempt(String username, String ip, String reason) {
        logSecurityEvent("FAILED_AUTH_ATTEMPT", Map.of(
            "username", username,
            "ip", ip,
            "reason", reason
        ));
    }

    public void logSuccessfulAuth(String username, String ip) {
        logSecurityEvent("SUCCESSFUL_AUTH", Map.of(
            "username", username,
            "ip", ip
        ));
    }

    public void logRateLimitExceeded(String ip, String endpoint) {
        logSecurityEvent("RATE_LIMIT_EXCEEDED", Map.of(
            "ip", ip,
            "endpoint", endpoint
        ));
    }

    public void logBlacklistedIpAttempt(String ip, String endpoint) {
        logSecurityEvent("BLACKLISTED_IP_ATTEMPT", Map.of(
            "ip", ip,
            "endpoint", endpoint
        ));
    }

    public void logIpBlacklisted(String ip, int failedAttempts) {
        logSecurityEvent("IP_BLACKLISTED", Map.of(
            "ip", ip,
            "failedAttempts", failedAttempts
        ));
    }

    public void logMalformedRequest(String ip, String endpoint, String error) {
        logSecurityEvent("MALFORMED_REQUEST", Map.of(
            "ip", ip,
            "endpoint", endpoint,
            "error", error
        ));
    }

    public void logInvalidToken(String ip, String tokenType, String reason) {
        logSecurityEvent("INVALID_TOKEN", Map.of(
            "ip", ip,
            "tokenType", tokenType,
            "reason", reason
        ));
    }

    public void logKeycloakError(String operation, String error, String ip) {
        logSecurityEvent("KEYCLOAK_ERROR", Map.of(
            "operation", operation,
            "error", error,
            "ip", ip != null ? ip : "unknown"
        ));
    }

    public void logSuspiciousActivity(String ip, String activityType, String details) {
        logSecurityEvent("SUSPICIOUS_ACTIVITY", Map.of(
            "ip", ip,
            "activityType", activityType,
            "details", details
        ));
    }

    public void logOAuth2Error(String provider, String error, String ip) {
        logSecurityEvent("OAUTH2_ERROR", Map.of(
            "provider", provider,
            "error", error,
            "ip", ip != null ? ip : "unknown"
        ));
    }

    /**
     * Core method to log security events with structured JSON format.
     */
    private void logSecurityEvent(String eventType, Map<String, Object> details) {
        try {
            Map<String, Object> event = new HashMap<>();
            event.put("eventType", eventType);
            event.put("timestamp", Instant.now().toString());
            event.put("details", details);

            String jsonLog = objectMapper.writeValueAsString(event);
            log.warn("SECURITY_EVENT: {}", jsonLog);
        } catch (Exception e) {
            log.error("Failed to log security event: {}", e.getMessage());
        }
    }
}

