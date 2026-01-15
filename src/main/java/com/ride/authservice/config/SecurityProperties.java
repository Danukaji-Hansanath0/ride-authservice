package com.ride.authservice.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.util.ArrayList;
import java.util.List;

/**
 * Configuration properties for security settings including IP filtering, rate limiting, and request validation.
 */
@Data
@Configuration
@ConfigurationProperties(prefix = "security")
public class SecurityProperties {

    private IpSecurityProperties ip = new IpSecurityProperties();
    private RateLimitProperties rateLimit = new RateLimitProperties();
    private RequestValidationProperties requestValidation = new RequestValidationProperties();

    @Data
    public static class IpSecurityProperties {
        /**
         * Maximum failed authentication attempts before IP is blacklisted
         */
        private int maxFailedAttempts = 10;

        /**
         * Maximum requests per minute per IP
         */
        private int maxRequestsPerMinute = 60;

        /**
         * Duration in minutes to blacklist an IP
         */
        private int blacklistDurationMinutes = 60;

        /**
         * IPs to whitelist (never block)
         */
        private List<String> whitelist = new ArrayList<>();

        /**
         * Enable IP-based security filtering
         */
        private boolean enabled = true;
    }

    @Data
    public static class RateLimitProperties {
        /**
         * Rate limit for login endpoint (requests per minute)
         */
        private int loginLimit = 10;

        /**
         * Rate limit for registration endpoint (requests per minute)
         */
        private int registerLimit = 5;

        /**
         * Rate limit for OAuth endpoints (requests per minute)
         */
        private int oauthLimit = 20;

        /**
         * Enable rate limiting
         */
        private boolean enabled = true;
    }

    @Data
    public static class RequestValidationProperties {
        /**
         * Maximum request body size in bytes (default 1MB)
         */
        private int maxRequestSize = 1024 * 1024;

        /**
         * Enable request validation
         */
        private boolean enabled = true;

        /**
         * Enforce UTF-8 encoding
         */
        private boolean enforceUtf8 = true;

        /**
         * Validate JSON structure
         */
        private boolean validateJson = true;
    }
}

