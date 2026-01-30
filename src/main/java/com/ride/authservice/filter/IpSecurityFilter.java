package com.ride.authservice.filter;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.ride.authservice.service.SecurityEventLogger;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicInteger;

import static com.ride.authservice.exception.GlobalExceptionHandler.getString;

/**
 * Filter to implement IP-based security including rate limiting, blacklisting, and suspicious activity tracking.
 */
@Slf4j
@Component
@Order(2)
public class IpSecurityFilter implements Filter {

    private final SecurityEventLogger securityEventLogger;

    // Cache to track failed attempts per IP
    private final Cache<String, AtomicInteger> failedAttemptsCache;

    // Cache to track blacklisted IPs
    private final Cache<String, Boolean> blacklistCache;

    // Cache to track request counts per IP for rate limiting
    private final Cache<String, AtomicInteger> requestCountCache;

    @Value("${security.ip.max-failed-attempts:10}")
    private int maxFailedAttempts;

    @Value("${security.ip.max-requests-per-minute:60}")
    private int maxRequestsPerMinute;

    @Value("${security.ip.blacklist-duration-minutes:60}")
    private int blacklistDurationMinutes;

    public IpSecurityFilter(SecurityEventLogger securityEventLogger) {
        this.securityEventLogger = securityEventLogger;

        // Initialize caches with Caffeine
        this.failedAttemptsCache = Caffeine.newBuilder()
                .expireAfterWrite(Duration.ofMinutes(15))
                .maximumSize(10_000)
                .build();

        this.blacklistCache = Caffeine.newBuilder()
                .expireAfterWrite(Duration.ofMinutes(blacklistDurationMinutes))
                .maximumSize(1_000)
                .build();

        this.requestCountCache = Caffeine.newBuilder()
                .expireAfterWrite(Duration.ofMinutes(1))
                .maximumSize(10_000)
                .build();
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;

        String clientIp = getClientIp(httpRequest);
        String requestUri = httpRequest.getRequestURI();
        String method = httpRequest.getMethod();

        // Check if IP is blacklisted
        if (isBlacklisted(clientIp)) {
            log.warn("Blocked request from blacklisted IP: {} to {} {}", clientIp, method, requestUri);
            securityEventLogger.logBlacklistedIpAttempt(clientIp, requestUri);
            sendBlockedResponse(httpResponse, "Access denied. IP has been temporarily blocked due to suspicious activity.");
            return;
        }

        // Check rate limit
        if (isRateLimitExceeded(clientIp)) {
            log.warn("Rate limit exceeded for IP: {} on {} {}", clientIp, method, requestUri);
            securityEventLogger.logRateLimitExceeded(clientIp, requestUri);
            sendRateLimitResponse(httpResponse);
            return;
        }

        // Continue with the request
        chain.doFilter(request, response);
    }

    /**
     * Record a failed authentication attempt for an IP address.
     */
    public void recordFailedAttempt(String ip) {
        AtomicInteger attempts = failedAttemptsCache.get(ip, k -> new AtomicInteger(0));
        int count = attempts.incrementAndGet();

        log.debug("Failed attempt recorded for IP {}: {} attempts", ip, count);

        if (count >= maxFailedAttempts) {
            blacklistIp(ip);
            log.warn("IP {} blacklisted after {} failed attempts", ip, count);
            securityEventLogger.logIpBlacklisted(ip, count);
        }
    }

    /**
     * Record a malformed request from an IP address.
     */
    public void recordMalformedRequest(String ip) {
        // Malformed requests count double towards blacklist
        AtomicInteger attempts = failedAttemptsCache.get(ip, k -> new AtomicInteger(0));
        int count = attempts.addAndGet(2);

        log.debug("Malformed request recorded for IP {}: {} attempts", ip, count);

        if (count >= maxFailedAttempts) {
            blacklistIp(ip);
            log.warn("IP {} blacklisted after malformed requests", ip);
            securityEventLogger.logIpBlacklisted(ip, count);
        }
    }

    private boolean isBlacklisted(String ip) {
        return blacklistCache.getIfPresent(ip) != null;
    }

    private void blacklistIp(String ip) {
        blacklistCache.put(ip, Boolean.TRUE);
    }

    private boolean isRateLimitExceeded(String ip) {
        AtomicInteger count = requestCountCache.get(ip, k -> new AtomicInteger(0));
        return count.incrementAndGet() > maxRequestsPerMinute;
    }

    private String getClientIp(HttpServletRequest request) {
        return getString(request);
    }

    private void sendBlockedResponse(HttpServletResponse response, String message) throws IOException {
        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        response.getWriter().write(String.format(
            "{\"error\":true,\"message\":\"%s\",\"timestamp\":%d}",
            message, System.currentTimeMillis()
        ));
    }

    private void sendRateLimitResponse(HttpServletResponse response) throws IOException {
        response.setStatus(429); // Too Many Requests
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        response.setHeader("Retry-After", "60");
        response.getWriter().write(String.format(
            "{\"error\":true,\"message\":\"Rate limit exceeded. Please try again later.\",\"timestamp\":%d}",
            System.currentTimeMillis()
        ));
    }

    public void clearBlacklist(String ip) {
        blacklistCache.invalidate(ip);
        failedAttemptsCache.invalidate(ip);
        log.info("Cleared blacklist for IP: {}", ip);
    }
}

