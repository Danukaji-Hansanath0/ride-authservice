package com.ride.authservice.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;


/**
 * Filter to validate incoming HTTP requests for proper encoding, content type, and size limits.
 * Protects against malformed requests, invalid UTF-8, and oversized payloads.
 */
@Slf4j
@Component
@Order(1)
public class RequestValidationFilter implements Filter {

    private static final int MAX_REQUEST_SIZE = 1024 * 1024; // 1MB
    private static final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;

        String requestUri = httpRequest.getRequestURI();
        String method = httpRequest.getMethod();
        String contentType = httpRequest.getContentType();

        try {
            // Validate content type for POST/PUT requests
            if (("POST".equals(method) || "PUT".equals(method)) && contentType != null) {
                if (!isValidContentType(contentType)) {
                    log.warn("Invalid content type from {}: {}", getClientIp(httpRequest), contentType);
                    sendErrorResponse(httpResponse, HttpServletResponse.SC_UNSUPPORTED_MEDIA_TYPE,
                        "Unsupported content type. Expected application/json or application/x-www-form-urlencoded");
                    return;
                }
            }

            // Validate content length
            int contentLength = httpRequest.getContentLength();
            if (contentLength > MAX_REQUEST_SIZE) {
                log.warn("Request too large from {}: {} bytes", getClientIp(httpRequest), contentLength);
                sendErrorResponse(httpResponse, HttpServletResponse.SC_REQUEST_ENTITY_TOO_LARGE,
                    "Request payload too large");
                return;
            }

            // Validate character encoding
            String encoding = httpRequest.getCharacterEncoding();
            if (encoding != null && !StandardCharsets.UTF_8.name().equalsIgnoreCase(encoding)) {
                log.warn("Invalid character encoding from {}: {}", getClientIp(httpRequest), encoding);
                sendErrorResponse(httpResponse, HttpServletResponse.SC_BAD_REQUEST,
                    "Invalid character encoding. Only UTF-8 is supported");
                return;
            }

            // Wrap request for potential body validation
            CachedBodyHttpServletRequest cachedRequest = new CachedBodyHttpServletRequest(httpRequest);

            // Validate JSON structure if content type is JSON
            if (contentType != null && contentType.contains(MediaType.APPLICATION_JSON_VALUE)) {
                if (!validateJsonBody(cachedRequest)) {
                    log.warn("Invalid JSON from {}: malformed structure", getClientIp(httpRequest));
                    sendErrorResponse(httpResponse, HttpServletResponse.SC_BAD_REQUEST,
                        "Invalid JSON structure");
                    return;
                }
            }

            // Log successful validation
            log.debug("Request validation passed for {} {} from {}", method, requestUri, getClientIp(httpRequest));

            chain.doFilter(cachedRequest, response);

        } catch (Exception e) {
            log.error("Error during request validation for {} {}: {}", method, requestUri, e.getMessage());
            sendErrorResponse(httpResponse, HttpServletResponse.SC_BAD_REQUEST,
                "Request validation failed");
        }
    }

    private boolean isValidContentType(String contentType) {
        return contentType.contains(MediaType.APPLICATION_JSON_VALUE) ||
               contentType.contains(MediaType.APPLICATION_FORM_URLENCODED_VALUE) ||
               contentType.contains(MediaType.MULTIPART_FORM_DATA_VALUE);
    }

    private boolean validateJsonBody(CachedBodyHttpServletRequest request) {
        try {
            byte[] body = request.getCachedBody();
            if (body == null || body.length == 0) {
                return true; // Empty body is valid
            }

            // Try to parse as UTF-8 string
            String bodyString = new String(body, StandardCharsets.UTF_8);

            // Check for common malformed patterns
            if (bodyString.trim().isEmpty()) {
                return true;
            }

            // Validate it's valid JSON by trying to parse it
            objectMapper.readTree(bodyString);
            return true;

        } catch (Exception e) {
            log.debug("JSON validation failed: {}", e.getMessage());
            return false;
        }
    }

    private String getClientIp(HttpServletRequest request) {
        String ip = request.getHeader("X-Forwarded-For");
        if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getHeader("X-Real-IP");
        }
        if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getRemoteAddr();
        }
        return ip != null ? ip.split(",")[0].trim() : "unknown";
    }

    private void sendErrorResponse(HttpServletResponse response, int status, String message) throws IOException {
        response.setStatus(status);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());

        Map<String, Object> errorBody = new HashMap<>();
        errorBody.put("error", true);
        errorBody.put("message", message);
        errorBody.put("timestamp", System.currentTimeMillis());

        response.getWriter().write(objectMapper.writeValueAsString(errorBody));
    }
}

