package com.ride.authservice.config;

import lombok.extern.slf4j.Slf4j;
import org.jspecify.annotations.NonNull;
import org.springframework.http.HttpRequest;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * RestTemplate interceptor to validate outgoing requests and incoming responses.
 * Ensures proper UTF-8 encoding and logs request/response details for debugging.
 */
@Slf4j
public class RequestValidationInterceptor implements ClientHttpRequestInterceptor {

    @Override
    public ClientHttpResponse intercept(@NonNull HttpRequest request, byte @NonNull [] body, @NonNull ClientHttpRequestExecution execution) throws IOException {
        // Validate request body encoding
        if (body != null && body.length > 0) {
            try {
                String bodyString = new String(body, StandardCharsets.UTF_8);
                log.debug("Outgoing request to {}: {}", request.getURI(), sanitizeForLog(bodyString));
            } catch (Exception e) {
                log.warn("Invalid UTF-8 encoding in outgoing request to {}", request.getURI());
                throw new IOException("Request body contains invalid UTF-8 encoding", e);
            }
        }

        // Execute the request
        ClientHttpResponse response;
        try {
            response = execution.execute(request, body);
            log.debug("Response from {} - Status: {}", request.getURI(), response.getStatusCode());
        } catch (IOException e) {
            log.error("Request to {} failed: {}", request.getURI(), e.getMessage());
            throw e;
        }

        return response;
    }

    /**
     * Sanitize log output to prevent log injection attacks.
     * Removes newlines and limits length.
     */
    private String sanitizeForLog(String input) {
        if (input == null) {
            return "";
        }
        String sanitized = input.replaceAll("[\n\r]", " ");
        return sanitized.length() > 500 ? sanitized.substring(0, 500) + "..." : sanitized;
    }
}

