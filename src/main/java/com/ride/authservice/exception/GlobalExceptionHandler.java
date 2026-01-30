package com.ride.authservice.exception;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.ride.authservice.filter.IpSecurityFilter;
import com.ride.authservice.service.SecurityEventLogger;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.jspecify.annotations.NonNull;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.client.RestClientException;
import org.springframework.web.context.request.WebRequest;

import java.nio.charset.CharacterCodingException;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler {

    @Autowired(required = false)
    private SecurityEventLogger securityEventLogger;

    @Autowired(required = false)
    private IpSecurityFilter ipSecurityFilter;

    private ResponseEntity<ApiError> build(HttpStatus status, String message, String path, List<String> details) {
        ApiError error = ApiError.builder()
                .timestamp(OffsetDateTime.now())
                .status(status.value())
                .error(status.getReasonPhrase())
                .message(message)
                .path(path)
                .traceId(UUID.randomUUID().toString())
                .details(details)
                .build();
        return ResponseEntity.status(status).body(error);
    }

    @ExceptionHandler(NotFoundException.class)
    public ResponseEntity<ApiError> handleNotFound(NotFoundException ex, WebRequest request) {
        return build(HttpStatus.NOT_FOUND, ex.getMessage(), getPath(request), null);
    }

    @ExceptionHandler(BadRequestException.class)
    public ResponseEntity<ApiError> handleBadRequest(BadRequestException ex, WebRequest request) {
        return build(HttpStatus.BAD_REQUEST, ex.getMessage(), getPath(request), null);
    }

    @ExceptionHandler(UnauthorizedException.class)
    public ResponseEntity<ApiError> handleUnauthorized(UnauthorizedException ex, WebRequest request) {
        return build(HttpStatus.UNAUTHORIZED, ex.getMessage(), getPath(request), null);
    }

    @ExceptionHandler(ForbiddenException.class)
    public ResponseEntity<ApiError> handleForbidden(ForbiddenException ex, WebRequest request) {
        return build(HttpStatus.FORBIDDEN, ex.getMessage(), getPath(request), null);
    }

    @ExceptionHandler(ConflictException.class)
    public ResponseEntity<ApiError> handleConflict(ConflictException ex, WebRequest request) {
        return build(HttpStatus.CONFLICT, ex.getMessage(), getPath(request), null);
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiError> handleValidation(MethodArgumentNotValidException ex, WebRequest request) {
        List<String> details = ex.getBindingResult().getAllErrors().stream()
                .map(error -> {
                    if (error instanceof FieldError fe) {
                        return fe.getField() + ": " + fe.getDefaultMessage();
                    }
                    return error.getDefaultMessage();
                })
                .collect(Collectors.toList());
        return build(HttpStatus.BAD_REQUEST, "Validation failed", getPath(request), details);
    }

    @ExceptionHandler(AuthenticationFailedException.class)
    public ResponseEntity<ApiError> handleAuthenticationFailed(AuthenticationFailedException ex, WebRequest request) {
        log.warn("Authentication failed: {}", ex.getMessage());
        return build(HttpStatus.UNAUTHORIZED, ex.getMessage(), getPath(request), null);
    }

    @ExceptionHandler(EmailVerificationRequiredException.class)
    public ResponseEntity<ApiError> handleEmailVerificationRequired(EmailVerificationRequiredException ex, WebRequest request) {
        log.warn("Email verification required: {}", ex.getMessage());
        return build(HttpStatus.FORBIDDEN, ex.getMessage(), getPath(request), null);
    }

    @ExceptionHandler(ServiceOperationException.class)
    public ResponseEntity<ApiError> handleServiceOperation(ServiceOperationException ex, WebRequest request) {
        log.error("Service operation failed: {}", ex.getMessage(), ex);
        return build(HttpStatus.INTERNAL_SERVER_ERROR, "Service operation failed. Please try again later.", getPath(request), null);
    }

    @ExceptionHandler(RuntimeException.class)
    public ResponseEntity<ApiError> handleRuntimeException(RuntimeException ex, WebRequest request) {
        log.error("Runtime exception occurred", ex);

        // Handle specific runtime exceptions with better error messages
        String message = ex.getMessage();
        if (message != null) {
            if (message.contains("Keycloak login failed: 401")) {
                return build(HttpStatus.UNAUTHORIZED, "Invalid credentials. Please check your email and password.", getPath(request), null);
            }
            if (message.contains("Email verification required")) {
                return build(HttpStatus.FORBIDDEN, "Email verification required. Please verify your email before logging in.", getPath(request), null);
            }
            if (message.contains("Keycloak login failed")) {
                return build(HttpStatus.BAD_REQUEST, "Login failed. Please try again.", getPath(request), null);
            }
        }

        return build(HttpStatus.INTERNAL_SERVER_ERROR, "An unexpected error occurred during processing", getPath(request), null);
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<ApiError> handleHttpMessageNotReadable(HttpMessageNotReadableException ex, WebRequest request, HttpServletRequest servletRequest) {
        String clientIp = getClientIp(servletRequest);
        log.warn("Malformed request from IP {}: {}", clientIp, ex.getMessage());

        if (securityEventLogger != null) {
            securityEventLogger.logMalformedRequest(clientIp, getPath(request), "Invalid JSON or HTTP message");
        }

        if (ipSecurityFilter != null) {
            ipSecurityFilter.recordMalformedRequest(clientIp);
        }

        return build(HttpStatus.BAD_REQUEST, "Invalid request format. Please check your request body.", getPath(request), null);
    }

    @ExceptionHandler(JsonProcessingException.class)
    public ResponseEntity<ApiError> handleJsonProcessing(JsonProcessingException ex, WebRequest request, HttpServletRequest servletRequest) {
        String clientIp = getClientIp(servletRequest);
        log.warn("JSON processing error from IP {}: {}", clientIp, ex.getMessage());

        if (securityEventLogger != null) {
            securityEventLogger.logMalformedRequest(clientIp, getPath(request), "Invalid JSON structure");
        }

        if (ipSecurityFilter != null) {
            ipSecurityFilter.recordMalformedRequest(clientIp);
        }

        return build(HttpStatus.BAD_REQUEST, "Invalid JSON format", getPath(request), null);
    }

    @ExceptionHandler(CharacterCodingException.class)
    public ResponseEntity<ApiError> handleCharacterCoding(CharacterCodingException ex, WebRequest request, HttpServletRequest servletRequest) {
        String clientIp = getClientIp(servletRequest);
        log.warn("Character encoding error from IP {}: {}", clientIp, ex.getMessage());

        if (securityEventLogger != null) {
            securityEventLogger.logMalformedRequest(clientIp, getPath(request), "Invalid character encoding");
        }

        if (ipSecurityFilter != null) {
            ipSecurityFilter.recordMalformedRequest(clientIp);
        }

        return build(HttpStatus.BAD_REQUEST, "Invalid character encoding. Only UTF-8 is supported.", getPath(request), null);
    }

    @ExceptionHandler(RestClientException.class)
    public ResponseEntity<ApiError> handleRestClientException(RestClientException ex, WebRequest request) {
        log.error("Keycloak communication error: {}", ex.getMessage(), ex);

        if (securityEventLogger != null) {
            securityEventLogger.logKeycloakError("rest_client_call", ex.getMessage(), "server");
        }

        // Check for specific Keycloak errors
        String message = ex.getMessage();
        if (message != null) {
            if (message.contains("401")) {
                return build(HttpStatus.UNAUTHORIZED, "Authentication failed", getPath(request), null);
            }
            if (message.contains("400")) {
                return build(HttpStatus.BAD_REQUEST, "Invalid request to authentication service", getPath(request), null);
            }
        }

        return build(HttpStatus.SERVICE_UNAVAILABLE, "Authentication service is temporarily unavailable. Please try again.", getPath(request), null);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiError> handleGeneric(Exception ex, WebRequest request) {
        log.error("Unhandled exception", ex);
        return build(HttpStatus.INTERNAL_SERVER_ERROR, "An unexpected error occurred", getPath(request), null);
    }

    private String getPath(WebRequest request) {
        return request.getDescription(false).replace("uri=", "");
    }

    private String getClientIp(HttpServletRequest request) {
        if (request == null) {
            return "unknown";
        }
        return getString(request);
    }

    @NonNull
    public static String getString(HttpServletRequest request) {
        String ip = request.getHeader("X-Forwarded-For");
        if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getHeader("X-Real-IP");
        }
        if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getRemoteAddr();
        }
        return ip != null ? ip.split(",")[0].trim() : "unknown";
    }
}

