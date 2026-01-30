package com.ride.authservice.controller;

import com.ride.authservice.dto.LoginResponse;
import com.ride.authservice.service.KeycloakOAuth2AdminServiceApp;
import io.swagger.v3.oas.annotations.Hidden;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

/**
 * OAuth2 callback controller for handling redirect from Keycloak/Google.
 * This provides a clean, stable callback endpoint without fragments or complex URLs.
 */
@RestController
@RequestMapping("/api/v1/auth/oauth2")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "OAuth2 Callback", description = "OAuth2 callback endpoints for authentication flows")
public class OAuth2CallbackController {

    private final KeycloakOAuth2AdminServiceApp keycloakOAuth2Service;

    @Value("${server.port:8081}")
    private String serverPort;

    @Value("${server.host:localhost}")
    private String serverHost;

    /**
     * OAuth2 callback endpoint for Swagger UI.
     * This is where Keycloak redirects after successful Google authentication.
     *
     * IMPORTANT: For Keycloak OAuth2 flow to work correctly:
     * 1. In Keycloak Admin Console, set Valid Redirect URIs to http://localhost:8081/api/v1/auth/oauth2/callback/swagger
     * 2. Do NOT use fragments with # in redirect URIs
     * 3. Make sure Keycloak proxy settings are correct (KC_PROXY=edge, KC_HOSTNAME_STRICT=true)
     * 4. Browser cookies must be preserved across redirects
     *
     * Flow:
     * 1. User clicks Authorize in Swagger UI
     * 2. Redirected to Keycloak then to Google
     * 3. Google authenticates user
     * 4. Google redirects to Keycloak
     * 5. Keycloak redirects HERE with code
     * 6. We exchange code for tokens
     * 7. Redirect to Swagger with token
     *
     * Error Cases from Keycloak logs:
     * - invalid_redirect_uri: Registered URI doesn't match OR session was lost (cookie issue)
     * - clientId=null: Session cookie wasn't sent (HTTPS/SameSite/proxy issue)
     */
    @GetMapping("/callback/swagger")
    @Hidden // Hide from Swagger UI to avoid confusion
    public void handleSwaggerCallback(
            @RequestParam(required = false) String code,
            @RequestParam(required = false) String state,
            @RequestParam(required = false) String error,
            @RequestParam(required = false) String error_description,
            @RequestParam(required = false) String session_state,
            HttpServletResponse response
    ) throws IOException {
        log.info("OAuth2 callback received - code present: {}, state: {}, session_state: {}, error: {}",
                code != null, state, session_state != null, error);

        // Log session information for debugging
        if (error != null && error.contains("invalid_redirect")) {
            log.error("CRITICAL: Invalid redirect URI error from Keycloak");
            log.error("This typically means: 1) URI not registered in Keycloak, OR 2) Session cookie was lost");
            log.error("Solutions: Check Keycloak client Valid Redirect URIs, proxy settings, and HTTPS/SameSite config");
        }

        if (error != null) {
            log.error("OAuth2 error: {} - {}", error, error_description);
            String errorUrl = String.format("http://%s:%s/swagger-ui.html?error=%s&error_description=%s",
                    serverHost, serverPort,
                    URLEncoder.encode(error, StandardCharsets.UTF_8),
                    URLEncoder.encode(error_description != null ? error_description : "Unknown error", StandardCharsets.UTF_8));
            response.sendRedirect(errorUrl);
            return;
        }

        if (code == null) {
            log.error("No code parameter in callback");
            response.sendRedirect(String.format("http://%s:%s/swagger-ui.html?error=no_code", serverHost, serverPort));
            return;
        }

        try {
            // For Swagger UI, we just redirect back with the code
            // Swagger UI will handle the token exchange
            String swaggerRedirect = String.format(
                    "http://%s:%s/swagger-ui/oauth2-redirect.html?code=%s&state=%s",
                    serverHost, serverPort,
                    URLEncoder.encode(code, StandardCharsets.UTF_8),
                    state != null ? URLEncoder.encode(state, StandardCharsets.UTF_8) : ""
            );

            log.info("Redirecting to Swagger OAuth2 redirect handler");
            response.sendRedirect(swaggerRedirect);

        } catch (Exception e) {
            log.error("Error handling OAuth2 callback", e);
            response.sendRedirect(String.format("http://%s:%s/swagger-ui.html?error=callback_error", serverHost, serverPort));
        }
    }

    /**
     * OAuth2 callback endpoint for mobile apps.
     * Mobile apps should call this after receiving the authorization code from Keycloak.
     *
     * @param code Authorization code from Keycloak
     * @param codeVerifier PKCE code verifier
     * @return LoginResponse with access token and refresh token
     */
    @PostMapping("/callback/mobile")
    @Operation(
            summary = "Exchange authorization code for tokens (Mobile)",
            description = "Mobile apps call this endpoint after receiving authorization code from Keycloak"
    )
    public ResponseEntity<LoginResponse> handleMobileCallback(
            @Parameter(description = "Authorization code from Keycloak")
            @RequestParam String code,

            @Parameter(description = "PKCE code verifier")
            @RequestParam String codeVerifier

    ) {
        log.info("Mobile OAuth2 callback - exchanging code for tokens");

        try {
            // Use the actual callback URL that was registered
            String callbackUrl = String.format("http://%s:%s/api/v1/auth/oauth2/callback/mobile", serverHost, serverPort);

            LoginResponse loginResponse = keycloakOAuth2Service.exchangeGoogleCodeForTokenMobile(
                    code,
                    codeVerifier,
                    callbackUrl
            );

            log.info("Token exchange successful for mobile client");
            return ResponseEntity.ok(loginResponse);

        } catch (Exception e) {
            log.error("Error exchanging code for tokens: {}", e.getMessage(), e);
            return ResponseEntity.status(500).build();
        }
    }

    /**
     * Test endpoint to verify OAuth2 callback is accessible.
     */
    @GetMapping("/callback/test")
    @Operation(summary = "Test callback endpoint", description = "Verify callback endpoint is accessible")
    public ResponseEntity<String> testCallback() {
        return ResponseEntity.ok("OAuth2 callback endpoint is working! ✅\n" +
                "Callback URL: http://" + serverHost + ":" + serverPort + "/api/v1/auth/oauth2/callback/swagger");
    }
}
