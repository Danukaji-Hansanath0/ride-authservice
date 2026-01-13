package com.ride.authservice.service.impl;

import com.ride.authservice.dto.LoginResponse;
import com.ride.authservice.service.KeycloakOAuth2AdminServiceApp;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * Service for handling OAuth2 authentication with Keycloak and Google.
 * Provides endpoints for mobile login using PKCE (Proof Key for Code Exchange).
 *
 * This implementation uses Google's OAuth2 standards with proper scope handling
 * to avoid common issues like invalid_scope errors.
 */
@Slf4j
@Service
public class KeycloakOAuth2AdminServiceAppImpl implements KeycloakOAuth2AdminServiceApp {
    private final String keycloakAuthUrl;
    private final String clientId;
    private final RestTemplate restTemplate;
    private final String keycloakTokenUrl;

    /**
     * Google OAuth2 valid scopes.
     * Note: When using Keycloak's identity provider (kc_idp_hint=google),
     * scopes must be configured in Keycloak Admin Console under:
     * Identity Providers > Google > Settings > Default Scopes
     *
     * The scopes should be: openid email profile
     * (NOT https://www.googleapis.com/auth/userinfo.profile)
     */
    private static final String[] KEYCLOAK_IDP_SCOPES = {
            "openid",
            "email",
            "profile"
    };

    /**
     * Constructor for dependency injection.
     *
     * @param keycloakAuthUrl Keycloak authorization endpoint URL
     * @param clientId Keycloak client ID for OAuth2
     * @param restTemplate RestTemplate for HTTP requests
     * @param keycloakTokenUrl Keycloak token endpoint URL
     */
    public KeycloakOAuth2AdminServiceAppImpl(
            @Value("${keycloak.admin.auth2-client.auth-url}") String keycloakAuthUrl,
            @Value("${keycloak.admin.auth2-client.client-id}") String clientId,
            RestTemplate restTemplate,
            @Value("${keycloak.admin.token-url}") String keycloakTokenUrl
    ) {
        this.clientId = clientId;
        this.keycloakAuthUrl = keycloakAuthUrl;
        this.restTemplate = restTemplate;
        this.keycloakTokenUrl = keycloakTokenUrl;

            }

    /**
     * Generates the Google login URL for mobile clients using PKCE.
     *
     * This method constructs a properly formatted OAuth2 authorization URL with:
     * - PKCE code challenge for security
     * - Google-specific identity provider hint (kc_idp_hint)
     * - State parameter for CSRF protection
     *
     * IMPORTANT: When using kc_idp_hint=google, Keycloak manages the OAuth2 scopes
     * through its Identity Provider configuration. Do NOT include the scope parameter
     * in this URL. Configure scopes in Keycloak Admin Console instead:
     * Identity Providers > Google > Settings > Default Scopes: "openid email profile"
     *
     * @param codeChallenge PKCE code challenge (SHA-256 hash of code verifier)
     * @param redirectUri Redirect URI for the mobile app (must match registered URI)
     * @param state State parameter for CSRF protection (must be validated in callback)
     * @return Complete Google authorization URL
     */
    @Override
    public String getGoogleLoginUrlForMobile(String codeChallenge, String redirectUri, String state) {
        log.debug("Building Google login URL with codeChallenge: {}, redirectUri: {}, state: {}",
                codeChallenge, redirectUri, state);

        // When using kc_idp_hint, Keycloak manages scopes via Identity Provider config
        // Do NOT include scope parameter here
        String url = UriComponentsBuilder.fromUriString(keycloakAuthUrl)
                .queryParam("client_id", clientId)
                .queryParam("redirect_uri", redirectUri)
                .queryParam("response_type", "code")
                .queryParam("kc_idp_hint", "google")
                .queryParam("code_challenge", codeChallenge)
                .queryParam("code_challenge_method", "S256")
                .queryParam("state", state)
                .build()
                .toUriString();

        log.info("Generated Google login URL for mobile with state parameter");

        return url;
    }


    /**
     * Exchanges the authorization code for tokens using PKCE for mobile clients.
     *
     * This method sends a token exchange request to Keycloak with:
     * - The authorization code received from Google
     * - The code verifier (must match the code challenge used earlier)
     * - The same redirect URI used in the authorization request
     *
     * @param code Authorization code from Google (obtained after user authentication)
     * @param codeVerifier PKCE code verifier (must be the same one used to generate code challenge)
     * @param redirectUri Redirect URI for the mobile app (must match the one in auth request)
     * @return LoginResponse containing access_token, refresh_token, and token metadata
     * @throws RuntimeException if token exchange fails
     */
    @Override
    public LoginResponse exchangeGoogleCodeForTokenMobile(String code, String codeVerifier, String redirectUri) {
        log.info("Exchanging authorization code for tokens");
        log.debug("Code: {}, Redirect URI: {}", code, redirectUri);

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "authorization_code");
        form.add("client_id", clientId);
        form.add("code", code);
        form.add("redirect_uri", redirectUri);
        form.add("code_verifier", codeVerifier);

        try {
            LoginResponse response = getLoginResponse(headers, form);
            log.info("Token exchange successful. Access token obtained.");
            return response;
        } catch (Exception e) {
            log.error("Failed to exchange code for token: {}", e.getMessage(), e);
            throw new RuntimeException("Token exchange failed: " + e.getMessage(), e);
        }
    }

    /**
     * Helper method to perform the token exchange HTTP request to Keycloak.
     *
     * Sends a POST request to the Keycloak token endpoint and parses the response.
     *
     * @param headers HTTP headers (must include Content-Type: application/x-www-form-urlencoded)
     * @param form Form data containing OAuth2 parameters (grant_type, code, etc.)
     * @return LoginResponse containing access token, refresh token, and metadata
     * @throws RuntimeException if the HTTP request fails or returns non-200 status
     */
    private LoginResponse getLoginResponse(HttpHeaders headers, MultiValueMap<String, String> form) {
        log.debug("Sending token exchange request to: {}", keycloakTokenUrl);

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(form, headers);

        try {
            ResponseEntity<LoginResponse> response = restTemplate.exchange(
                    keycloakTokenUrl,
                    HttpMethod.POST,
                    request,
                    LoginResponse.class
            );

            if (response.getStatusCode() == HttpStatus.OK && response.getBody() != null) {
                log.debug("Successfully received token response from Keycloak");
                LoginResponse loginResponse = response.getBody();
                log.debug("Token type: {}, Expires in: {} seconds",
                        loginResponse.tokenType(), loginResponse.expiresIn());
                return loginResponse;
            }

            log.error("Unexpected response from Keycloak. Status: {}", response.getStatusCode());
            throw new RuntimeException("Failed to get token from Keycloak. Status: " + response.getStatusCode());

        } catch (Exception e) {
            log.error("Error during token exchange request: {}", e.getMessage(), e);
            throw new RuntimeException("Token exchange request failed: " + e.getMessage(), e);
        }
    }
}