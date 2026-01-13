package com.ride.authservice.util;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Utility class for PKCE (Proof Key for Code Exchange) operations.
 * Provides methods to generate code verifiers and code challenges for OAuth2 flows.
 */
public class PKCEUtil {

    /**
     * Generates a cryptographically random code verifier.
     * The code verifier is a high-entropy random string between 43-128 characters.
     *
     * @return A base64url-encoded random string
     */
    public static String generateCodeVerifier() {
        byte[] code = new byte[32];
        new SecureRandom().nextBytes(code);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(code);
    }

    /**
     * Generates a cryptographically secure random state parameter for OAuth2 flow.
     * The state parameter prevents CSRF attacks and should be validated in the callback.
     *
     * @return A base64url-encoded random string suitable for OAuth2 state parameter
     */
    public static String generateState() {
        byte[] state = new byte[32];
        new SecureRandom().nextBytes(state);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(state);
    }

    /**
     * Generates a code challenge from a code verifier using SHA-256 hashing.
     * The code challenge is sent to the authorization server, while the code verifier
     * is kept by the client and sent later during token exchange.
     *
     * @param codeVerifier The code verifier to hash
     * @return A base64url-encoded SHA-256 hash of the code verifier
     * @throws RuntimeException if SHA-256 algorithm is not available
     */
    public static String generateCodeChallenge(String codeVerifier) {
        try {
            byte[] bytes = codeVerifier.getBytes(StandardCharsets.US_ASCII);
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(bytes);
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Failed to generate code challenge", e);
        }
    }

    /**
     * Main method for testing and generating PKCE values.
     * Run this to get a code verifier and code challenge for testing.
     */
    public static void main(String[] args) {
        String codeVerifier = generateCodeVerifier();
        String codeChallenge = generateCodeChallenge(codeVerifier);

        System.out.println("=== PKCE Values for Testing ===");
        System.out.println("Code Verifier: " + codeVerifier);
        System.out.println("Code Challenge: " + codeChallenge);
        System.out.println("\nUse these values to test the Google login flow:");
        System.out.println("1. Send the Code Verifier to GET /api/login/google/mobile");
        System.out.println("2. Use the same Code Verifier in POST /api/google/callback/mobile");
        System.out.println("\nExample cURL command:");
        System.out.println("curl -X GET \"http://localhost:8081/api/login/google/mobile?codeVerifier=" + codeVerifier + "&redirectUri=http://localhost:8081/auth/callback\"");
        System.out.println("\nIMPORTANT: The redirectUri must be registered in Keycloak:");
        System.out.println("Keycloak Admin Console -> Clients -> auth2-client -> Valid redirect URIs");
    }
}

