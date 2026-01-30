package com.ride.authservice.service.impl;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ride.authservice.dto.*;
import com.ride.authservice.event.EventPublisher;
import com.ride.authservice.event.UserCreateEvent;
import com.ride.authservice.exception.AuthenticationFailedException;
import com.ride.authservice.exception.EmailVerificationRequiredException;
import com.ride.authservice.exception.NotFoundException;
import com.ride.authservice.exception.ServiceOperationException;
import com.ride.authservice.service.KeycloakAdminService;
import com.ride.authservice.service.UserServiceClientWebClient;
import jakarta.ws.rs.core.Response;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;import org.keycloak.OAuth2Constants;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.admin.client.resource.UsersResource;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.keycloak.util.JsonSerialization.mapper;

/**
 * Implementation of the KeycloakAdminService interface.
 * Provides methods for user management, authentication, and role assignment using Keycloak.
 */
@Service
@Slf4j
@SuppressWarnings("unused") // EventPublisher will be used when event publishing is enabled
public class KeycloakAdminServiceImpl implements KeycloakAdminService {
    private final RestTemplate restTemplate = new RestTemplate();
    private final String realm;
    private final Keycloak keycloak;
    private final String tokenUrl;
    private final String clientId;
    private final String clientSecret;
    private final EventPublisher eventPublisher;
    private final UserServiceClientWebClient userServiceClientWebClient;

    /**
     * Constructor for initializing KeycloakAdminServiceImpl with required configurations.
     *
     * @param serverUrl    The Keycloak server URL.
     * @param realm        The Keycloak realm name.
     * @param clientId     The Keycloak client ID.
     * @param clientSecret The Keycloak client secret.
     * @param tokenUrl     The Keycloak token endpoint URL.
     * @param eventPublisher The event publisher for publishing domain events.
     */
    public KeycloakAdminServiceImpl(
            @Value("${keycloak.admin.server-url}") String serverUrl,
            @Value("${keycloak.admin.realm}") String realm,
            @Value("${keycloak.admin.client-id}") String clientId,
            @Value("${keycloak.admin.client-secret}") String clientSecret,
            @Value("${keycloak.admin.token-url}") String tokenUrl,
            EventPublisher eventPublisher,
            UserServiceClientWebClient userServiceClientWebClient
    ) {
        this.realm = realm;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.tokenUrl = tokenUrl;
        this.eventPublisher = eventPublisher;
        this.userServiceClientWebClient = userServiceClientWebClient;
        this.keycloak = KeycloakBuilder.builder()
                .serverUrl(serverUrl)
                .realm(realm)
                .clientId(clientId)
                .clientSecret(clientSecret)
                .grantType(OAuth2Constants.CLIENT_CREDENTIALS)
                .build();
    }

    /**
     * Registers a new user in Keycloak.
     *
     * @param request The registration request containing user details.
     * @return A RegisterResponse object with the registration result.
     */
    @Override
    public RegisterResponse registerUser(RegisterRequest request) {
        RealmResource resource = keycloak.realm(realm);
        UsersResource users = resource.users();

        // Check if the role is allowed for registration
        List<CustomRole> allowedRegistrationRoles = List.of(
                CustomRole.CUSTOMER, CustomRole.DRIVER,
                CustomRole.CAR_OWNER, CustomRole.PLATFORM_ADMIN,
                CustomRole.FRANCHISE_ADMIN
        );
        if (!allowedRegistrationRoles.contains(request.role())) {
            return new RegisterResponse(
                    null,
                    request.email(),
                    request.firstName(),
                    request.lastName(),
                    false,
                    Instant.now(),
                    "INVALID_ROLE_FOR_REGISTRATION"
            );
        }

        UserRepresentation user = getUserRepresentation(request);

        try (Response response = users.create(user)) {
            int status = response.getStatus();
            if (status == 201) {
                String userId = response.getLocation().getPath().replaceAll(".*/([^/]+)$", "$1");
                assignRoleToUser(userId, request.role());

                // Send verification email to the newly registered user
                try {
                    sendVerificationEmail(userId);
                    log.info("Verification email sent successfully to user: {} ({})", userId, request.email());
                } catch (Exception emailException) {
                    log.error("Failed to send verification email to user {} ({}): {}",
                             userId, request.email(), emailException.getMessage());
                }

                // Publish UserCreateEvent for successful user creation
                UserCreateEvent userCreateEvent = UserCreateEvent.create(
                        userId,
                        request.email(),
                        request.firstName() + " " + request.lastName()
                );
                eventPublisher.publish(userCreateEvent);

                return new RegisterResponse(
                        userId,
                        request.email(),
                        request.firstName(),
                        request.lastName(),
                        false,
                        Instant.now(),
                        "USER_CREATED"
                );
            } else if (status == 403) {
                String errorMessage = "Keycloak client does not have permission to create users. " +
                        "Please ensure the client '" + keycloak.tokenManager().getAccessTokenString() +
                        "' has 'manage-users' role assigned from realm-management.";
                return new RegisterResponse(
                        null,
                        request.email(),
                        request.firstName(),
                        request.lastName(),
                        false,
                        Instant.now(),
                        "PERMISSION_DENIED: " + errorMessage
                );
            } else if (status == 409) {
                return new RegisterResponse(
                        null,
                        request.email(),
                        request.firstName(),
                        request.lastName(),
                        false,
                        Instant.now(),
                        "USER_ALREADY_EXISTS"
                );
            } else {
                String errorBody = response.hasEntity() ? response.readEntity(String.class) : "No error details";
                return new RegisterResponse(
                        null,
                        request.email(),
                        request.firstName(),
                        request.lastName(),
                        false,
                        Instant.now(),
                        "USER_CREATION_FAILED_WITH_STATUS_" + status + ": " + errorBody
                );
            }
        } catch (Exception e) {
            return new RegisterResponse(
                    null,
                    request.email(),
                    request.firstName(),
                    request.lastName(),
                    false,
                    Instant.now(),
                    "USER_CREATION_FAILED: " + e.getClass().getSimpleName() + " - " + e.getMessage()
            );
        }
    }

    /**
     * Creates a UserRepresentation object from the registration request.
     *
     * @param request The registration request.
     * @return A UserRepresentation object.
     */
    private static @NonNull UserRepresentation getUserRepresentation(@org.jspecify.annotations.NonNull RegisterRequest request) {
        UserRepresentation user = new UserRepresentation();
        user.setUsername(request.email());
        user.setEmail(request.email());
        user.setFirstName(request.firstName());
        user.setLastName(request.lastName());
        user.setEnabled(true);
        user.setEmailVerified(false);

        CredentialRepresentation cred = new CredentialRepresentation();
        cred.setTemporary(false);
        cred.setType(CredentialRepresentation.PASSWORD);
        cred.setValue(request.password());
        user.setCredentials(List.of(cred));
        return user;
    }

    /**
     * Sends a verification email to the user.
     *
     * @param userId The ID of the user.
     */
    @Override
    public void sendVerificationEmail(String userId) {
        try {
            RealmResource realmResource = keycloak.realm(realm);
            UserResource usersResource = realmResource.users().get(userId);

            // Check if user exists
            UserRepresentation user = usersResource.toRepresentation();
            if (user == null) {
                log.error("User not found with ID: {}", userId);
                throw new NotFoundException("User not found with ID: " + userId);
            }

            // Check if email is already verified
            if (user.isEmailVerified()) {
                log.info("Email already verified for user: {} ({})", userId, user.getEmail());
                return;
            }

            log.info("Sending verification email to user: {} ({})", userId, user.getEmail());
            usersResource.sendVerifyEmail();
            log.info("Verification email sent successfully to user: {} ({})", userId, user.getEmail());

        } catch (NotFoundException e) {
            throw e;
        } catch (Exception e) {
            log.error("Failed to send verification email to user: {}", userId, e);
            throw new ServiceOperationException("Failed to send verification email: " + e.getMessage(), e);
        }
    }

    /**
     * Checks if the user's email is verified.
     *
     * @param userId The ID of the user.
     * @return True if the email is verified, false otherwise.
     */
    @Override
    public boolean isUserEmailVerified(String userId) {
        try {
            RealmResource realmResource = keycloak.realm(realm);
            UserResource usersResource = realmResource.users().get(userId);
            UserRepresentation user = usersResource.toRepresentation();

            if (user == null) {
                log.error("User not found with ID: {}", userId);
                throw new NotFoundException("User not found with ID: " + userId);
            }

            boolean isVerified = user.isEmailVerified();
            log.info("Email verification status for user {} ({}): {}",
                    userId, user.getEmail(), isVerified);
            return isVerified;

        } catch (NotFoundException e) {
            throw e;
        } catch (Exception e) {
            log.error("Failed to check email verification status for user: {}", userId, e);
            throw new ServiceOperationException("Failed to check email verification status: " + e.getMessage(), e);
        }
    }

    /**
     * Logs in a user and retrieves authentication tokens.
     *
     * @param request The login request containing user credentials.
     * @return A LoginResponse object with authentication tokens.
     */
    @Override
    public LoginResponse loginUser(@org.jspecify.annotations.NonNull LoginRequest request) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", OAuth2Constants.PASSWORD);
        form.add("client_id", clientId);
        form.add("client_secret", clientSecret);
        form.add("username", request.email());
        form.add("password", request.password());
        Map<String , Object> mapData = new HashMap<>();

        try {
            // Try to get user profile from user-service (optional - for additional data)
            try {
                // Fetch profile JSON string reactively and block with timeout-safe default
                String profileJson = userServiceClientWebClient
                        .getUserProfile(request.email())
                        .blockOptional()
                        .orElse(null);

                if (profileJson != null && !profileJson.isBlank()) {
                    ObjectMapper mapper1 = new ObjectMapper();
                    JsonNode jsonNode = mapper1.readTree(profileJson);

                    // Extract data with null-safe checks
                    JsonNode firstNameNode = jsonNode.get("firstName");
                    JsonNode lastNameNode = jsonNode.get("lastName");
                    JsonNode uidNode = jsonNode.get("uid");
                    JsonNode emailNode = jsonNode.get("email");
                    JsonNode phoneNode = jsonNode.get("phoneNumber");
                    JsonNode availNode = jsonNode.get("userAvailability");
                    JsonNode activeNode = jsonNode.get("isActive");

                    mapData.put("firstName", firstNameNode != null ? firstNameNode.asText("") : "");
                    mapData.put("lastName", lastNameNode != null ? lastNameNode.asText("") : "");
                    mapData.put("uid", uidNode != null ? uidNode.asText("") : "");
                    mapData.put("email", emailNode != null ? emailNode.asText("") : "");
                    mapData.put("phoneNumber", phoneNode != null ? phoneNode.asText("") : "");
                    mapData.put("userAvailability", availNode != null ? availNode.asText("OFFLINE") : "OFFLINE");
                    mapData.put("isActive", activeNode != null && activeNode.asBoolean(false));

                    log.info("✅ User profile loaded from user-service for email: {}", request.email());
                } else {
                    log.warn("⚠️ User profile not available from user-service for email: {} (continuing)", request.email());
                    mapData.put("firstName", "");
                    mapData.put("lastName", "");
                    mapData.put("uid", "");
                    mapData.put("email", "");
                    mapData.put("phoneNumber", "");
                    mapData.put("userAvailability", "OFFLINE");
                    mapData.put("isActive", false);
                }
            } catch (Exception e) {
                log.warn("⚠️ Could not retrieve user profile from user-service (non-blocking): {}", e.getMessage());
                // Continue with empty user data - profile sync may not be complete yet
                mapData.put("firstName", "");
                mapData.put("lastName", "");
                mapData.put("uid", "");
                mapData.put("email", "");
                mapData.put("phoneNumber", "");
                mapData.put("userAvailability", "OFFLINE");
                mapData.put("isActive", false);
            }

            return getLoginResponse(headers, form, mapData);
        } catch (HttpClientErrorException e) {
            String body = e.getResponseBodyAsString();
            int statusCode = e.getStatusCode().value();

            if (body.contains("Account is not fully set up") || body.contains("invalid_grant")) {
                throw new EmailVerificationRequiredException("Email verification required. Please verify your email before logging in.");
            }

            if (statusCode == 401) {
                if (body.contains("Invalid user credentials") || body.contains("invalid_grant")) {
                    throw new AuthenticationFailedException("Invalid credentials. Please check your email and password.");
                }
                throw new AuthenticationFailedException("Authentication failed. Please check your credentials.");
            }

            if (statusCode == 400) {
                if (body.contains("invalid_client")) {
                    throw new AuthenticationFailedException("Authentication service configuration error. Please contact support.");
                }
                throw new AuthenticationFailedException("Invalid login request. Please check your input.");
            }

            throw new AuthenticationFailedException("Login failed: " + statusCode + " - " + body);
        } catch (Exception e) {
            throw new AuthenticationFailedException("Login error: " + e.getMessage(), e);
        }
    }

    /**
     * Assigns a role to a user in Keycloak.
     *
     * @param userId The ID of the user.
     * @param role   The role to assign.
     */
    @Override
    public void assignRoleToUser(String userId, CustomRole role) {
        RealmResource realmResource = keycloak.realm(realm);
        UserResource userResource = realmResource.users().get(userId);

        try {
            // Get the role by name from Keycloak
            RoleRepresentation roleRepresentation = realmResource.roles()
                    .get(role.name())
                    .toRepresentation();

            // Assign the role to the user
            userResource.roles().realmLevel().add(List.of(roleRepresentation));
        } catch (Exception e) {
            throw new ServiceOperationException("Failed to assign role " + role.name() + " to user: " + e.getMessage(), e);
        }
    }

    /**
     * Refreshes the authentication token using a refresh token.
     *
     * @param refreshToken The refresh token.
     * @return A LoginResponse object with new authentication tokens.
     */
    @Override
    public LoginResponse refreshToken(String refreshToken) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", OAuth2Constants.REFRESH_TOKEN);
        form.add("client_id", clientId);
        form.add("client_secret", clientSecret);
        form.add("refresh_token", refreshToken);

        try {
            return getLoginResponse(headers, form, new HashMap<>());
        } catch (Exception e) {
            throw new AuthenticationFailedException("Token refresh error: " + e.getMessage(), e);
        }
    }

    /**
     * Sends a password reset email to the user.
     *
     * @param email The email address of the user.
     */
    @Override
    public void sendPasswordResetEmail(String email) {
        RealmResource realmResource = keycloak.realm(realm);
        UsersResource users = realmResource.users();
        List<UserRepresentation> found = users.search(email, 0, 1);
        if (found.isEmpty()) {
            throw new NotFoundException("User with email " + email + " not found.");
        }
        String userId = found.getFirst().getId();
        users.get(userId).executeActionsEmail(
                null,
                null,
                null,
                List.of("UPDATE_PASSWORD")
        );
    }

    /**
     * Changes the user's email address after verifying their password.
     *
     * @param request The email change request containing current email, new email, and password
     * @return EmailUpdatedResponse with the result of the operation
     */
    @Override
    public EmailUpdatedResponse changeUserEmail(EmailChangeRequest request) {
        try {
            // Step 1: Verify the user's password by attempting to login
            LoginRequest loginRequest = new LoginRequest(request.getEmail(), request.getPassword());
            try {
                loginUser(loginRequest);
            } catch (Exception e) {
                log.error("Password verification failed for email: {}", request.getEmail());
                return new EmailUpdatedResponse(
                        null,
                        request.getNewEmail(),
                        "Invalid password. Email update failed.",
                        false
                );
            }

            // Step 2: Find the user by current email
            RealmResource realmResource = keycloak.realm(realm);
            UsersResource usersResource = realmResource.users();
            List<UserRepresentation> users = usersResource.search(request.getEmail(), 0, 1);

            if (users.isEmpty()) {
                log.error("User not found with email: {}", request.getEmail());
                return new EmailUpdatedResponse(
                        null,
                        request.getNewEmail(),
                        "User not found.",
                        false
                );
            }

            String userId = users.getFirst().getId();

            // Step 3: Check if new email is already in use
            List<UserRepresentation> existingUsers = usersResource.search(request.getNewEmail(), 0, 1);
            if (!existingUsers.isEmpty() && !existingUsers.getFirst().getId().equals(userId)) {
                log.error("Email already in use: {}", request.getNewEmail());
                return new EmailUpdatedResponse(
                        userId,
                        request.getNewEmail(),
                        "Email address is already in use by another account.",
                        false
                );
            }

            // Step 4: Get the user resource and retrieve fresh representation
            UserResource userResource = usersResource.get(userId);
            UserRepresentation userToUpdate = userResource.toRepresentation();

            // Update only the necessary fields
            userToUpdate.setEmail(request.getNewEmail());
            userToUpdate.setUsername(request.getNewEmail());
            userToUpdate.setEmailVerified(false); // Require email verification for the new email

            // Perform the update with proper error handling
            try {
                userResource.update(userToUpdate);
                log.info("Email successfully updated for user {}: {} -> {}",
                         userId, request.getEmail(), request.getNewEmail());
            } catch (jakarta.ws.rs.BadRequestException e) {
                log.error("Bad request when updating email for user {}: {}", userId, e.getMessage());
                // Try updating email only without changing username
                try {
                    userToUpdate = userResource.toRepresentation();
                    userToUpdate.setEmail(request.getNewEmail());
                    userToUpdate.setEmailVerified(false);
                    userResource.update(userToUpdate);
                    log.info("Email updated (username unchanged) for user {}: {} -> {}",
                             userId, request.getEmail(), request.getNewEmail());
                } catch (Exception retryException) {
                    log.error("Failed to update email even without username change: {}", retryException.getMessage());
                    return new EmailUpdatedResponse(
                            userId,
                            request.getNewEmail(),
                            "Failed to update email. Please try again or contact support.",
                            false
                    );
                }
            } catch (Exception e) {
                log.error("Unexpected error updating user {}: {}", userId, e.getMessage(), e);
                return new EmailUpdatedResponse(
                        userId,
                        request.getNewEmail(),
                        "Failed to update email: " + e.getMessage(),
                        false
                );
            }

            // Step 5: Send verification email to the new email address
            try {
                sendVerificationEmail(userId);
                log.info("Verification email sent to new email: {}", request.getNewEmail());
            } catch (Exception emailException) {
                log.warn("Failed to send verification email to new email {}: {}",
                         request.getNewEmail(), emailException.getMessage());
            }

            return new EmailUpdatedResponse(
                    userId,
                    request.getNewEmail(),
                    "Email updated successfully. Please verify your new email address.",
                    true
            );

        } catch (AuthenticationFailedException e) {
            log.error("Authentication failed for email: {}", request.getEmail());
            return new EmailUpdatedResponse(
                    null,
                    request.getNewEmail(),
                    "Invalid password. Email update failed.",
                    false
            );
        } catch (Exception e) {
            log.error("Error updating email from {} to {}: {}",
                      request.getEmail(), request.getNewEmail(), e.getMessage(), e);
            return new EmailUpdatedResponse(
                    null,
                    request.getNewEmail(),
                    "Failed to update email: " + e.getMessage(),
                    false
            );
        }
    }


    /**
     * Helper method to send an HTTP request to Keycloak and parse the response.
     *
     * @param headers The HTTP headers.
     * @param form    The form data for the request.
     * @return A LoginResponse object with authentication tokens.
     * @throws JsonProcessingException If there is an error parsing the response.
     */
    @NonNull
    private LoginResponse getLoginResponse(HttpHeaders headers, MultiValueMap<String, String> form, Map<String,Object> data) throws JsonProcessingException {
        ResponseEntity<String> response = restTemplate.postForEntity(tokenUrl, new HttpEntity<>(form, headers), String.class);
        JsonNode json = mapper.readTree(response.getBody());

        // Extract user data with null-safe handling
        String firstName = data != null && data.get("firstName") != null ? data.get("firstName").toString() : "";
        String lastName = data != null && data.get("lastName") != null ? data.get("lastName").toString() : "";
        String email = data != null && data.get("email") != null ? data.get("email").toString() : "";
        String uid = data != null && data.get("uid") != null ? data.get("uid").toString() : "";
        String userAvailability = data != null && data.get("userAvailability") != null ? data.get("userAvailability").toString() : "OFFLINE";
        boolean isActive = data != null && data.get("isActive") != null && Boolean.parseBoolean(data.get("isActive").toString());

        return new LoginResponse(
                json.path("access_token").asText(null),
                json.path("refresh_token").asText(null),
                json.path("expires_in").asLong(0),
                json.path("refresh_expires_in").asLong(0),
                json.path("token_type").asText(null),
                json.path("scope").asText(null),
                firstName,
                lastName,
                email,
                uid,
                userAvailability,
                isActive
        );
    }

    /**
     * Updates user profile information (firstName, lastName) in Keycloak.
     *
     * @param request The update request containing email, firstName, lastName
     */
    @Override
    public void updateUserProfile(UpdateProfileRequest request) {
        try {
            RealmResource resource = keycloak.realm(realm);
            UsersResource users = resource.users();
            List<UserRepresentation> matches = users.search(request.getEmail(), true);
            if (matches == null || matches.isEmpty()) {
                throw new NotFoundException("User not found with email: " + request.getEmail());
            }
            UserRepresentation userRep = matches.getFirst();
            userRep.setFirstName(request.getFirstName());
            userRep.setLastName(request.getLastName());
            users.get(userRep.getId()).update(userRep);
            log.info("Updated Keycloak profile for {}", request.getEmail());

            // Also update the user-service profile to keep data in sync
            try {
                UserProfileRequest userProfileRequest = UserProfileRequest.builder()
                        .email(request.getEmail())
                        .firstName(request.getFirstName())
                        .lastName(request.getLastName())
                        .phoneNumber(request.getPhoneNumber())
                        .build();

                userServiceClientWebClient.updateUserProfile(request.getEmail(), userProfileRequest)
                        .blockOptional();
                log.info("Updated user-service profile for {}", request.getEmail());
            } catch (Exception clientEx) {
                log.warn("Failed to update user-service profile for {}: {}", request.getEmail(), clientEx.getMessage());
            }
        } catch (NotFoundException e) {
            throw e;
        } catch (Exception e) {
            log.error("Failed to update profile for {}: {}", request.getEmail(), e.getMessage(), e);
            throw new ServiceOperationException("Error updating Keycloak profile", e);
        }
    }
}
