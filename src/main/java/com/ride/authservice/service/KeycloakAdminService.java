package com.ride.authservice.service;

    import com.ride.authservice.dto.*;

    /**
     * Interface for managing Keycloak administrative operations.
     * Provides methods for user registration, authentication, role assignment,
     * and other user-related operations.
     */
    public interface KeycloakAdminService {

        /**
         * Registers a new user in Keycloak.
         *
         * @param request The registration request containing user details.
         * @return A response object containing registration details.
         */
        RegisterResponse registerUser(RegisterRequest request);

        /**
         * Sends a verification email to the user.
         *
         * @param userId The ID of the user to whom the verification email will be sent.
         */
        void sendVerificationEmail(String userId);

        /**
         * Checks if a user's email is verified.
         *
         * @param userId The ID of the user to check.
         * @return True if the user's email is verified, false otherwise.
         */
        boolean isUserEmailVerified(String userId);

        /**
         * Logs in a user and retrieves authentication tokens.
         *
         * @param request The login request containing user credentials.
         * @return A response object containing authentication tokens.
         */
        LoginResponse loginUser(LoginRequest request);

        /**
         * Assigns a custom role to a user.
         *
         * @param userId The ID of the user to whom the role will be assigned.
         * @param role The custom role to assign to the user.
         */
        void assignRoleToUser(String userId, CustomRole role);

        /**
         * Refreshes the authentication token using a refresh token.
         *
         * @param refreshToken The refresh token to use for generating a new access token.
         * @return A response object containing the new authentication tokens.
         */
        LoginResponse refreshToken(String refreshToken);

        /**
         * Sends a password reset email to the user.
         *
         * @param email The email address of the user to whom the password reset email will be sent.
         */
        void sendPasswordResetEmail(String email);

        EmailUpdatedResponse changeUserEmail(EmailChangeRequest request);

        /**
         * Updates user profile information (firstName, lastName) in Keycloak.
         *
         * @param request The update request containing email, firstName, lastName
         */
        void updateUserProfile(UpdateProfileRequest request);
    }