package com.ride.authservice.dto;

import lombok.*;

/**
 * Request DTO for updating user profile information (firstName, lastName).
 * Email is used as the identifier to find the user in Keycloak.
 */
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class UpdateProfileRequest {
    private String email;       // User identifier
    private String firstName;   // New first name
    private String lastName;    // New last name
    private String phoneNumber; // New phone number
}
