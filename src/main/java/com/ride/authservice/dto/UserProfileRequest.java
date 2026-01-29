package com.ride.authservice.dto;

import lombok.*;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class UserProfileRequest {
    private String userId;      // Keycloak user ID
    private String email;
    private String firstName;
    private String lastName;
    private String phoneNumber;
    private String profilePictureUrl;
    private boolean isActive;
    private boolean isVerified;
}
