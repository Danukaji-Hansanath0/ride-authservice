package com.ride.authservice.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Request DTO for changing user email.
 * Requires current email, new email, and password for verification.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class EmailChangeRequest {
    private String email;
    private String newEmail;
    private String password;
}
