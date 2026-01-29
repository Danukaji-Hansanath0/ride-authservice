package com.ride.authservice.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
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

    @NotBlank(message = "Current email is required")
    @Email(message = "Current email must be a valid email address")
    private String email;

    @NotBlank(message = "New email is required")
    @Email(message = "New email must be a valid email address")
    private String newEmail;

    @NotBlank(message = "Password is required")
    @Size(min = 6, message = "Password must be at least 6 characters")
    private String password;
}
