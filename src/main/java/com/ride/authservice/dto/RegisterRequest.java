package com.ride.authservice.dto;

//TODO: Add validation annotations

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
public record RegisterRequest(
        @NotBlank(message = "Email cannot be blank")
        @Email(message = "Invalid email format")
        String email,
        @NotBlank(message = "Password cannot be blank")
        @Size(min = 8, message = "Password must be at least 8 characters long")
        String password,
        @NotBlank(message = "First name cannot be blank")
        @Size(min = 2, max = 50, message = "First name cannot exceed 50 characters")
        String firstName,
        @NotBlank(message = "Last name cannot be blank")
        @Size(min = 2, max = 50, message = "Last name cannot exceed 50 characters")
        String lastName,
        CustomRole role
) {

    //default role to CUSTOMER if not provided
    public RegisterRequest {
        role = role != null ? role : CustomRole.CUSTOMER;
    }
}
