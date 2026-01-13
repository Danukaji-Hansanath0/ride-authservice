package com.ride.authservice.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Response DTO for email update operation.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class EmailUpdatedResponse {
    private String userId;
    private String newEmail;
    private String message;
    private boolean success;
}
