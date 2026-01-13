package com.ride.authservice.service;

import com.ride.authservice.dto.UserProfileRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

@Service
@Slf4j
public class UserServiceClient {

    private final RestTemplate restTemplate;
    private final String userServiceUrl;

    public UserServiceClient(RestTemplate restTemplate,
                           @Value("${services.user-service.url}") String userServiceUrl) {
        this.restTemplate = restTemplate;
        this.userServiceUrl = userServiceUrl;
    }

    public void createUserProfile(UserProfileRequest userRequest) {
        try {
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);

            HttpEntity<UserProfileRequest> request = new HttpEntity<>(userRequest, headers);

            // User service has context path /api/users, so we need to append /users for the endpoint
            String url = userServiceUrl + "/api/users/users";
            log.info("Sending user profile creation request to: {}", url);

            ResponseEntity<String> response = restTemplate.postForEntity(url, request, String.class);

            if (response.getStatusCode().is2xxSuccessful()) {
                log.info("User profile created successfully for email: {}", userRequest.getEmail());
            } else {
                log.error("Failed to create user profile. Status: {}, Response: {}",
                         response.getStatusCode(), response.getBody());
            }
        } catch (Exception e) {
            log.error("Error creating user profile for email: {}", userRequest.getEmail(), e);
        }
    }
}
