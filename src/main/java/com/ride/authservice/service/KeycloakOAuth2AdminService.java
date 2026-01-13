package com.ride.authservice.service;


import com.ride.authservice.dto.LoginResponse;

public interface KeycloakOAuth2AdminService {
    LoginResponse getAccessToken();

}
