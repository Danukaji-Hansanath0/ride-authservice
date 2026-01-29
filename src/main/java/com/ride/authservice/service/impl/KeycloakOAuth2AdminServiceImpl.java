package com.ride.authservice.service.impl;

import com.ride.authservice.dto.LoginResponse;
import com.ride.authservice.service.KeycloakOAuth2AdminService;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@AllArgsConstructor
public class KeycloakOAuth2AdminServiceImpl implements KeycloakOAuth2AdminService {

    @Override
    public LoginResponse getAccessToken() {
        return new LoginResponse(
                "accessTokenValue",
                "refreshTokenValue",
                3600,
                7200,
                "Bearer",
                "openid profile email",
                "John",
                "Doe",
                "johndoe@mail.com",
                "user-service-user-id",
                "AVAILABLE",
                true
        );
    }
}
