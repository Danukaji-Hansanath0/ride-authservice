package com.ride.authservice.event;

import lombok.Getter;

import java.time.LocalDateTime;

@Getter
public class UserCreateEvent extends BaseEvent {

    private final String userId;
    private final String email;
    private final String name;

    public UserCreateEvent(String userId, String email, String name) {
        super("USER_CREATED");
        this.userId = userId;
        this.email = email;
        this.name = name;
    }

    public static UserCreateEvent create(String userId, String email, String name) {
        return new UserCreateEvent(userId, email, name);
    }
}
