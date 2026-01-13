package com.ride.authservice.event;

import lombok.Getter;

import java.time.LocalDateTime;
import java.util.UUID;

@Getter
public abstract class BaseEvent {
    private final String eventId;
    private final LocalDateTime timeStamp;
    private final String eventType;

    protected BaseEvent(String eventType) {
        this.eventId = UUID.randomUUID().toString();
        this.timeStamp = LocalDateTime.now();
        this.eventType = eventType;
    }
}
