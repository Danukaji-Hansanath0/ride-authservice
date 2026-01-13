package com.ride.authservice.config;

import com.ride.authservice.event.*;
import com.ride.authservice.event.handlers.*;
import jakarta.annotation.PostConstruct;
import org.springframework.context.annotation.Configuration;
import java.util.List;

@Configuration
public class EventConfig {

    private final EventPublisher eventPublisher;
    private final List<EventHandler<?>> eventHandlers;

    public EventConfig(EventPublisher eventPublisher, List<EventHandler<?>> eventHandlers) {
        this.eventPublisher = eventPublisher;
        this.eventHandlers = eventHandlers;
    }

    @PostConstruct
    public void configureEventHandlers() {
        eventHandlers.forEach(this::registerHandler);
    }

    @SuppressWarnings("unchecked")
    private void registerHandler(EventHandler<?> handler) {
        if (handler instanceof AbstractEventHandler) {
            // For UserCreateEvent handlers, register them with UserCreateEvent.class
            if (handler instanceof EmailNotificationHandler || handler instanceof UserProfileHandler) {
                eventPublisher.subscribe(UserCreateEvent.class, (EventHandler<UserCreateEvent>) handler);
            }
        }
    }

    // Remove unused method
    // private Class<?> getEventType(EventHandler<?> handler) {
    //     return UserCreateEvent.class;
    // }
}