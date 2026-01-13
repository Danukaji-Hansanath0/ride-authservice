package com.ride.authservice.event.handlers;

import com.ride.authservice.dto.UserProfileRequest;
import com.ride.authservice.event.AbstractEventHandler;
import com.ride.authservice.event.UserCreateEvent;
import com.ride.authservice.messaging.UserProfileMessageProducer;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

@Component
@Slf4j
public class UserProfileHandler extends AbstractEventHandler<UserCreateEvent> {

    private final UserProfileMessageProducer messageProducer;

    public UserProfileHandler(UserProfileMessageProducer messageProducer) {
        super(UserCreateEvent.class, 2);
        this.messageProducer = messageProducer;
    }

    @Override
    public void handle(UserCreateEvent event) {
        try {
            log.info("Processing user profile creation for user: {} with email: {}",
                    event.getName(), event.getEmail());

            // Extract first and last name from the full name
            String[] nameParts = event.getName().split(" ", 2);
            String firstName = nameParts[0];
            String lastName = nameParts.length > 1 ? nameParts[1] : "";

            // Create user profile request
            UserProfileRequest userRequest = UserProfileRequest.builder()
                    .email(event.getEmail())
                    .firstName(firstName)
                    .lastName(lastName)
                    .phoneNumber(null) // Not available in the event
                    .profilePictureUrl(null) // Default null
                    .isActive(true) // New users are active by default
                    .build();

            // Send message to queue instead of direct HTTP call
            // This ensures the message is persisted even if user-service is down
            messageProducer.sendUserProfileCreationMessage(userRequest);

            log.info("User profile creation message queued successfully for: {}", event.getEmail());

        } catch (Exception e) {
            log.error("Failed to queue user profile creation for user: {} with email: {}",
                     event.getName(), event.getEmail(), e);
        }
    }
}
