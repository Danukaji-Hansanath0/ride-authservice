package com.ride.authservice.event.handlers;

import com.ride.authservice.event.AbstractEventHandler;
import com.ride.authservice.event.UserCreateEvent;
import org.springframework.stereotype.Component;

@Component
public class EmailNotificationHandler extends AbstractEventHandler<UserCreateEvent> {

    public EmailNotificationHandler() {
        super(UserCreateEvent.class, 1);
    }

    @Override
    public void handle(UserCreateEvent event) {
        // Logic to send email notification
        System.out.println("Sending email notification to " + event.getEmail() + " for user " + event.getName());
    }
}
