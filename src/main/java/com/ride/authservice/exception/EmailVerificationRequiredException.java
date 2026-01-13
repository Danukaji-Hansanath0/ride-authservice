package com.ride.authservice.exception;

public class EmailVerificationRequiredException extends RuntimeException {
    public EmailVerificationRequiredException(String message) {
        super(message);
    }
}
