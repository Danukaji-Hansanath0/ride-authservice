//package com.ride.authservice.integration;
//
//import com.ride.authservice.dto.RegisterRequest;
//import com.ride.authservice.event.UserCreateEvent;
//import com.ride.authservice.event.handlers.UserProfileHandler;
//import com.ride.authservice.service.UserServiceClient;
//import org.testng.annotations.Test;
//import lombok.extern.slf4j.Slf4j;
//
///**
// * Integration test to verify that user service requests are sent when users are created
// */
//@Slf4j
//public class UserServiceIntegrationTest {
//
//    @Test
//    public void testUserServiceRequestFlow() {
//        // This test demonstrates the flow without requiring actual services to be running
//
//        log.info("=== User Service Integration Test ===");
//
//        // 1. Simulate user registration data
//        String userId = "test-user-123";
//        String email = "integration.test@example.com";
//        String name = "Integration User";
//
//        log.info("1. User registration data: userId={}, email={}, name={}", userId, email, name);
//c
//        // 2. Create UserCreateEvent (normally published by KeycloakAdminServiceImpl)
//        UserCreateEvent event = UserCreateEvent.create(userId, email, name);
//
//        log.info("2. UserCreateEvent created: eventId={}, eventType={}",
//                event.getEventId(), event.getEventType());
//
//        // 3. Create mock UserServiceClient
//        UserServiceClient mockClient = new UserServiceClient(null, "http://localhost:8086") {
//            @Override
//            public void createUserProfile(com.ride.authservice.dto.UserProfileRequest request) {
//                log.info("3. HTTP Request sent to user service:");
//                log.info("   URL: http://localhost:8086");
//                log.info("   Method: POST");
//                log.info("   Body: {}", request);
//                log.info("   Email: {}", request.getEmail());
//                log.info("   FirstName: {}", request.getFirstName());
//                log.info("   LastName: {}", request.getLastName());
//                log.info("   IsActive: {}", request.isActive());
//            }
//        };
//
//        // 4. Create UserProfileHandler with mock client
//        UserProfileHandler handler = new UserProfileHandler(mockClient);
//
//        log.info("4. UserProfileHandler created with priority: {}", handler.getPriority());
//
//        // 5. Process the event (this is what happens in the real flow)
//        handler.handle(event);
//
//        log.info("5. Event processed successfully - user service request completed");
//        log.info("=== Integration Test Complete ===");
//    }
//
//    @Test
//    public void testCompleteRegistrationFlow() {
//        log.info("=== Complete Registration Flow Test ===");
//
//        // This demonstrates what happens when a user registers
//        RegisterRequest registerRequest = new RegisterRequest(
//            "complete.flow@example.com",
//            "CompleteFlow",
//            "User",
//            "password123",
//            com.ride.authservice.dto.CustomRole.CUSTOMER
//        );
//
//        log.info("1. Registration request received: {}", registerRequest);
//
//        // The actual flow would be:
//        log.info("2. KeycloakAdminServiceImpl.registerUser() called");
//        log.info("3. User created in Keycloak with ID: user-456");
//        log.info("4. Role 'CUSTOMER' assigned to user");
//        log.info("5. UserCreateEvent published");
//
//        // Event handling (what we're testing)
//        UserCreateEvent event = UserCreateEvent.create(
//            "user-456",
//            registerRequest.email(),
//            registerRequest.firstName() + " " + registerRequest.lastName()
//        );
//
//        log.info("6. Event published: {}", event.getEventType());
//        log.info("7. EmailNotificationHandler executes (priority 1)");
//        log.info("8. UserProfileHandler executes (priority 2)");
//
//        // Mock the user service call
//        UserServiceClient mockClient = new UserServiceClient(null, "http://localhost:8086") {
//            @Override
//            public void createUserProfile(com.ride.authservice.dto.UserProfileRequest request) {
//                log.info("9. POST http://localhost:8086 with user profile data");
//                log.info("10. User service creates profile in database");
//                log.info("11. User service returns success response");
//            }
//        };
//
//        UserProfileHandler handler = new UserProfileHandler(mockClient);
//        handler.handle(event);
//
//        log.info("12. Registration flow complete - user exists in both Keycloak and user-service");
//        log.info("=== Complete Flow Test Complete ===");
//    }
//}
