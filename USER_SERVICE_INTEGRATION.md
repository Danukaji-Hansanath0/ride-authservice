# User Service Integration for User Profile Creation

## Overview
This implementation enables the auth-service to automatically send HTTP requests to the user-service to create user profiles when new users are registered. The integration is event-driven using the existing UserCreateEvent system.

## Architecture Flow

```
User Registration → KeycloakAdminService → UserCreateEvent → UserProfileHandler → UserServiceClient → HTTP POST → UserService
```

### Detailed Flow:
1. **User Registration**: User registers through `/api/auth/register` endpoint
2. **User Creation**: `KeycloakAdminServiceImpl.registerUser()` creates user in Keycloak
3. **Event Publishing**: `UserCreateEvent` is published with user details
4. **Event Handling**: `UserProfileHandler` receives the event (priority 2)
5. **HTTP Request**: `UserServiceClient` sends POST request to user-service
6. **Profile Creation**: User-service creates the user profile in its database

## Implementation Components

### 1. Configuration ✅
**application.yml**
```yaml
services:
  user-service:
    url: ${USER_SERVICE_URL:http://localhost:8086}
```

### 2. DTOs ✅
**UserProfileRequest.java**
```java
@Builder
public class UserProfileRequest {
    private String email;
    private String firstName;
    private String lastName;
    private String phoneNumber;
    private String profilePictureUrl;
    private boolean isActive;
}
```

### 3. HTTP Client Service ✅
**UserServiceClient.java**
- Handles HTTP communication with user-service
- Uses `RestTemplate` for HTTP requests
- Sends POST requests to create user profiles
- Includes error handling and logging

### 4. Event Handler ✅
**UserProfileHandler.java**
- Listens for `UserCreateEvent`
- Transforms event data into `UserProfileRequest`
- Calls `UserServiceClient` to send HTTP request
- Executes with priority 2 (after email notifications)

### 5. RestTemplate Configuration ✅
**RestTemplateConfig.java**
- Provides `RestTemplate` bean for dependency injection
- Enables HTTP client functionality

## Request/Response Details

### HTTP Request to User Service
```http
POST http://localhost:8086
Content-Type: application/json

{
  "email": "user@example.com",
  "firstName": "John",
  "lastName": "Doe",
  "phoneNumber": null,
  "profilePictureUrl": null,
  "isActive": true
}
```

### User Service Endpoint
- **URL**: `http://localhost:8086` (configured via `USER_SERVICE_URL` environment variable)
- **Method**: POST
- **Controller**: `UserController.addUser(UserRequest userRequest)`
- **Response**: Returns `UserResponse` with created user details

## Data Mapping

| UserCreateEvent | → | UserProfileRequest |
|-----------------|---|-------------------|
| email | → | email |
| name (split) | → | firstName |
| name (split) | → | lastName |
| N/A | → | phoneNumber (null) |
| N/A | → | profilePictureUrl (null) |
| N/A | → | isActive (true) |

## Error Handling

### UserServiceClient
- HTTP errors are caught and logged
- Non-2xx responses are logged as errors
- Network exceptions are handled gracefully
- Failed requests don't break user registration flow

### UserProfileHandler
- Wraps all operations in try-catch
- Logs success and failure events
- Ensures event handling doesn't throw exceptions

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `USER_SERVICE_URL` | `http://localhost:8086` | Base URL for user service |

## Docker Compose Integration

The user service runs on port 8086 as configured in docker-compose.yml:
```yaml
user-service:
  ports:
    - "8086:8086"
  environment:
    - SERVER_PORT=8086
```

## Logging

### Success Flow:
```
INFO - Processing user profile creation for user: John Doe with email: user@example.com
INFO - Sending user profile creation request to: http://localhost:8086
INFO - User profile created successfully for email: user@example.com
INFO - User profile creation request sent successfully for: user@example.com
```

### Error Flow:
```
ERROR - Error creating user profile for email: user@example.com
ERROR - Failed to process user profile creation for user: John Doe with email: user@example.com
```

## Testing

### Manual Testing:
1. **Start Services**: Start both auth-service and user-service
2. **Register User**: POST to `/api/auth/register` with valid user data
3. **Check Logs**: Verify HTTP request is sent to user-service
4. **Verify Creation**: Check user-service database for created profile

### Example Registration Request:
```bash
curl -X POST http://localhost:8081/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "firstName": "John",
    "lastName": "Doe",
    "password": "password123",
    "role": "CUSTOMER"
  }'
```

## Integration Benefits

### 1. **Automatic Synchronization** 🔄
- User profiles are automatically created when users register
- No manual intervention required
- Consistent data across services

### 2. **Event-Driven Architecture** 📡
- Loose coupling between auth-service and user-service
- Easy to extend with additional services
- Asynchronous processing doesn't block registration

### 3. **Error Resilience** 🛡️
- User registration succeeds even if profile creation fails
- Proper error logging for debugging
- Graceful degradation

### 4. **Configurable** ⚙️
- Service URL configurable via environment variables
- Works in different deployment environments
- Easy to switch between local/staging/production

## Future Enhancements

### 1. **Retry Logic**
- Implement retry mechanism for failed HTTP requests
- Exponential backoff for temporary failures

### 2. **Circuit Breaker**
- Add circuit breaker pattern to prevent cascading failures
- Fallback mechanisms when user-service is unavailable

### 3. **Message Queue**
- Replace HTTP calls with message queue (RabbitMQ, Kafka)
- Better reliability and decoupling

### 4. **Authentication**
- Add service-to-service authentication
- JWT tokens or API keys for secure communication

## Troubleshooting

### Common Issues:

1. **Connection Refused**
   - Check if user-service is running
   - Verify USER_SERVICE_URL configuration
   - Check network connectivity

2. **HTTP 404 Not Found**
   - Verify user-service controller endpoint
   - Check if user-service is properly deployed

3. **JSON Parsing Errors**
   - Verify UserProfileRequest matches UserRequest structure
   - Check Content-Type headers

4. **Event Not Triggered**
   - Verify EventConfig is registering handlers
   - Check if UserCreateEvent is being published
   - Confirm Spring component scanning

## Summary

The integration successfully enables automatic user profile creation in the user-service when users register through the auth-service. The implementation is robust, configurable, and follows event-driven architecture principles for loose coupling between services.
