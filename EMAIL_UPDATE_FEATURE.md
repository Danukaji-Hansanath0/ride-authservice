# Email Update Feature Documentation

## Overview
This feature allows authenticated users to update their email address after verifying their current password. The implementation includes JWT token-based authentication and automatic user ID extraction from the session token.

## Features Implemented

### 1. **Email Update Endpoint**
- **Endpoint**: `PUT /api/auth/update-email`
- **Authentication**: Required (JWT Bearer token)
- **Description**: Updates a user's email address after password verification

### 2. **JWT Token Utilities**
- **Class**: `JwtUtil`
- **Location**: `auth-service/src/main/java/com/ride/authservice/util/JwtUtil.java`
- **Functions**:
  - `extractUserIdFromToken(String token)` - Extracts user ID from JWT
  - `extractEmailFromToken(String token)` - Extracts email from JWT
  - `extractUsernameFromToken(String token)` - Extracts username from JWT
  - `isValidTokenFormat(String token)` - Validates JWT format

### 3. **Security Features**
- Password verification before email update
- JWT token validation
- Duplicate email checking
- Email verification required for new email
- Proper error handling and logging

## API Documentation

### Update Email Request

**Endpoint**: `PUT /api/auth/update-email`

**Headers**:
```
Content-Type: application/json
Authorization: Bearer <JWT_ACCESS_TOKEN>
```

**Request Body**:
```json
{
  "email": "current@example.com",
  "newEmail": "new@example.com",
  "password": "CurrentPassword123!"
}
```

**Success Response** (200 OK):
```json
{
  "userId": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "newEmail": "new@example.com",
  "message": "Email updated successfully. Please verify your new email address.",
  "success": true
}
```

**Error Responses**:

*Invalid Password* (400 Bad Request):
```json
{
  "userId": null,
  "newEmail": "new@example.com",
  "message": "Invalid password. Email update failed.",
  "success": false
}
```

*Email Already In Use* (400 Bad Request):
```json
{
  "userId": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "newEmail": "new@example.com",
  "message": "Email address is already in use by another account.",
  "success": false
}
```

*Invalid Token* (401 Unauthorized):
```json
{
  "userId": null,
  "newEmail": "new@example.com",
  "message": "Invalid or expired authentication token.",
  "success": false
}
```

## How It Works

### Flow Diagram

```
1. User sends request with:
   ├── Current email
   ├── New email
   ├── Current password
   └── JWT token in Authorization header

2. Extract User ID from JWT Token
   └── Parse JWT payload to get 'sub' claim

3. Verify Password
   ├── Attempt login with current email & password
   └── If fails → Return "Invalid password"

4. Validate New Email
   ├── Check if user exists
   └── Check if new email already in use

5. Update Email in Keycloak
   ├── Update email field
   ├── Update username field
   └── Set emailVerified to false

6. Send Verification Email
   └── Send to new email address

7. Return Success Response
   └── Include userId, newEmail, and success message
```

### Security Measures

1. **JWT Token Required**: Endpoint requires valid JWT authentication token
2. **Password Verification**: Current password must be correct
3. **User Validation**: Verifies user exists before update
4. **Duplicate Prevention**: Checks if new email is already registered
5. **Email Verification**: New email requires verification
6. **Session Validation**: Token must be valid and not expired

## Code Examples

### Frontend/Client Usage

#### JavaScript/TypeScript Example
```javascript
async function updateEmail(currentEmail, newEmail, password, accessToken) {
  const response = await fetch('http://localhost:8081/api/auth/update-email', {
    method: 'PUT',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${accessToken}`
    },
    body: JSON.stringify({
      email: currentEmail,
      newEmail: newEmail,
      password: password
    })
  });

  const result = await response.json();
  
  if (result.success) {
    console.log('Email updated successfully!');
    console.log('User ID:', result.userId);
    console.log('New Email:', result.newEmail);
    alert(result.message);
  } else {
    console.error('Email update failed:', result.message);
    alert('Failed to update email: ' + result.message);
  }
  
  return result;
}

// Usage example
updateEmail(
  'olduser@example.com',
  'newuser@example.com',
  'MySecurePassword123!',
  'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...'
);
```

#### cURL Example
```bash
# 1. First, login to get JWT token
LOGIN_RESPONSE=$(curl -X POST http://localhost:8081/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "Password123!"
  }')

ACCESS_TOKEN=$(echo $LOGIN_RESPONSE | jq -r '.accessToken')

# 2. Update email with the token
curl -X PUT http://localhost:8081/api/auth/update-email \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -d '{
    "email": "user@example.com",
    "newEmail": "newuser@example.com",
    "password": "Password123!"
  }'
```

#### Java/Spring RestTemplate Example
```java
public EmailUpdatedResponse updateEmail(String currentEmail, String newEmail, 
                                       String password, String accessToken) {
    RestTemplate restTemplate = new RestTemplate();
    HttpHeaders headers = new HttpHeaders();
    headers.setContentType(MediaType.APPLICATION_JSON);
    headers.setBearerAuth(accessToken);
    
    EmailChangeRequest request = new EmailChangeRequest(
        currentEmail, 
        newEmail, 
        password
    );
    
    HttpEntity<EmailChangeRequest> entity = new HttpEntity<>(request, headers);
    
    ResponseEntity<EmailUpdatedResponse> response = restTemplate.exchange(
        "http://localhost:8081/api/auth/update-email",
        HttpMethod.PUT,
        entity,
        EmailUpdatedResponse.class
    );
    
    return response.getBody();
}
```

## Testing

### Run the Test Script
```bash
cd /mnt/projects/Ride/auth-service
./test-email-update.sh
```

### Manual Testing Steps

1. **Register a user**:
```bash
curl -X POST http://localhost:8081/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "Test123!",
    "firstName": "Test",
    "lastName": "User",
    "role": "CUSTOMER"
  }'
```

2. **Login to get JWT token**:
```bash
curl -X POST http://localhost:8081/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "Test123!"
  }'
```

3. **Update email** (use the accessToken from step 2):
```bash
curl -X PUT http://localhost:8081/api/auth/update-email \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN_HERE" \
  -d '{
    "email": "test@example.com",
    "newEmail": "newemail@example.com",
    "password": "Test123!"
  }'
```

## JWT Token Structure

The JWT token contains the following claims:
```json
{
  "sub": "user-id-uuid",           // User ID (extracted by JwtUtil)
  "email": "user@example.com",      // User email
  "preferred_username": "username", // Username
  "exp": 1234567890,                // Expiration time
  "iat": 1234567800,                // Issued at time
  "authorities": ["ROLE_CUSTOMER"]  // User roles
}
```

## Files Modified/Created

### Created Files:
1. `/mnt/projects/Ride/auth-service/src/main/java/com/ride/authservice/util/JwtUtil.java`
   - JWT token parsing and user ID extraction utility

2. `/mnt/projects/Ride/auth-service/test-email-update.sh`
   - Automated test script for the email update feature

### Modified Files:
1. `/mnt/projects/Ride/auth-service/src/main/java/com/ride/authservice/dto/EmailChangeRequest.java`
   - Added Lombok annotations
   - Added documentation

2. `/mnt/projects/Ride/auth-service/src/main/java/com/ride/authservice/dto/EmailUpdatedResponse.java`
   - Added userId and success fields
   - Added Lombok annotations

3. `/mnt/projects/Ride/auth-service/src/main/java/com/ride/authservice/service/impl/KeycloakAdminServiceImpl.java`
   - Implemented `changeUserEmail()` method
   - Added password verification
   - Added duplicate email checking
   - Added email verification sending

4. `/mnt/projects/Ride/auth-service/src/main/java/com/ride/authservice/controller/AuthController.java`
   - Added `updateEmail()` endpoint
   - Added JWT token extraction
   - Added comprehensive error handling

5. `/mnt/projects/Ride/auth-service/src/main/java/com/ride/authservice/config/SecurityConfig.java`
   - Added authentication requirement for `/api/auth/update-email` endpoint

## Configuration

No additional configuration is required. The feature uses existing Keycloak configuration from `application.properties` or `application.yml`:

```yaml
keycloak:
  admin:
    server-url: ${KEYCLOAK_SERVER_URL:http://localhost:9090}
    realm: ${KEYCLOAK_REALM:ride-platform}
    client-id: ${KEYCLOAK_CLIENT_ID:ride-auth-service}
    client-secret: ${KEYCLOAK_CLIENT_SECRET:your-secret}
    token-url: ${KEYCLOAK_TOKEN_URL:http://localhost:9090/realms/ride-platform/protocol/openid-connect/token}
```

## Error Handling

The implementation includes comprehensive error handling:

| Scenario | HTTP Status | Response |
|----------|-------------|----------|
| Success | 200 | EmailUpdatedResponse with success=true |
| Invalid Password | 400 | Error message about invalid password |
| Email Already Exists | 400 | Error message about duplicate email |
| Invalid Token Format | 401 | Error message about invalid token |
| Missing Authentication | 401/403 | Authentication required error |
| User Not Found | 400 | Error message about user not found |
| Server Error | 500 | Error message with exception details |

## Best Practices

1. **Always use HTTPS** in production to protect JWT tokens
2. **Validate token expiration** on the client side
3. **Handle token refresh** when access token expires
4. **Store tokens securely** (not in localStorage for sensitive apps)
5. **Implement rate limiting** to prevent brute force attacks
6. **Log security events** for audit purposes

## Troubleshooting

### Common Issues:

1. **401 Unauthorized Error**
   - Check if JWT token is valid and not expired
   - Ensure "Bearer " prefix is included in Authorization header
   - Verify token was obtained from successful login

2. **Invalid Password Error**
   - Verify the current password is correct
   - Check if user account is locked or disabled
   - Ensure password matches the current account

3. **Email Already Exists Error**
   - Check if the new email is already registered
   - Try a different email address

4. **Token Extraction Failed**
   - Verify JWT token format (should be header.payload.signature)
   - Check if token contains 'sub' claim
   - Ensure token is from the correct Keycloak realm

## Security Considerations

- ✅ Password verification required before email update
- ✅ JWT token authentication required
- ✅ User session validation
- ✅ Duplicate email prevention
- ✅ Email verification required for new address
- ✅ Comprehensive error handling without exposing sensitive information
- ✅ Request logging for security audit
- ✅ Token format validation

## Future Enhancements

Potential improvements for future versions:

1. **Email Change Confirmation**: Send confirmation link to old email before changing
2. **Rate Limiting**: Limit email update requests per time period
3. **Email History**: Track email change history
4. **Multi-factor Authentication**: Require 2FA for email changes
5. **Notification**: Send notification to old email when change occurs
6. **Rollback Feature**: Allow reverting to old email within time window

## Support

For issues or questions:
- Check the logs: `auth-service` container logs
- Review Keycloak admin console for user details
- Use the test script for validation
- Check Spring Security configuration

## License

This feature is part of the Ride Platform project.

