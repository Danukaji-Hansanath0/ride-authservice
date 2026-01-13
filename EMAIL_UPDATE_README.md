# Email Update Feature - Quick Reference

## What's New

✅ **Email Update Endpoint**: Users can now update their email with password verification  
✅ **JWT User ID Extraction**: Automatically extracts user ID from session tokens  
✅ **Password Verification**: Ensures security by requiring current password  
✅ **Email Verification**: New email requires verification  

## Quick Start

### 1. Login to get JWT token
```bash
curl -X POST http://localhost:8081/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "password": "Password123!"}'
```

### 2. Update Email
```bash
curl -X PUT http://localhost:8081/api/auth/update-email \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{
    "email": "user@example.com",
    "newEmail": "newuser@example.com", 
    "password": "Password123!"
  }'
```

### 3. Run Tests
```bash
cd /mnt/projects/Ride/auth-service
./test-email-update.sh
```

## API Endpoint

**PUT** `/api/auth/update-email`
- **Auth**: Required (JWT Bearer token)
- **Request**: `{ email, newEmail, password }`
- **Response**: `{ userId, newEmail, message, success }`

## Key Files

| File | Purpose |
|------|---------|
| `JwtUtil.java` | JWT token parsing & user ID extraction |
| `AuthController.java` | Email update endpoint |
| `KeycloakAdminServiceImpl.java` | Email update business logic |
| `EmailChangeRequest.java` | Request DTO |
| `EmailUpdatedResponse.java` | Response DTO |
| `test-email-update.sh` | Automated test script |

## Features

- 🔐 **Secure**: Password verification required
- 🎫 **JWT-based**: User ID extracted from token
- ✉️ **Verification**: Email verification sent to new address
- 🛡️ **Protected**: Duplicate email prevention
- 📝 **Logged**: All operations logged for audit

## Documentation

See [EMAIL_UPDATE_FEATURE.md](./EMAIL_UPDATE_FEATURE.md) for complete documentation.

## Testing

```bash
# Run automated tests
./test-email-update.sh

# Or test manually with Postman/curl
# See EMAIL_UPDATE_FEATURE.md for detailed examples
```

## Success Response Example

```json
{
  "userId": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "newEmail": "newemail@example.com",
  "message": "Email updated successfully. Please verify your new email address.",
  "success": true
}
```

## Error Response Example

```json
{
  "userId": null,
  "newEmail": "newemail@example.com",
  "message": "Invalid password. Email update failed.",
  "success": false
}
```

## Security Checklist

- ✅ JWT authentication required
- ✅ Password verification before update
- ✅ Token validation
- ✅ Duplicate email check
- ✅ Email verification for new address
- ✅ Comprehensive error handling

---

**Ready to use!** The feature is fully implemented and tested.

