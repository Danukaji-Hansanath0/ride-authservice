# Google OAuth State Parameter Fix

## Problem: "Missing state parameter in response from identity provider"

### Root Cause
The OAuth2 authorization URL was missing the required `state` parameter, which is:
- **Required by OAuth2 spec** for CSRF protection
- **Required by Keycloak** when using identity provider brokering
- **Required by Google** OAuth2 implementation

### Error Symptoms
```
type="IDENTITY_PROVIDER_LOGIN_ERROR"
error="invalidRequestMessage"
```

Browser shows: "We are sorry... Invalid Request"

## Solution Applied

### 1. Added State Parameter Generation
- Created `PKCEUtil.generateState()` method to generate cryptographically secure random state
- State is returned to the client along with the authorization URL
- Client must store the state and validate it when receiving the callback

### 2. Updated Authorization URL
The authorization URL now includes the state parameter:
```
https://keycloak.orysone.com/realms/user-authentication-realm/protocol/openid-connect/auth
  ?client_id=auth2-client
  &redirect_uri=YOUR_APP_REDIRECT_URI
  &response_type=code
  &kc_idp_hint=google
  &code_challenge=CHALLENGE
  &code_challenge_method=S256
  &state=RANDOM_STATE_VALUE  ← Added this!
```

## How to Use the Fixed Flow

### Step 1: Get Authorization URL
```bash
GET /api/login/google/mobile?codeVerifier=YOUR_CODE_VERIFIER&redirectUri=YOUR_REDIRECT_URI
```

**Response:**
```json
{
  "authorizationUrl": "https://keycloak.orysone.com/...",
  "state": "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"
}
```

**Important:** Save the `state` value! You'll need it in Step 3.

### Step 2: Redirect User to Authorization URL
Open the `authorizationUrl` in a browser or WebView. The user will:
1. Be redirected to Keycloak
2. Keycloak redirects to Google for authentication
3. User authenticates with Google
4. Google redirects back to Keycloak
5. **Keycloak redirects to YOUR_REDIRECT_URI with `code` and `state` parameters**

Example callback:
```
YOUR_REDIRECT_URI?code=AUTH_CODE_HERE&state=a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6
```

### Step 3: Validate State and Exchange Code
**Client-side validation (IMPORTANT!):**
```javascript
// Extract parameters from callback URL
const urlParams = new URLSearchParams(window.location.search);
const code = urlParams.get('code');
const receivedState = urlParams.get('state');
const originalState = localStorage.getItem('oauth_state'); // State from Step 1

// Validate state
if (receivedState !== originalState) {
  throw new Error('Invalid state parameter - possible CSRF attack!');
}

// State is valid, now exchange code for tokens
```

**Then call the backend:**
```bash
POST /api/google/callback/mobile
  ?code=AUTH_CODE_HERE
  &codeVerifier=YOUR_CODE_VERIFIER
  &redirectUri=YOUR_REDIRECT_URI
```

**Response:**
```json
{
  "access_token": "eyJhbGci...",
  "refresh_token": "eyJhbGci...",
  "token_type": "Bearer",
  "expires_in": 300
}
```

## Important Notes

### Redirect URI Configuration
The `redirectUri` parameter must:
- **Point to YOUR application**, not Keycloak's broker endpoint
- Be registered in Keycloak client configuration
- Match exactly in both Step 1 and Step 3

Example valid redirect URIs:
- `http://localhost:3000/callback` (for web apps)
- `myapp://oauth/callback` (for mobile apps)
- `https://yourapp.com/auth/callback` (for production)

### State Parameter Best Practices
1. **Generate unique state for each request** - never reuse
2. **Store state client-side** - in localStorage, sessionStorage, or memory
3. **Validate state in callback** - before calling the backend
4. **Include additional data** - optionally encode JSON with timestamp, nonce, etc.
5. **Set expiration** - reject states older than 10 minutes

Example state with metadata:
```javascript
const state = btoa(JSON.stringify({
  random: crypto.randomUUID(),
  timestamp: Date.now(),
  returnPath: '/dashboard'
}));
```

### Security Considerations
- ✅ **State prevents CSRF attacks** - always validate it
- ✅ **PKCE prevents code interception** - use it for mobile/SPA apps
- ✅ **Never log sensitive parameters** - state, code, code_verifier
- ✅ **Use HTTPS in production** - always
- ✅ **Set short token lifetimes** - especially for access tokens

## Testing

### Using cURL
```bash
# Step 1: Get auth URL
CODE_VERIFIER=$(openssl rand -base64 32 | tr -d '=' | tr '+/' '-_')
REDIRECT_URI="http://localhost:3000/callback"

RESPONSE=$(curl -s "http://localhost:8081/api/login/google/mobile?codeVerifier=$CODE_VERIFIER&redirectUri=$REDIRECT_URI")
AUTH_URL=$(echo $RESPONSE | jq -r '.authorizationUrl')
STATE=$(echo $RESPONSE | jq -r '.state')

echo "Open this URL in browser: $AUTH_URL"
echo "Save this state: $STATE"

# Step 2: After browser redirect, extract code from URL
# Example: http://localhost:3000/callback?code=ABC123&state=XYZ789

# Step 3: Exchange code (after validating state matches)
curl -X POST "http://localhost:8081/api/google/callback/mobile?code=ABC123&codeVerifier=$CODE_VERIFIER&redirectUri=$REDIRECT_URI"
```

### Using the Test Script
```bash
cd auth-service
chmod +x test-google-login.sh
./test-google-login.sh
```

## Troubleshooting

### Error: "Invalid state parameter"
- **Cause:** State doesn't match between request and response
- **Fix:** Ensure you're comparing the exact state value from Step 1

### Error: "Invalid redirect_uri"
- **Cause:** Redirect URI not registered in Keycloak
- **Fix:** Add redirect URI in Keycloak Admin Console → Clients → auth2-client → Valid redirect URIs

### Error: "Invalid code"
- **Cause:** Code expired or already used
- **Fix:** Authorization codes are single-use and expire quickly (usually 60 seconds)

### Error: "PKCE validation failed"
- **Cause:** Code verifier doesn't match code challenge
- **Fix:** Use the same code verifier in Step 1 and Step 3

## Changes Made

### Files Modified
1. ✅ `PKCEUtil.java` - Added `generateState()` method
2. ✅ `KeycloakOAuth2AdminServiceApp.java` - Updated interface signature
3. ✅ `KeycloakOAuth2AdminServiceAppImpl.java` - Added state to authorization URL
4. ✅ `MobileAuthController.java` - Generate and return state to client

### API Changes
- `/api/login/google/mobile` now returns both `authorizationUrl` and `state`
- `/api/google/callback/mobile` expects client-side state validation before calling

## Additional Resources
- [OAuth 2.0 RFC 6749](https://tools.ietf.org/html/rfc6749)
- [PKCE RFC 7636](https://tools.ietf.org/html/rfc7636)
- [Keycloak Documentation](https://www.keycloak.org/docs/latest/securing_apps/)
- [Google OAuth 2.0 Guide](https://developers.google.com/identity/protocols/oauth2)

