#!/bin/bash

# Google Login Testing Script
# This script helps you test the Google OAuth2 login flow with PKCE

echo "=========================================="
echo "Google Login with PKCE - Test Script"
echo "=========================================="
echo ""

# Configuration
BASE_URL="http://localhost:8081"
# IMPORTANT: This redirect_uri must be registered in Keycloak Admin Console
# Go to: Clients -> auth2-client -> Settings -> Valid redirect URIs
# Add: http://localhost:8081/auth/callback (or your mobile app's custom scheme)
REDIRECT_URI="http://localhost:8081/auth/callback"

# For mobile apps, use a custom scheme like:
# REDIRECT_URI="myapp://oauth/callback"

# Step 1: Generate Code Verifier (using openssl for random bytes)
echo "Step 1: Generating Code Verifier..."
CODE_VERIFIER=$(openssl rand -base64 32 | tr -d '=' | tr '+/' '-_')
echo "Code Verifier: $CODE_VERIFIER"
echo ""

# Step 2: Get Authorization URL
echo "Step 2: Getting Authorization URL..."
echo "Making request to: $BASE_URL/api/login/google/mobile"
RESPONSE=$(curl -s -X GET "$BASE_URL/api/login/google/mobile?codeVerifier=$CODE_VERIFIER&redirectUri=$REDIRECT_URI")
AUTH_URL=$(echo $RESPONSE | jq -r '.authorizationUrl')

if [ "$AUTH_URL" == "null" ] || [ -z "$AUTH_URL" ]; then
    echo "Error: Failed to get authorization URL"
    echo "Response: $RESPONSE"
    exit 1
fi

echo "Authorization URL: $AUTH_URL"
echo ""

# Step 3: Instructions for manual authentication
echo "=========================================="
echo "Step 3: Manual Authentication Required"
echo "=========================================="
echo ""
echo "1. Open the following URL in your browser:"
echo ""
echo "$AUTH_URL"
echo ""
echo "2. Complete the Google login process"
echo "3. After authentication, you'll be redirected to a URL that contains a 'code' parameter"
echo "4. Copy the value of the 'code' parameter from the URL"
echo "5. Run the following command with the code you copied:"
echo ""
echo "curl -X POST \"$BASE_URL/api/google/callback/mobile?code=YOUR_CODE_HERE&codeVerifier=$CODE_VERIFIER&redirectUri=$REDIRECT_URI\""
echo ""
echo "=========================================="
echo ""
echo "Tip: The authorization code expires quickly (usually within 60 seconds),"
echo "     so complete the exchange as soon as possible."
echo ""

# Optional: Open the URL in the default browser (uncomment to enable)
# xdg-open "$AUTH_URL" 2>/dev/null || open "$AUTH_URL" 2>/dev/null || echo "Could not auto-open browser"

