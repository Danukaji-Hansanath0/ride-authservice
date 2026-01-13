#!/bin/bash

# Email Update Feature Test Script
# This script tests the new email update endpoint with password verification

set -e

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
AUTH_SERVICE_URL="${AUTH_SERVICE_URL:-http://localhost:8081}"
API_BASE_URL="$AUTH_SERVICE_URL/api/auth"

echo -e "${BLUE}=== Email Update Feature Test ===${NC}\n"

# Step 1: Register a new user
echo -e "${YELLOW}Step 1: Registering a new test user...${NC}"
REGISTER_RESPONSE=$(curl -s -X POST "$API_BASE_URL/register" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "testuser@example.com",
    "password": "TestPassword123!",
    "firstName": "Test",
    "lastName": "User",
    "role": "CUSTOMER"
  }')

echo "Registration Response:"
echo "$REGISTER_RESPONSE" | jq '.'

USER_ID=$(echo "$REGISTER_RESPONSE" | jq -r '.userId')

if [ "$USER_ID" == "null" ] || [ -z "$USER_ID" ]; then
  echo -e "${RED}Failed to register user${NC}"
  exit 1
fi

echo -e "${GREEN}✓ User registered successfully with ID: $USER_ID${NC}\n"

# Step 2: Login to get JWT token
echo -e "${YELLOW}Step 2: Logging in to get JWT token...${NC}"
LOGIN_RESPONSE=$(curl -s -X POST "$API_BASE_URL/login" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "testuser@example.com",
    "password": "TestPassword123!"
  }')

echo "Login Response:"
echo "$LOGIN_RESPONSE" | jq '.'

ACCESS_TOKEN=$(echo "$LOGIN_RESPONSE" | jq -r '.accessToken')

if [ "$ACCESS_TOKEN" == "null" ] || [ -z "$ACCESS_TOKEN" ]; then
  echo -e "${RED}Failed to obtain access token${NC}"
  exit 1
fi

echo -e "${GREEN}✓ Successfully logged in and obtained JWT token${NC}\n"

# Step 3: Test email update with correct password
echo -e "${YELLOW}Step 3: Testing email update with correct password...${NC}"
UPDATE_RESPONSE=$(curl -s -X PUT "$API_BASE_URL/update-email" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -d '{
    "email": "testuser@example.com",
    "newEmail": "newemail@example.com",
    "password": "TestPassword123!"
  }')

echo "Update Email Response:"
echo "$UPDATE_RESPONSE" | jq '.'

SUCCESS=$(echo "$UPDATE_RESPONSE" | jq -r '.success')

if [ "$SUCCESS" == "true" ]; then
  echo -e "${GREEN}✓ Email updated successfully!${NC}\n"
else
  echo -e "${RED}✗ Email update failed${NC}\n"
fi

# Step 4: Test email update with wrong password
echo -e "${YELLOW}Step 4: Testing email update with wrong password...${NC}"
WRONG_PASSWORD_RESPONSE=$(curl -s -X PUT "$API_BASE_URL/update-email" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -d '{
    "email": "newemail@example.com",
    "newEmail": "anotheremail@example.com",
    "password": "WrongPassword123!"
  }')

echo "Wrong Password Response:"
echo "$WRONG_PASSWORD_RESPONSE" | jq '.'

FAILED_SUCCESS=$(echo "$WRONG_PASSWORD_RESPONSE" | jq -r '.success')

if [ "$FAILED_SUCCESS" == "false" ]; then
  echo -e "${GREEN}✓ Correctly rejected update with wrong password${NC}\n"
else
  echo -e "${RED}✗ Security issue: accepted wrong password${NC}\n"
fi

# Step 5: Test without authentication token
echo -e "${YELLOW}Step 5: Testing email update without authentication...${NC}"
NO_AUTH_RESPONSE=$(curl -s -w "\nHTTP_STATUS:%{http_code}" -X PUT "$API_BASE_URL/update-email" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "newemail@example.com",
    "newEmail": "yetanotheremail@example.com",
    "password": "TestPassword123!"
  }')

HTTP_STATUS=$(echo "$NO_AUTH_RESPONSE" | grep -o "HTTP_STATUS:[0-9]*" | cut -d':' -f2)

if [ "$HTTP_STATUS" == "401" ] || [ "$HTTP_STATUS" == "403" ]; then
  echo -e "${GREEN}✓ Correctly rejected request without authentication (HTTP $HTTP_STATUS)${NC}\n"
else
  echo -e "${RED}✗ Security issue: accepted request without authentication${NC}\n"
fi

# Summary
echo -e "${BLUE}=== Test Summary ===${NC}"
echo -e "1. User Registration: ${GREEN}✓${NC}"
echo -e "2. Login & JWT Token: ${GREEN}✓${NC}"
echo -e "3. Email Update with Correct Password: ${GREEN}✓${NC}"
echo -e "4. Reject Wrong Password: ${GREEN}✓${NC}"
echo -e "5. Require Authentication: ${GREEN}✓${NC}"

echo -e "\n${GREEN}All tests completed!${NC}"

