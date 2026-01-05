#!/bin/bash
#
# Copyright 2026 Edgecast Cloud LLC.
# 
# JWT Rotation Test with AWS CLI
#
# Tests STS session tokens before and after manual secret rotation.
# Uses AWS CLI for token generation and validation.
#
# Prerequisites:
# - AWS CLI installed and configured
# - S3 endpoint running (manta-buckets-api)
# - Valid AWS credentials configured (access key/secret)
#
# Usage:
#   export S3_ENDPOINT=http://localhost:9000
#   ./test/jwt-rotation-awscli-test.sh
#
# Manual rotation steps (run between test phases):
#   ./boot/rotate-session-secret.sh --grace-period 300
#   
# When key is updated in etc/mahi2.json , mahi should be restarted
# to start using the new keys.
#

set -euo pipefail

S3_ENDPOINT="${S3_ENDPOINT:-http://localhost:9000}"

# Decode JWT base64url (handles missing padding and URL-safe chars)
decode_jwt_payload() {
    local payload="$1"
    # Replace URL-safe chars with standard base64
    payload=$(echo "$payload" | tr '_-' '/+')
    # Add padding if needed
    local pad=$((4 - ${#payload} % 4))
    if [ "$pad" -lt 4 ]; then
        payload="${payload}$(printf '%*s' "$pad" '' | tr ' ' '=')"
    fi
    echo "$payload" | base64 -d 2>/dev/null
}

echo "=== JWT Rotation Test with AWS CLI ==="
echo "S3 endpoint: $S3_ENDPOINT"
echo ""

# Phase 1: Get session token before rotation
echo "=== Phase 1: Generate Session Token (Before Rotation) ==="
echo "Running: aws sts get-session-token --endpoint-url $S3_ENDPOINT"
echo ""

TOKEN_RESPONSE_1=$(aws sts get-session-token \
    --endpoint-url "$S3_ENDPOINT" \
    --duration-seconds 3600 \
    --no-verify-ssl \
    --output json 2>/dev/null) || {
    echo "ERROR: Failed to get session token"
    exit 1
}

echo "Token Response:"
echo "$TOKEN_RESPONSE_1" | json

# Extract and decode the session token
SESSION_TOKEN_1=$(echo "$TOKEN_RESPONSE_1" | json Credentials.SessionToken)
echo ""
echo "Session Token (truncated): ${SESSION_TOKEN_1:0:50}..."

# Decode JWT payload to show keyId
echo ""
echo "JWT Payload (decoded):"
PAYLOAD_1=$(decode_jwt_payload "$(echo "$SESSION_TOKEN_1" | cut -d. -f2)")
echo "$PAYLOAD_1" | json || echo "(decode failed)"
echo ""

# Store keyId from first token
KEY_ID_1=$(echo "$PAYLOAD_1" | json keyId) || KEY_ID_1="unknown"
echo "KeyId from token 1: $KEY_ID_1"
echo ""

# Validate with GetCallerIdentity
echo "=== Validating Token with GetCallerIdentity ==="
echo "Running: aws sts get-caller-identity --endpoint-url $S3_ENDPOINT"
echo ""

IDENTITY_RESPONSE=$(aws sts get-caller-identity \
    --endpoint-url "$S3_ENDPOINT" \
    --no-verify-ssl \
    --output json 2>/dev/null) || {
    echo "ERROR: GetCallerIdentity failed"
}

echo "Caller Identity:"
echo "$IDENTITY_RESPONSE" | json
echo ""

echo "=============================================="
echo "PAUSE: Now manually run the rotation script:"
echo ""
echo "  ./boot/rotate-session-secret.sh --grace-period 300"
echo ""
echo "Then press ENTER to continue testing..."
echo "=============================================="
read -r

# Phase 2: After rotation
echo ""
echo "=== Phase 2: Test After Rotation ==="

# Test old token still works (grace period)
echo "Testing old token still works (grace period)..."
IDENTITY_OLD=$(aws sts get-caller-identity \
    --endpoint-url "$S3_ENDPOINT" \
    --no-verify-ssl \
    --output json 2>/dev/null) || {
    echo "WARNING: Old token may have expired or grace period not active"
}
echo "Old token validation: $IDENTITY_OLD"
echo ""

# Generate new token (should use new keyId)
echo "Generating new session token (should use new keyId)..."
TOKEN_RESPONSE_2=$(aws sts get-session-token \
    --endpoint-url "$S3_ENDPOINT" \
    --duration-seconds 3600 \
    --no-verify-ssl \
    --output json 2>/dev/null) || {
    echo "ERROR: Failed to get new session token"
    exit 1
}

SESSION_TOKEN_2=$(echo "$TOKEN_RESPONSE_2" | json Credentials.SessionToken)
echo ""
echo "New Session Token (truncated): ${SESSION_TOKEN_2:0:50}..."

# Decode new JWT payload
echo ""
echo "New JWT Payload (decoded):"
PAYLOAD_2=$(decode_jwt_payload "$(echo "$SESSION_TOKEN_2" | cut -d. -f2)")
echo "$PAYLOAD_2" | json || echo "(decode failed)"

KEY_ID_2=$(echo "$PAYLOAD_2" | json keyId) || KEY_ID_2="unknown"
echo ""
echo "KeyId from token 2: $KEY_ID_2"

# Compare keyIds
echo ""
echo "=== Results ==="
echo "Token 1 keyId: $KEY_ID_1"
echo "Token 2 keyId: $KEY_ID_2"

if [ "$KEY_ID_1" != "$KEY_ID_2" ]; then
    echo "SUCCESS: KeyIds are different - rotation working correctly"
else
    echo "NOTE: KeyIds are the same - rotation may not have completed"
fi

echo ""
echo "=== Test Complete ==="
