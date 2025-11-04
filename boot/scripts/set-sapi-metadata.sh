#!/bin/bash
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#

#
# Copyright 2025 Edgecast Cloud LLC.
#

#
# set-sapi-metadata.sh: Set metadata values in SAPI service using proper workflow
# 
# Usage: set-sapi-metadata.sh <key> <value>
#
# This script:
# 1. Gets SAPI URL from SAPI_URL metadata
# 2. Gets service role from sdc:tags.manta_role (should be "authcache") 
# 3. Gets service UUID from SAPI using the role name
# 4. Updates service metadata via SAPI API
# 5. Config-agent will update mahi configuration automatically

set -o errexit
set -o pipefail

if [[ $# -ne 2 ]]; then
    echo "Usage: $0 <metadata_key> <metadata_value>" >&2
    exit 1
fi

METADATA_KEY="$1"
METADATA_VALUE="$2"

# Get SAPI URL from zone metadata
SAPI_URL=$(mdata-get SAPI_URL 2>/dev/null || echo "")

if [[ -z "$SAPI_URL" ]]; then
    echo "Warning: Could not determine SAPI URL from SAPI_URL metadata" >&2
    echo "Skipping SAPI metadata update for ${METADATA_KEY}" >&2
    exit 0
fi

# Get service role from zone metadata (should be "authcache" for mahi)
SERVICE_ROLE=$(mdata-get sdc:tags.manta_role 2>/dev/null || echo "")

if [[ -z "$SERVICE_ROLE" ]]; then
    echo "Warning: Could not determine service role from sdc:tags.manta_role" >&2
    echo "Skipping SAPI metadata update for ${METADATA_KEY}" >&2
    exit 0
fi

echo "Getting service UUID for role: ${SERVICE_ROLE}"

# Get service UUID from SAPI using the role name
SERVICE_UUID=$(curl -s -H 'Content-Type: application/json' \
    "${SAPI_URL}/services?name=${SERVICE_ROLE}" | \
    json -ga uuid 2>/dev/null | head -1)

if [[ -z "$SERVICE_UUID" ]]; then
    echo "Warning: Could not determine service UUID for role ${SERVICE_ROLE}" >&2
    echo "Available services:" >&2
    curl -s -H 'Content-Type: application/json' "${SAPI_URL}/services" | \
        json -ga name 2>/dev/null || echo "Failed to list services" >&2
    echo "Skipping SAPI metadata update for ${METADATA_KEY}" >&2
    exit 0
fi

echo "Found service UUID: ${SERVICE_UUID}"
echo "Setting ${METADATA_KEY} in SAPI service metadata..."

# Create JSON payload for SAPI service update
TEMP_JSON=$(mktemp)
cat > "$TEMP_JSON" <<EOF
{
  "action": "update",
  "metadata": {
    "${METADATA_KEY}": "${METADATA_VALUE}"
  }
}
EOF

# Update SAPI service metadata
if curl -k -H "Content-Type: application/json" -X PUT \
    "${SAPI_URL}/services/${SERVICE_UUID}" \
    -d @"$TEMP_JSON" >/dev/null 2>&1; then
    echo "Successfully set ${METADATA_KEY} in SAPI service metadata"
    echo "Config-agent will update mahi configuration automatically"
else
    echo "Warning: Failed to update SAPI service metadata" >&2
    echo "SAPI URL: ${SAPI_URL}" >&2
    echo "Service Role: ${SERVICE_ROLE}" >&2
    echo "Service UUID: ${SERVICE_UUID}" >&2
    echo "This may be expected in development environments" >&2
    rm -f "$TEMP_JSON"
    exit 0
fi

# Clean up
rm -f "$TEMP_JSON"

echo "SAPI metadata update completed"