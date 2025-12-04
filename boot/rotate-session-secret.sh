#!/bin/bash
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# Copyright 2025 Edgecast Cloud LLC.
#
# Rotate JWT session secret with grace period support
# Allows graceful secret rotation without invalidating existing tokens
#

set -euo pipefail

# Default configuration
GRACE_PERIOD="${GRACE_PERIOD:-86400}"  # 24 hours
DRY_RUN="${DRY_RUN:-false}"
FORCE="${FORCE:-false}"

SVC_ROOT="/opt/smartdc"
BOOT_ROOT="$SVC_ROOT/boot"

function usage() {
    cat << EOF
Usage: $0 [options]

Rotate JWT session secret with grace period support.

Options:
    -d, --dry-run           Show what would be done without making changes
    -f, --force             Force rotation even if recent rotation detected
    -g, --grace-period SEC  Grace period in seconds (default: 86400)
    -h, --help              Show this help message

Environment Variables:
    GRACE_PERIOD           Default grace period in seconds
    DRY_RUN               Set to 'true' for dry run mode
    FORCE                 Set to 'true' to force rotation

Examples:
    # Standard rotation with 24-hour grace period
    $0
    
    # Dry run to see what would happen
    $0 --dry-run
    
    # Forced rotation with custom grace period
    $0 --force --grace-period 3600
EOF
    exit 1
}

function log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >&2
}

function get_current_secret() {
    mdata-get "sdc:application_metadata.$1" 2>/dev/null || echo ""
}

function set_sapi_metadata() {
    local key="$1"
    local value="$2"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "DRY RUN: Would set $key = $value"
        return 0
    fi
    
    log "Setting $key in SAPI metadata..."
    if ! $BOOT_ROOT/set-sapi-metadata.sh "$key" "$value"; then
        log "Warning: SAPI metadata update failed for $key (this may be expected in dev environments)"
    else
        log "Successfully set $key in SAPI metadata"
    fi
    return 0
}

function generate_new_secret() {
    local secret
    secret=$(xxd -p -c 64 -l 32 /dev/random)

    if [[ -z "$secret" ]]; then
        log "ERROR: Failed to generate new secret"
        exit 1
    fi

    echo "$secret"
}

function generate_key_id() {
    local timestamp
    local random
    
    timestamp=$(date +%Y%m%d-%H%M%S)
    random=$(openssl rand -hex 4)
    
    echo "key-${timestamp}-${random}"
}

function check_rotation_needed() {
    local current_secret
    local current_key_id
    local last_rotation
    local now
    local rotation_age
    local min_interval
    
    # Check if this is a manual rotation request
    if [[ "$FORCE" == "true" ]]; then
        log "Force flag set, skipping all rotation checks"
        return 0
    fi
    
    # Check if secrets are already configured (prevents rotation on boot)
    current_secret=$(get_current_secret "SESSION_SECRET_KEY")
    current_key_id=$(get_current_secret "SESSION_SECRET_KEY_ID")
    last_rotation=$(get_current_secret "SESSION_SECRET_ROTATION_TIME")
    
    if [[ -n "$current_secret" && -n "$current_key_id" ]]; then
        log "Secrets are already configured:"
        log "  Key ID: $current_key_id"
        if [[ -n "$last_rotation" ]]; then
            log "  Last rotation: $(date -d "@$last_rotation" 2>/dev/null || echo "$last_rotation")"
        fi
        log ""
        log "No rotation needed - secrets are already present."
        log "To force rotation, use --force flag."
        return 1
    fi
    
    if [[ -z "$last_rotation" ]]; then
        log "No previous rotation found, initial setup needed"
        return 0
    fi
    
    now=$(date +%s)
    rotation_age=$((now - last_rotation))
    min_interval=3600  # Minimum 1 hour between rotations
    
    if [[ $rotation_age -lt $min_interval ]]; then
        log "WARNING: Last rotation was ${rotation_age} seconds ago"
        log "Minimum interval is ${min_interval} seconds"
        log "Use --force to override this check"
        return 1
    fi
    
    return 0
}

function backup_current_secret() {
    local current_secret
    local current_key_id
    local current_rotation_time
    
    current_secret=$(get_current_secret "SESSION_SECRET_KEY")
    current_key_id=$(get_current_secret "SESSION_SECRET_KEY_ID")
    current_rotation_time=$(get_current_secret "SESSION_SECRET_ROTATION_TIME")
    
    if [[ -z "$current_secret" ]]; then
        log "WARNING: No current secret to backup"
        return 0
    fi
    
    log "Backing up current secret as old secret"
    
    # Use current key ID or default
    if [[ -z "$current_key_id" ]]; then
        current_key_id="primary-$(date +%Y%m%d)"
    fi
    
    # Use current rotation time or now
    if [[ -z "$current_rotation_time" ]]; then
        current_rotation_time=$(date +%s)
    fi
    
    set_sapi_metadata "SESSION_SECRET_KEY_OLD" "$current_secret"
    set_sapi_metadata "SESSION_SECRET_KEY_OLD_ID" "$current_key_id"
    
    log "Current secret backed up with key ID: $current_key_id"
}

function set_new_secret() {
    local new_secret="$1"
    local new_key_id="$2"
    local rotation_time="$3"
    
    log "Setting new primary secret"
    
    set_sapi_metadata "SESSION_SECRET_KEY" "$new_secret"
    set_sapi_metadata "SESSION_SECRET_KEY_ID" "$new_key_id"
    set_sapi_metadata "SESSION_SECRET_ROTATION_TIME" "$rotation_time"
    set_sapi_metadata "SESSION_SECRET_GRACE_PERIOD" "$GRACE_PERIOD"
    
    log "New secret set with key ID: $new_key_id"
    log "NOTE: Key ID will be embedded in JWT payload for rotation support"
}

function cleanup_expired_secrets() {
    local rotation_time
    local grace_period
    local now
    local expiry_time
    
    rotation_time=$(get_current_secret "SESSION_SECRET_ROTATION_TIME")
    grace_period=$(get_current_secret "SESSION_SECRET_GRACE_PERIOD")
    now=$(date +%s)
    
    if [[ -z "$rotation_time" || -z "$grace_period" ]]; then
        log "No rotation metadata found, skipping cleanup"
        return 0
    fi
    
    expiry_time=$((rotation_time + grace_period))
    
    if [[ $now -gt $expiry_time ]]; then
        log "Cleaning up expired old secret"
        
        if [[ "$DRY_RUN" == "true" ]]; then
            log "DRY RUN: Would remove old secret keys"
        else
            $BOOT_ROOT/set-sapi-metadata.sh SESSION_SECRET_KEY_OLD ""
            $BOOT_ROOT/set-sapi-metadata.sh SESSION_SECRET_KEY_OLD_ID ""
            log "Expired old secret removed"
        fi
    else
        local remaining=$((expiry_time - now))
        log "Old secret expires in $remaining seconds"
    fi
}

function notify_instances() {
    log "Notifying mahi instances to reload configuration..."
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "DRY RUN: Would notify mahi instances"
        return 0
    fi
    
    # Send refresh to running mahi processes to reload config
    status=$(svcs mahi-server | tail -1 | cut -d ' ' -f 1)
    if [[ "$status" == "online" ]]; then
        svcadm refresh "mahi-server"
        log "Sent refresh to mahi processes"
    else
        log "WARNING: No running mahi processes found"
    fi
}

function rotate_secret() {
    local new_secret
    local new_key_id
    local rotation_time
    
    log "Starting JWT secret rotation..."
    log "Grace period: $GRACE_PERIOD seconds"
    
    if ! check_rotation_needed; then
        log "ERROR: Rotation not needed or blocked"
        exit 1
    fi
    
    # Generate new credentials
    log "Generating new secret and key ID..."
    new_secret=$(generate_new_secret)
    new_key_id=$(generate_key_id)
    rotation_time=$(date +%s)
    
    log "Generated new key ID: $new_key_id"
    
    # Backup current secret
    backup_current_secret
    
    # Set new secret
    set_new_secret "$new_secret" "$new_key_id" "$rotation_time"
    
    # Notify running instances
    notify_instances
    
    # Cleanup old expired secrets
    cleanup_expired_secrets
    
    log "Secret rotation completed successfully!"
    log "New key ID: $new_key_id"
    log "Rotation time: $(date -d "@$rotation_time")"
    log "Grace period expires: $(date -d @$((rotation_time + GRACE_PERIOD)))"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "DRY RUN: No actual changes were made"
    fi
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -d|--dry-run)
            DRY_RUN="true"
            shift
            ;;
        -f|--force)
            FORCE="true"
            shift
            ;;
        -g|--grace-period)
            GRACE_PERIOD="$2"
            shift 2
            ;;
        -h|--help)
            usage
            ;;
        *)
            log "ERROR: Unknown option $1"
            usage
            ;;
    esac
done

# Validate grace period
if ! [[ "$GRACE_PERIOD" =~ ^[0-9]+$ ]] || [[ "$GRACE_PERIOD" -lt 60 ]]; then
    log "ERROR: Grace period must be a number >= 60 seconds"
    exit 1
fi

# Check if running as root or with proper permissions
if [[ $EUID -eq 0 ]]; then
    log "WARNING: Running as root. Consider using a service user."
fi

# Main execution
rotate_secret
