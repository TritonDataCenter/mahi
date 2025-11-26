#!/bin/bash
# -*- mode: shell-script; fill-column: 80; -*-
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#

#
# Copyright (c) 2014, Joyent, Inc.
#

export PS4='[\D{%FT%TZ}] ${BASH_SOURCE}:${LINENO}: ${FUNCNAME[0]:+${FUNCNAME[0]}(): }'
set -o xtrace

role=mahi
SOURCE="${BASH_SOURCE[0]}"
if [[ -h $SOURCE ]]; then
    SOURCE="$(readlink "$SOURCE")"
fi
DIR="$( cd -P "$( dirname "$SOURCE" )" && pwd )"
SVC_ROOT=/opt/smartdc/mahi
MAHI_ROOT=/mahi

MAHI_CFG=$SVC_ROOT/etc/mahi.json
ZONE_UUID=`/usr/bin/zonename`
ZONE_DATASET=zones/$ZONE_UUID/data

export PATH=$SVC_ROOT/build/node/bin:/opt/local/bin:/usr/sbin/:/usr/bin:$PATH

mkdir -p $MAHI_ROOT
zfs list $ZONE_DATASET && rc=$? || rc=$?
if [[ $rc == 0 ]]; then
    mountpoint=$(zfs get -H -o value mountpoint $ZONE_DATASET)
    if [[ $mountpoint != $MAHI_ROOT ]]; then
        zfs set mountpoint=$MAHI_ROOT $ZONE_DATASET || \
            fatal "failed to set mountpoint"
    fi
fi
chmod 777 $MAHI_ROOT
mkdir -p $MAHI_ROOT/redis
chmod 777 $MAHI_ROOT/redis

#
# XXX in the future this should come from SAPI and we should be pulling out
# the "application" that's the parent of this instance. (see: SAPI-173)
#
if [[ -n $(mdata-get sdc:tags.manta_role) ]]; then
    export FLAVOR="manta"
else
    export FLAVOR="sdc"
fi

function manta_setup_redis {
    manta_add_logadm_entry "redis"
    svccfg import $SVC_ROOT/smf/manifests/mahi-redis.xml
    svcadm enable redis
}

function get_sapi_metadata {
    local key="$1"
    local sapi_url=""

    sapi_url=$(mdata-get SAPI_URL 2>/dev/null || true)
    if [[ -z "$sapi_url" ]]; then
        echo ""
        return 1
    fi

    curl -sH 'application/json' \
        "$sapi_url/services?name=authcache" | \
        json -ga "metadata.$key" 2>/dev/null || true
}

function manta_setup_session_secret {
    echo "Configuring SESSION_SECRET_KEY with rotation support"
    
    # Check if SESSION_SECRET_KEY is already configured in SAPI
    local current_secret=""
    local current_key_id=""
    local sapi_url=""

    sapi_url=$(mdata-get SAPI_URL 2>/dev/null || true)

    current_secret=$(curl -sH 'application/json' \
        $sapiurl/services?name=authcache | \
        json -ga metadata.SESSION_SECRET_KEY 2>/dev/null || true)

    current_key_id=$(curl -sH 'application/json' \
        $sapiurl/services?name=authcache | \
        json -ga metadata.SESSION_SECRET_KEY_ID 2>/dev/null || true)
    
    if [[ -z "$current_secret" ]]; then
        echo "Generating initial SESSION_SECRET_KEY with rotation support"
        local secret_key=""
        local key_id=""
        local rotation_time=""
        
        secret_key=$($SVC_ROOT/boot/generate-session-secret.js)
        if [[ -z "$secret_key" ]]; then
            fatal "Failed to generate session secret key"
        fi
        
        # Generate initial key ID
        key_id="initial-$(date +%Y%m%d-%H%M%S)"
        rotation_time=$(date +%s)
        
        echo "Setting SESSION_SECRET_KEY and metadata in SAPI"
        if ! $SVC_ROOT/boot/set-sapi-metadata.sh SESSION_SECRET_KEY "$secret_key"; then
            echo "Warning: Failed to set SESSION_SECRET_KEY in SAPI" >&2
            echo "This may require manual configuration" >&2
        fi
        
        if ! $SVC_ROOT/boot/set-sapi-metadata.sh SESSION_SECRET_KEY_ID "$key_id"; then
            echo "Warning: Failed to set SESSION_SECRET_KEY_ID in SAPI" >&2
        fi
        
        if ! $SVC_ROOT/boot/set-sapi-metadata.sh SESSION_SECRET_ROTATION_TIME "$rotation_time"; then
            echo "Warning: Failed to set rotation timestamp in SAPI" >&2
        fi

        if ! $SVC_ROOT/boot/set-sapi-metadata.sh SESSION_SECRET_GRACE_PERIOD "86400"; then
            echo "Warning: Failed to set grace period in SAPI" >&2
        fi

        echo "SESSION_SECRET_KEY configured successfully with key ID: $key_id"
        
        # Make rotation script executable
        chmod +x $SVC_ROOT/boot/rotate-session-secret.sh
        
    else
        echo "SESSION_SECRET_KEY already configured"
        
        # Ensure key ID exists for existing installations
        if [[ -z "$current_key_id" ]]; then
            echo "Adding key ID to existing secret for rotation support"
            local legacy_key_id="legacy-$(date +%Y%m%d)"
            
            if ! $SVC_ROOT/boot/set-sapi-metadata.sh SESSION_SECRET_KEY_ID "$legacy_key_id"; then
                echo "Warning: Failed to set legacy key ID in SAPI" >&2
            else
                echo "Added legacy key ID: $legacy_key_id"
            fi
        fi
        
        # Ensure rotation script is executable
        chmod +x $SVC_ROOT/boot/rotate-session-secret.sh
        
        # Clean up any expired old secrets
        cleanup_expired_session_secrets
    fi
}

function cleanup_expired_session_secrets {
    local rotation_time=""
    local grace_period=""
    local now=""
    local expiry_time=""
    
    rotation_time=$(get_sapi_metadata SESSION_SECRET_ROTATION_TIME)
    grace_period=$(get_sapi_metadata SESSION_SECRET_GRACE_PERIOD)
    
    if [[ -n "$rotation_time" && -n "$grace_period" ]]; then
        now=$(date +%s)
        expiry_time=$((rotation_time + grace_period))
        
        if [[ $now -gt $expiry_time ]]; then
            echo "Cleaning up expired session secret during boot"
            $SVC_ROOT/boot/set-sapi-metadata.sh SESSION_SECRET_KEY_OLD "" 2>/dev/null || true
            $SVC_ROOT/boot/set-sapi-metadata.sh SESSION_SECRET_KEY_OLD_ID "" 2>/dev/null || true
            echo "Expired session secret cleaned up"
        fi
    fi
}

function setup_rotation_cron {
    local cron_entry="0 2 */3 * * $SVC_ROOT/boot/rotate-session-secret.sh --force 2>&1 | logger -t jwt-rotation"
    local cron_file="/var/spool/cron/crontabs/root"

    echo "Configuring JWT rotation cron job"

    if [[ ! -f "$cron_file" ]]; then
        touch "$cron_file"
        chmod 600 "$cron_file"
    fi

    if grep -q "rotate-session-secret.sh" "$cron_file" 2>/dev/null; then
        echo "JWT rotation cron job already installed"
        return 0
    fi

    echo "Installing JWT rotation cron job (every 3 days at 2:00 AM)"
    echo "$cron_entry" >> "$cron_file"

    if [[ -x /usr/sbin/crontab ]]; then
        /usr/sbin/crontab "$cron_file"
    fi

    echo "JWT rotation cron job installed successfully"
}

function manta_setup_auth {
    svccfg import $SVC_ROOT/smf/manifests/mahi.xml
    svcadm enable mahi
}

function manta_setup_auth2 {
    svccfg import $SVC_ROOT/smf/manifests/mahi-replicator.xml
    svcadm enable mahi-replicator

    svccfg import $SVC_ROOT/smf/manifests/mahi-server.xml
    svcadm enable mahi-server
}

function sdc_setup_redis {
    sdc_log_rotation_add amon-agent /var/svc/log/*amon-agent*.log 1g
    sdc_log_rotation_add config-agent /var/svc/log/*config-agent*.log 1g
    sdc_log_rotation_add redis /var/log/redis/*redis*.log 1g
    sdc_log_rotation_setup_end

    svccfg import $SVC_ROOT/smf/manifests/mahi-redis.xml
    svcadm enable redis
}

if [[ ${FLAVOR} == "manta" ]]; then

    source ${DIR}/scripts/util.sh
    source ${DIR}/scripts/services.sh

    # XXX See MANTA-1615.  These manifests are shipped for SDC but aren't relevant
    # for the manta image, so remove them until the situation with SDC/manta
    # manifests is resolved.
    rm -rf $SVC_ROOT/sdc/sapi_manifests

    # Mainline

    echo "Running common setup scripts"
    manta_common_presetup

    echo "Adding local manifest directories"
    manta_add_manifest_dir "/opt/smartdc/mahi"

    echo "Setting up session secret for JWT tokens"
    manta_setup_session_secret

    echo "Setting up JWT rotation cron job"
    setup_rotation_cron

    # set up log rotation for mahiv2 first so logadm rotates logs properly
    manta_add_logadm_entry "mahi-replicator"
    manta_add_logadm_entry "mahi-server"

    manta_common_setup "mahi"

    manta_ensure_zk

    echo "Updating redis"
    manta_setup_redis

    echo "Updating auth"
    manta_setup_auth

    echo "Updating authv2"
    manta_setup_auth2

    manta_common_setup_end

else # ${FLAVOR} == "sdc"

    # Local manifests
    CONFIG_AGENT_LOCAL_MANIFESTS_DIRS=/opt/smartdc/$role/sdc

    # Include common utility functions (then run the boilerplate)
    source /opt/smartdc/boot/lib/util.sh
    sdc_common_setup

    echo "Installing auth redis"
    sdc_setup_redis

    echo "Setting up session secret for JWT tokens"
    manta_setup_session_secret

    echo "Setting up JWT rotation cron job"
    setup_rotation_cron

    # add log rotation entries for mahi
    sdc_log_rotation_add mahi-replicator /var/svc/log/*mahi-replicator*.log 1g
    sdc_log_rotation_add mahi-server /var/svc/log/*mahi-server*.log 1g

    # SDC doesn't need old mahi service
    # echo "Installing auth"
    # manta_setup_auth

    echo "installing authv2"
    manta_setup_auth2

    # All done, run boilerplate end-of-setup
    sdc_setup_complete

fi

exit 0
