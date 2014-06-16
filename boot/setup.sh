#!/bin/bash
# -*- mode: shell-script; fill-column: 80; -*-
#
# Copyright (c) 2014 Joyent Inc., All rights reserved.
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

MAHI_CFG=$SVC_ROOT/etc/mahi.json
ZONE_UUID=`/usr/bin/zonename`

export PATH=$SVC_ROOT/build/node/bin:/opt/local/bin:/usr/sbin/:/usr/bin:$PATH

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
    svccfg import /opt/local/share/smf/redis/manifest.xml
    svcadm enable redis
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
    sdc_log_rotation_add $role /var/svc/log/*$role*.log 1g
    sdc_log_rotation_add $role /var/log/redis/*redis*.log 1g
    sdc_log_rotation_setup_end

    svccfg import /opt/local/share/smf/redis/manifest.xml
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

    manta_common_setup "mahi"

    manta_ensure_zk

    echo "Updating redis"
    manta_setup_redis

    echo "Updating auth"
    manta_setup_auth

    echo "Updating authv2"
    manta_add_logadm_entry "mahi-replicator"
    manta_add_logadm_entry "mahi-server"
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

    # SDC doesn't need old mahi service
    # echo "Installing auth"
    # manta_setup_auth

    echo "insgtalling authv2"
    manta_setup_auth2

    # All done, run boilerplate end-of-setup
    sdc_setup_complete

fi

exit 0
