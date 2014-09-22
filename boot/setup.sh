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

    # add log rotation entries for mahi
    sdc_log_rotation_add mahi-replicator /var/svc/log/*mahi-replicator*.log 1g
    sdc_log_rotation_add mahi-server /var/svc/log/*mahi-server*.log 1g

    # SDC doesn't need old mahi service
    # echo "Installing auth"
    # manta_setup_auth

    echo "insgtalling authv2"
    manta_setup_auth2

    # All done, run boilerplate end-of-setup
    sdc_setup_complete

fi

exit 0
