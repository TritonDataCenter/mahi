#!/usr/bin/bash

# -*- mode: shell-script; fill-column: 80; -*-

set -o xtrace

SOURCE="${BASH_SOURCE[0]}"
if [[ -h $SOURCE ]]; then
    SOURCE="$(readlink "$SOURCE")"
fi
DIR="$( cd -P "$( dirname "$SOURCE" )" && pwd )"
SVC_ROOT=/opt/smartdc/mahi

MAHI_CFG=$SVC_ROOT/etc/mahi.json
ZONE_UUID=$(zonename)

source ${DIR}/scripts/util.sh
source ${DIR}/scripts/services.sh

export PATH=$SVC_ROOT/build/node/bin:/opt/local/bin:/usr/sbin/:/usr/bin:$PATH


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

echo "Updating auithv2"
manta_setup auth2

manta_common_setup_end

exit 0
