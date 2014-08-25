#!/bin/bash
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#

#
# Copyright (c) 2014, Joyent, Inc.
#

set -o errexit

if [ -z "$1" ]; then
    echo "remote mahi host required (e.g. authcache.us-east.joyent.us)" >&2
    exit 1
fi

PORT=$(json -f etc/mahi2.json replicator.port)
DBDIR=$(json -f etc/mahi2.json redis.directory)
REMOTE="http://$1:$PORT/snapshot"

echo "fetching snapshot from $REMOTE to /var/tmp/mahi-snapshot.rdb"
curl -o /var/tmp/mahi-snapshot.rdb $REMOTE

echo "backing up existing db to /var/tmp/dump.rdb.backup"
cp $DBDIR/dump.rdb /var/tmp/dump.rdb.backup

echo "disabling mahi-server"
svcadm disable mahi-server

echo "disabling mahi-replicator"
svcadm disable mahi-replicator

echo "disabling redis"
svcadm disable redis

echo "copying new db to $DBDIR/dump.rdb"
cp /var/tmp/mahi-snapshot.rdb $DBDIR/dump.rdb

echo "enabling redis"
svcadm enable redis

echo "enabling mahi-replicator"
svcadm enable mahi-replicator

echo "enabling mahi-server"
svcadm enable mahi-server
