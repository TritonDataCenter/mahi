#!/bin/bash
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#

#
# Copyright (c) 2014, Joyent, Inc.
#

dbnum=$(json -f etc/mahi2.json redis.db || 0)
svcadm disable mahi-replicator
redis-cli -n $dbnum flushdb
svcadm enable mahi-replicator
