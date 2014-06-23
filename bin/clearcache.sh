#!/bin/bash

dbnum=$(json -f etc/mahi2.json redis.db || 0)
svcadm disable mahi-replicator
redis-cli -n $dbnum flushdb
svcadm enable mahi-replicator
