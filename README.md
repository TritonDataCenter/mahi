# Mahi - Manta Authentication Service

Repository: <git@git.joyent.com:mahi.git>
Browsing: <https://mo.joyent.com/mahi>
Who: Yunong Xiao
Docs: <https://mo.joyent.com/docs/mahi>
Tickets/bugs: <https://devhub.joyent.com/jira/browse/MANTA>


# Overview

This the manta authentication service. It pulls in user, group, and key
information from UFDS and caches them in a local redis instance running on port
6789.


# Interface

The authentication keys are exposed directly via redis. Specifically these keys
are available to consumers:

    /login/:username
    /uuid/:uuid

The username entry contains a JSON string containing attributes of the
user's uuid, keys, and groups:

    {
        uuid: $user's uuid from ldap,
        keys: {
           $fingerprint1: '$publickey1',
           $fingerprint2: '$publickey2',
           ...
        },
        groups: {
           $group1: $group1,
           $group2: $group2,
           ...
        }
    }

The uuid entry is just a simple reverse index of uuid -> username.


# Testing

Mahi tests require a virgin UFDS service. The easiest way to do this is to:

- Provision/sdc-factoryreset a COAL.
- Disable the UFDS zone in COAL. (this prevents other services from modifying
  the rows in the underlying moray datastore). `vmadm reboot $ufds_zone_uuid`
- Delete the ufds buckets in moray `delbucket ufds_cn_changelog && delbucket
  ufds_o_smartdc`
- Now you'll have a virgin moray, you'll want to checkout and run a local copy
of UFDS. `node main.js -f etc/config.coal.json -vvv | bunyan`
- Finally - you can run the tests via `make test`. Just remember to repeat these
  steps across test invocations as the tests don't clean up.

