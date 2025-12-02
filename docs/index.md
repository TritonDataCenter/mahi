---
title: Mahi
markdown2extras: tables, code-friendly
apisections: Task Control API
---
<!--
    This Source Code Form is subject to the terms of the Mozilla Public
    License, v. 2.0. If a copy of the MPL was not distributed with this
    file, You can obtain one at http://mozilla.org/MPL/2.0/.
-->
<!--
    Copyright (c) 2017, Joyent, Inc.
    Copyright 2024 MNX Cloud, Inc.
-->

# Mahi

Mahi is the auth cache API used by
[Triton Data Center](https://github.com/TritonDataCenter/triton)
and [Manta](https://github.com/TritonDataCenter/manta). It maintains a cache of
user auth data from [UFDS](https://github.com/TritonDataCenter/sdc-ufds) in a
local Redis and exposes a REST API to that data.


# Accounts

## GetAccount (GET /accounts)

Returns JSON containing account information.

### Inputs

| Field | Type | Required? | Notes |
| ----- | ---- | --------- | ----- |
| login (query param) | string | Yes | account login name |

### Returns

The account object.

### Errors

| Code | HTTP Status Code | Description |
| ---- | ---------------- | ----------- |
| AccountDoesNotExistError | 404 | No account exists with the given login |
| BadRequestError | 400 | "login" was not specified |
| RedisError | 500 | Error contacting redis |

### Example

    $ curl -is http://localhost/accounts?login=poseidon | json
    HTTP/1.1 200 OK
    Content-Type: application/json
    Content-Length: 703
    Date: Thu, 04 Sep 2014 21:44:21 GMT
    Connection: keep-alive

    {
      "roles": {},
      "account": {
        "type": "account",
        "uuid": "845b7932-8b94-e063-979b-ef931f191d04",
        "login": "poseidon",
        "groups": [
          "operators"
        ],
        "approved_for_provisioning": false,
        "keys": {
          "06:a5:88:80:f9:0b:44:4d:10:ae:09:68:71:4b:56:b7": "elided"
        },
        "isOperator": true
      }
    }



## GetAccountByUuid (GET /accounts/:accountid)

Returns account information by UUID.

### Inputs

| Field | Type | Required? | Notes |
| ----- | ---- | --------- | ----- |
| accountid | UUID | Yes |  |

### Returns

The account object.

### Errors

| Code | HTTP Status Code | Description |
| ---- | ---------------- | ----------- |
| AccountIdDoesNotExistError | 404 | No account exists with the given UUID |
| RedisError | 500 | Error contacting redis |

### Example

    $ curl -is http://localhost/accounts/845b7932-8b94-e063-979b-ef931f191d04 | json
    HTTP/1.1 200 OK
    Content-Type: application/json
    Content-Length: 703
    Date: Thu, 04 Sep 2014 21:47:15 GMT
    Connection: keep-alive

    {
      "roles": {},
      "account": {
        "type": "account",
        "uuid": "845b7932-8b94-e063-979b-ef931f191d04",
        "login": "poseidon",
        "groups": [
          "operators"
        ],
        "approved_for_provisioning": false,
        "keys": {
          "06:a5:88:80:f9:0b:44:4d:10:ae:09:68:71:4b:56:b7": "elided"
        },
        "isOperator": true
      }
    }


# Users

## GetUser (GET /users)

Returns JSON containing user information, including the user's parent account
information. Set the `fallback` parameter to true to get account information
even if the user does not exist.

For backwards compatibility, if the `fallback` query parameter is not specified,
it defaults to true.

### Inputs

| Field | Type | Required? | Notes |
| ----- | ---- | --------- | ----- |
| account (query param) | string | Yes | account login |
| login (query param) | string | Yes | user login |
| fallback (query param) | boolean | No | See above |

### Returns

The user object.

### Errors

| Code | HTTP Status Code | Description |
| ---- | ---------------- | ----------- |
| AccountDoesNotExistError | 404 | No account exists with the given account login |
| BadRequestError | 400 | "account" or "login" was not specified |
| UserDoesNotExistError | 404 | No user with the given login exists under the given account |
| RedisError | 500 | Error contacting redis |

### Examples

    $ curl -is "http://localhost/users?account=fred&login=muskie_test_user" | json -Ha
    {
      "roles": {
        "1e605e9d-e591-c865-e1df-9d60b3d98ce8": {
          "type": "role",
          "uuid": "1e605e9d-e591-c865-e1df-9d60b3d98ce8",
          "name": "muskie_test_role_jobs_only",
          "account": "83546bda-028d-11e2-aabe-17b87241f6ee",
          "policies": [
            "3875dd17-2f92-62d6-cbed-9591946fdf6f"
          ],
          "rules": [
            [
              "Can createjob and managejob",
              {
                "effect": true,
                "actions": {
                  "exact": {
                    "createjob": true,
                    "managejob": true
                  },
                  "regex": []
                },
                "conditions": []
              }
            ]
          ]
        },
      },
      "account": {
        "type": "account",
        "uuid": "83546bda-028d-11e2-aabe-17b87241f6ee",
        "login": "fred",
        "groups": [],
        "approved_for_provisioning": true,
        "keys": {
          "e3:4d:9b:26:bd:ef:a1:db:43:ae:4b:f7:bc:69:a7:24": "elided"
        },
        "isOperator": false
      },
      "user": {
        "type": "user",
        "uuid": "92543592-6018-62ae-fc60-ffb83f0b5157",
        "account": "83546bda-028d-11e2-aabe-17b87241f6ee",
        "login": "muskie_test_user",
        "keys": {
          "e3:4d:9b:26:bd:ef:a1:db:43:ae:4b:f7:bc:69:a7:24": "elided"
        },
        "roles": [
          "1e605e9d-e591-c865-e1df-9d60b3d98ce8"
        ],
        "defaultRoles": []
      }
    }

<!-- -->

    $ curl -is "http://localhost/users?account=fred&login=fakeuser&fallback=false" | json -a
    HTTP/1.1 404 Not Found
    Content-Type: application/json
    Content-Length: 84
    Date: Fri, 05 Sep 2014 17:32:31 GMT
    Connection: keep-alive

    {
      "code": "UserDoesNotExist",
      "message": "user fakeuser does not exist in account fred"
    }

<!-- -->

    $ curl -is "http://localhost/users?account=fred&login=fakeuser&fallback=true" | json -Ha
    {
      "roles": {},
      "account": {
        "type": "account",
        "uuid": "83546bda-028d-11e2-aabe-17b87241f6ee",
        "login": "fred",
        "groups": [],
        "approved_for_provisioning": true,
        "keys": {
          "e3:4d:9b:26:bd:ef:a1:db:43:ae:4b:f7:bc:69:a7:24": "elided"
        },
        "isOperator": false
      }
    }


## GetUserByUuid (GET /users/:userid)

Returns user information by UUID.

### Inputs

| Field | Type | Required? | Notes |
| ----- | ---- | --------- | ----- |
| userid | UUID | Yes |  |

### Returns

The user object.

### Errors

| Code | HTTP Status Code | Description |
| ---- | ---------------- | ----------- |
| UserIdDoesNotExistError | 404 | No user exists with that UUID |
| RedisError | 500 | Error contacting redis |

### Examples

    $ curl -is "http://localhost/users/92543592-6018-62ae-fc60-ffb83f0b5157" | json -Ha
    {
      "roles": {
        "1e605e9d-e591-c865-e1df-9d60b3d98ce8": {
          "type": "role",
          "uuid": "1e605e9d-e591-c865-e1df-9d60b3d98ce8",
          "name": "muskie_test_role_jobs_only",
          "account": "83546bda-028d-11e2-aabe-17b87241f6ee",
          "policies": [
            "3875dd17-2f92-62d6-cbed-9591946fdf6f"
          ],
          "rules": [
            [
              "Can createjob and managejob",
              {
                "effect": true,
                "actions": {
                  "exact": {
                    "createjob": true,
                    "managejob": true
                  },
                  "regex": []
                },
                "conditions": []
              }
            ]
          ]
        },
      },
      "account": {
        "type": "account",
        "uuid": "83546bda-028d-11e2-aabe-17b87241f6ee",
        "login": "fred",
        "groups": [],
        "approved_for_provisioning": true,
        "keys": {
          "e3:4d:9b:26:bd:ef:a1:db:43:ae:4b:f7:bc:69:a7:24": "elided"
        },
        "isOperator": false
      },
      "user": {
        "type": "user",
        "uuid": "92543592-6018-62ae-fc60-ffb83f0b5157",
        "account": "83546bda-028d-11e2-aabe-17b87241f6ee",
        "login": "muskie_test_user",
        "keys": {
          "e3:4d:9b:26:bd:ef:a1:db:43:ae:4b:f7:bc:69:a7:24": "elided"
        },
        "roles": [
          "1e605e9d-e591-c865-e1df-9d60b3d98ce8"
        ],
        "defaultRoles": []
      }
    }


# STS (Security Token Service)

AWS-compatible STS endpoints for temporary credential management.
See [STS API](sts.md) for full documentation.

| Endpoint | Method | Description |
| -------- | ------ | ----------- |
| /sts/assume-role | POST | Assume an IAM role |
| /sts/get-session-token | POST | Get temporary credentials |
| /sts/get-caller-identity | GET | Get caller identity |


# Translations

## NameToUuid (GET /uuids)

### Inputs

| Field | Type | Required? | Notes |
| --------- | -------- | ------------- | --------- |
| account (query param) | string | Yes | account login to translate |
| name (query param) | string | No | name of policy/user/role under the given account to translate. required if type is specified. specify multiple times for multiple translations |
| type (query param) | string | No | type of the names to translate (policy, user, role). required if any names are specified |

### Returns

Translation of account login and any names given. No error is returned for any
translations that don't exist, but no translation will be returned for that
name. Check for undefined.

### Errors

| Code | HTTP Status Code | Description |
| ---- | ---------------- | ----------- |
| AccountDoesNotExist | 404 | No account exists with the given login |
| BadRequestError | 400 | "account" was not specified |
| RedisError | 500 | Error contacting redis |

### Examples

    $ curl -is "http://localhost/uuids?account=fred" | json -Ha
    {
      "account": "83546bda-028d-11e2-aabe-17b87241f6ee"
    }

<!-- -->

    $ curl -is "http://localhost/uuids?account=fred&type=user&name=muskie_test_user&name=fakeuser" | json -Ha
    {
      "account": "83546bda-028d-11e2-aabe-17b87241f6ee",
      "uuids": {
        "muskie_test_user": "92543592-6018-62ae-fc60-ffb83f0b5157"
      }
    }


## UuidToName (GET /names)

### Inputs

| Field | Type | Required? | Notes |
| ----- | ---- | --------- | ----- |
| uuid (query param) | UUID | Yes | repeat param for multiple translations |

### Returns

Translation of uuid to account or user login, or role or policy name. No error
is returned for any translations that don't exist, but no translation will be
returned for that name. Check for undefined.

### Errors

| Code | HTTP Status Code | Description |
| ---- | ---------------- | ----------- |
| RedisError | 500 | Error contacting redis |

### Examples

    $ curl -is "http://localhost/names?uuid=83546bda-028d-11e2-aabe-17b87241f6ee&uuid=92543592-6018-62ae-fc60-ffb83f0b5157&uuid=00000000-0000-0000-0000-000000000000" | json -Ha
    {
      "83546bda-028d-11e2-aabe-17b87241f6ee": "fred",
      "92543592-6018-62ae-fc60-ffb83f0b5157": "muskie_test_user"
    }


# Troubleshooting


## Changes don't show up

If changes in UFDS aren't showing up in services that use mahi, there could be
a few things wrong.

Since mahi is split into two parts, if the mahi-replicator crashes or is taken
offline then mahi-server will still serve requests using the existing, stale
data in redis.

Check if mahi-replicator has crashed or is stuck.


## mahi-replicator has crashed

If mahi-replicator crashes, the most likely cause is it tried to apply a change
to redis but because of inconsistencies in the data, the transformation failed.

Inconsistencies in the redis data occur if mahi skips changes that it's
supposed to apply. This is always a bug. As an example, in the past, this has
been seen because UFDS returned changelogs entries out of order.

If the redis data becomes inconsistent with the data in UFDS, a cache rebuild is
required after the bug is fixed.

## mahi-replicator is stuck

Mahi-replicator may get stuck if it encounters a change it doesn't know how to
handle. To check if mahi-replicator is stuck, compare mahi's changenumber
UFDS's changenumber.

To get the latest UFDS changelog number run this on the headnode:

    sdc-ldap search -b "cn=latestchangenumber" "objectclass=*"

Then, get the changelog number from mahi by running this in the mahi zone:

    redis-cli -n $(json -f /opt/smartdc/mahi/etc/mahi2.json redis.db) get changenumber

The mahi number should be within ~10-15 changenumbers of the UFDS number. They
won't always match because of polling delay and because mahi doesn't update the
changenumber in redis if it sees a change it doesn't care about (e.g.
`updated_at` changes).

If mahi-replicator is stuck, the logs should indicate the change that mahi is
stuck on.

    cat $(svcs -L mahi-replicator) | bunyan

This is usually a bug in mahi. A cache rebuild is probalby not required after
the bug is fixed.


## Rebuilding the Redis Cache

Mahi stores its redis database on a zfs dataset so reboots don't require mahi
to start over from the beginning of time to rebuild the cache. However, there
are some times when rebuilding the cache is necessary. Follow these steps to
rebuild the cache.

1. In the mahi zone, disable registrar and mahi-server. This takes mahi out of
   DNS so services will not try to use this instance of mahi. HA setups (Manta)
   will continue to use other instances.

        svcadm disable registrar
        svcadm disable mahi-server

1. Disable mahi-replicator, flush the redis database and re-enable
   mahi-replicator.

        svcadm disable mahi-replicator
        redis-cli -n $(json -f /opt/smartdc/mahi/etc/mahi2.json redis.db || 0) flushdb
        svcadm enable mahi-replicator

  Or

        sh /opt/smartdc/mahi/bin/clearcache.sh

1. (Optional) Wait for mahi-replicator to catch back up to UFDS. You can follow
  the steps under "mahi-replicator is stuck" to see where mahi is at.

1. Enable mahi-server and registrar. Registrar's healthcheck won't pass and
   mahi-server will return 500s until mahi-replicator has caught up.

        svcadm enable mahi-server
        svcadm enable registrar

1. Done.
