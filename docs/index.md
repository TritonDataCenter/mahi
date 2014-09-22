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
    Copyright (c) 2014, Joyent, Inc.
-->

# Mahi

Mahi is the auth cache API used by [SmartDataCenter](https://github.com/joyent/sdc)
and [Manta](https://github.com/joyent/manta). It maintains a cache of user auth
data from [UFDS](https://github.com/joyent/sdc-ufds) in a local Redis and exposes
a REST API to that data.


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


# Userse

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

# Translations

## NameToUuid (GET /uuids)

### Inputs
|| **Field** || **Type** || **Required?** || **Notes** ||
|| account (query param) || string || Yes || account login to translate ||
|| name (query param) || string || No || name of policy/user/role under the given account to translate. required if type is specified. specify multiple times for multiple translations ||
|| type (query param) || string || No || type of the names to translate (policy, user, role). required if any names are specified ||

### Returns

Translation of account login and any names given. No error is returned for any
translations that don't exist, but no translation will be returned for that
name. Check for undefined.

### Errors

| Code | HTTP Status Code | Description |
| ---- | ---------------- | ----------- |
| AccountDoesNotExist | 404 | No account exists with the given login |
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
|| **Field** || **Type** || **Required?** || **Notes** ||
|| uuid (query param) || UUID || Yes || repeat param for multiple translations ||

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
