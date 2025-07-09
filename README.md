<!--
    This Source Code Form is subject to the terms of the Mozilla Public
    License, v. 2.0. If a copy of the MPL was not distributed with this
    file, You can obtain one at http://mozilla.org/MPL/2.0/.
-->

<!--
    Copyright 2019 Joyent, Inc.
    Copyright 2025 Edgecast Cloud LLC.
-->

# mahi

This repository is part of the Triton Data Center and Manta projects.
For contribution guidelines, issues, and general documentation, visit the main
[Triton](http://github.com/TritonDataCenter/triton) and
[Manta](http://github.com/TritonDataCenter/manta) project pages.

Mahi is the authentication cache. It has two components: the replicator and the
server. The replicator pulls in account, user, role, group, and
key information from UFDS and caches them in a local redis instance.
The server is a restify server that talks to the redis instance.


## Active Branches

There are currently two active branches of this repository, for the two
active major versions of Manta. See the [mantav2 overview
document](https://github.com/TritonDataCenter/manta/blob/master/docs/mantav2.md) for
details on major Manta versions.

- [`master`](../../tree/master/) - For development of mantav2, the latest
  version of Manta. This is the version used by Triton.
- [`mantav1`](../../tree/mantav1/) - For development of mantav1, the long
  term support maintenance version of Manta.


## Interface

    GET /accounts/:accountid
    GET /accounts?login=:accountlogin
    GET /users/:userid
    GET /users?account=x&login=y&fallback=true
    GET /uuids?account=x&type=y&name=z1&name=z2
    GET /names?uuid=x1&uuid=x2
    GET /aws-auth/:accesskeyid
    POST /aws-verify


## Redis Schema

All data is stored in keys of the form `/uuid/<uuid>`. There are also mappings
for login or name to uuid, and sets that contain full lists of uuids.

    /uuid/<accountUUID> ->
    {
        type: "account",
        uuid: <uuid>,
        keys: {keyfp: key},
        groups: [str],
        login: <login>,
        approved_for_provisioning: bool
    }

    /uuid/<userUUID> ->
    {
        type: "user",
        uuid: <uuid>,
        account: <parentAccountUUID>,
        keys: {keyfp: key},
        accesskeys: {accessKeyId: secret},
        roles: [roleUUID],
        defaultRoles: [roleUUID],
        login: <login>,
    }

    /uuid/<policyUUID> ->
    {
        type: "policy",
        uuid: <uuid>,
        name: <name>,
        rules: [ [text, parsed], ..., [text, parsed] ],
        account: <parentAccountUUID>
    }

    /uuid/<roleUUID> ->
    {
        type: "role",
        uuid: <uuid>,
        name: <name>,
        account: <parentAccountUUID>,
        policies: [policyUUID]
    }

    /account/<accountLogin> -> accountUUID
    /user/<accountUUID>/<userLogin> -> userUUID
    /role/<accountUUID>/<roleName> -> roleUUID
    /policy/<accountUUID>/<policyName> -> policyUUID
    /accesskey/<accessKeyId> -> userUUID

    /set/accounts -> set of accountUUIDs
    /set/users/<account> -> set of userUUIDs
    /set/roles/<account> -> set of roleUUIDSs
    /set/policies/<account> -> set of policyUUIDs

## AWS Signature V4 Authentication

Mahi supports AWS Signature Version 4 (SigV4) authentication for S3 API compatibility.

    GET /aws-auth/:accesskeyid

Returns user information for the given AWS access key ID. 

Response:
```json
{
    "type": "account",
    "uuid": "user-uuid",
    "login": "username",
    "accesskeys": ["AKIA123456789EXAMPLE"],
    "approved_for_provisioning": true
}
```

    POST /aws-verify

Verifies an AWS Signature Version 4 request signature. Validates the authorization
header, timestamp, and signature against the stored access key secret.
Services requiring to use SigV4 auth should use this endpoint.

Request: Standard HTTP request with AWS4-HMAC-SHA256 authorization header
Response:
```json
{
    "valid": true,
    "accessKeyId": "AKIA123456789EXAMPLE", 
    "userUuid": "user-uuid"
}
```

## Testing

Auth data from tests/data is loaded into a fake redis implemented in node for
testing.
Run `make test`.


#### AWS SigV4 Endpoints

**Testing Access Key Lookup:**
```bash
# Get user information by access key ID
curl -i http://localhost:8080/aws-auth/AKIA123456789EXAMPLE

# Expected response:
# {
#   "type": "account", 
#   "uuid": "550e8400-e29b-41d4-a716-446655440001",
#   "login": "s3user",
#   "accesskeys": ["AKIA123456789EXAMPLE", "AKIA987654321EXAMPLE"],
#   "approved_for_provisioning": true
# }

# Test nonexistent access key
curl -i http://localhost:8080/aws-auth/AKIANONEXISTENT0001
# Expected: 404 ObjectDoesNotExist error
```

### Redis Data Inspection

**Check Access Key Storage:**
```bash
# Connect to Redis
redis-cli

# Check user record with access keys
redis> GET /uuid/550e8400-e29b-41d4-a716-446655440001
# Shows: {"accesskeys": {"AKIA123456789EXAMPLE": "secret..."}}

# Check reverse lookup mapping
redis> GET /accesskey/AKIA123456789EXAMPLE  
# Shows: 550e8400-e29b-41d4-a716-446655440001

```
