<!--
    This Source Code Form is subject to the terms of the Mozilla Public
    License, v. 2.0. If a copy of the MPL was not distributed with this
    file, You can obtain one at http://mozilla.org/MPL/2.0/.
-->

<!--
    Copyright (c) 2014, Joyent, Inc.
-->

# mahi

This repository is part of the Joyent SmartDataCenter project (SDC).  For
contribution guidelines, issues, and general documentation, visit the main
[SDC](http://github.com/joyent/sdc) project page.

# Overview

Mahi is the authentication cache. It has two components: the replicator and the
server. The replicator pulls in account, user, role, group, and
key information from UFDS and caches them in a local redis instance.
The server is a restify server that talks to the redis instance.


# Interface

    GET /accounts/:accountid
    GET /accounts?login=:accountlogin
    GET /users/:userid
    GET /users?account=x&login=y&fallback=true
    GET /uuids?account=x&type=y&name=z1&name=z2
    GET /names?uuid=x1&uuid=x2


# Redis Schema

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

    /set/accounts -> set of accountUUIDs
    /set/users/<account> -> set of userUUIDs
    /set/roles/<account> -> set of roleUUIDSs
    /set/policies/<account> -> set of policyUUIDs


# Testing

Auth data from tests/data is loaded into a fake redis implemented in node for
testing.
Run `make test`.
