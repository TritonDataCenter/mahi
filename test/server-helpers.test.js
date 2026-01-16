/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2026 Edgecast Cloud LLC.
 */

/*
 * Unit tests for server.js exported helper functions.
 * These tests improve coverage without requiring full server integration.
 */

var nodeunit = require('nodeunit-plus');
var test = nodeunit.test;

var server = require('../lib/server/server.js');
var buildDefaultTrustPolicy = server.buildDefaultTrustPolicy;
var buildGetRoleResponse = server.buildGetRoleResponse;
var buildRoleDn = server.buildRoleDn;
var buildListRolesRoleObject = server.buildListRolesRoleObject;
var applyPagination = server.applyPagination;
var buildSecretConfig = server.buildSecretConfig;
var isMantaInstance = server.isMantaInstance;

/*
 * ==============================
 * SECTION 1: buildDefaultTrustPolicy Tests
 */

test('buildDefaultTrustPolicy: basic trust policy', function (t) {
    var result = buildDefaultTrustPolicy();
    t.ok(result, 'should return a trust policy');
    t.ok(typeof (result) === 'string', 'should return a string');

    var parsed = JSON.parse(result);
    t.ok(parsed.Version, 'should have Version');
    t.ok(parsed.Statement, 'should have Statement');
    t.ok(Array.isArray(parsed.Statement), 'Statement should be an array');
    t.end();
});

test('buildDefaultTrustPolicy: default allows AssumeRole', function (t) {
    var result = buildDefaultTrustPolicy();
    var parsed = JSON.parse(result);

    var hasAssumeRole = parsed.Statement.some(function (stmt) {
        if (stmt.Action === '*' || stmt.Action === 'sts:AssumeRole') {
            return (true);
        }
        if (Array.isArray(stmt.Action)) {
            return stmt.Action.some(function (a) {
                return (a === '*' || a === 'sts:AssumeRole');
            });
        }
        return (false);
    });
    t.ok(hasAssumeRole, 'should have AssumeRole or wildcard action');
    t.end();
});

/*
 * ==============================
 * SECTION 2: buildGetRoleResponse Tests
 */

test('buildGetRoleResponse: basic response', function (t) {
    var params = {
        accountUuid: '123456789012',
        role: {
            name: 'TestRole',
            uuid: 'role-id-123',
            path: '/',
            createtime: new Date('2025-01-01').toISOString(),
            assumerolepolicydocument: '{"Statement":[]}',
            description: 'A test role'
        }
    };
    var result = buildGetRoleResponse(params);

    t.ok(result, 'should return a response');
    t.ok(result.Role, 'should have Role');
    t.equal(result.Role.RoleName, params.role.name, 'RoleName should match');
    t.equal(result.Role.RoleId, params.role.uuid, 'RoleId should match');
    t.equal(result.Role.Path, params.role.path, 'Path should match');
    t.end();
});

test('buildGetRoleResponse: minimal params with defaults', function (t) {
    var params = {
        accountUuid: '123456789012',
        role: {
            name: 'MinRole',
            uuid: 'role-min'
            // no path, createtime, etc - should use defaults
        }
    };
    var result = buildGetRoleResponse(params);

    t.ok(result, 'should return a response');
    t.equal(result.Role.RoleName, 'MinRole', 'RoleName should match');
    t.equal(result.Role.Path, '/', 'Path should default to /');
    t.ok(result.Role.AssumeRolePolicyDocument, 'should have default policy');
    t.end();
});

test('buildGetRoleResponse: custom path', function (t) {
    var params = {
        accountUuid: '123456789012',
        role: {
            name: 'ServiceRole',
            uuid: 'role-svc',
            path: '/service/'
        }
    };
    var result = buildGetRoleResponse(params);

    t.ok(result.Role.Arn.indexOf('/service/') !== -1,
         'Arn should include path');
    t.equal(result.Role.Path, '/service/', 'Path should match');
    t.end();
});

/*
 * ==============================
 * SECTION 3: buildRoleDn Tests
 */

test('buildRoleDn: basic DN', function (t) {
    var roleUuid = 'role-uuid-123';
    var accountUuid = 'account-uuid-456';
    var result = buildRoleDn(roleUuid, accountUuid);

    t.ok(result, 'should return a DN');
    t.ok(typeof (result) === 'string', 'should be a string');
    t.ok(result.indexOf(roleUuid) !== -1, 'should contain role UUID');
    t.ok(result.indexOf(accountUuid) !== -1, 'should contain account UUID');
    t.end();
});

test('buildRoleDn: UUID format', function (t) {
    var roleUuid = '11111111-2222-3333-4444-555555555555';
    var accountUuid = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee';
    var result = buildRoleDn(roleUuid, accountUuid);

    var expectedRoleUuid = 'role-uuid=11111111-2222-3333-4444-555555555555';
    t.ok(result.indexOf(expectedRoleUuid) !== -1, 'should contain role UUID');
    t.ok(result.indexOf('o=smartdc') !== -1, 'should have smartdc base');
    t.end();
});

/*
 * ==============================
 * SECTION 4: buildListRolesRoleObject Tests
 */

test('buildListRolesRoleObject: basic role object', function (t) {
    var params = {
        accountUuid: '123456789012',
        roleObj: {
            name: 'ListedRole',
            uuid: 'list-role-id',
            path: '/service/',
            createtime: new Date('2025-06-15').toISOString(),
            assumerolepolicydocument: '{"Statement":[]}',
            description: 'Listed role description'
        }
    };
    var result = buildListRolesRoleObject(params);

    t.ok(result, 'should return a role object');
    t.equal(result.RoleName, params.roleObj.name, 'RoleName should match');
    t.equal(result.Path, params.roleObj.path, 'Path should match');
    t.ok(result.Arn.indexOf(':role/service/ListedRole') !== -1,
         'Arn should include path and name');
    t.end();
});

test('buildListRolesRoleObject: minimal params with defaults', function (t) {
    var params = {
        accountUuid: '123456789012',
        roleObj: {
            name: 'MinListRole'
            // no path, createtime, etc
        }
    };
    var result = buildListRolesRoleObject(params);

    t.ok(result, 'should return a role object');
    t.equal(result.RoleName, 'MinListRole', 'RoleName should match');
    t.equal(result.Path, '/', 'Path should default to /');
    t.ok(result.AssumeRolePolicyDocument, 'should have default policy');
    t.end();
});

/*
 * ==============================
 * SECTION 5: applyPagination Tests
 */

test('applyPagination: no pagination params', function (t) {
    var roles = [
        { RoleName: 'Role1' },
        { RoleName: 'Role2' },
        { RoleName: 'Role3' }
    ];
    var result = applyPagination(roles, null, 100);

    t.ok(result, 'should return result');
    t.ok(result.paginatedRoles, 'should have paginatedRoles array');
    t.equal(result.paginatedRoles.length, 3, 'should return all roles');
    t.ok(!result.isTruncated, 'should not be truncated');
    t.end();
});

test('applyPagination: with maxItems limit', function (t) {
    var roles = [
        { RoleName: 'Role1' },
        { RoleName: 'Role2' },
        { RoleName: 'Role3' },
        { RoleName: 'Role4' }
    ];
    var result = applyPagination(roles, null, 2);

    t.ok(result, 'should return result');
    t.equal(result.paginatedRoles.length, 2, 'should return limited roles');
    t.ok(result.isTruncated, 'should be truncated');
    t.equal(result.nextMarker, 'Role2', 'should have marker for next page');
    t.end();
});

test('applyPagination: with marker', function (t) {
    var roles = [
        { RoleName: 'RoleA' },
        { RoleName: 'RoleB' },
        { RoleName: 'RoleC' },
        { RoleName: 'RoleD' }
    ];
    var result = applyPagination(roles, 'RoleB', 100);

    t.ok(result, 'should return result');
    t.equal(result.paginatedRoles.length, 2,
        'should return roles after marker');
    t.equal(result.paginatedRoles[0].RoleName, 'RoleC',
        'first should be RoleC');
    t.end();
});

test('applyPagination: with marker and maxItems', function (t) {
    var roles = [
        { RoleName: 'R1' },
        { RoleName: 'R2' },
        { RoleName: 'R3' },
        { RoleName: 'R4' },
        { RoleName: 'R5' }
    ];
    var result = applyPagination(roles, 'R2', 2);

    t.ok(result, 'should return result');
    t.equal(result.paginatedRoles.length, 2, 'should respect maxItems');
    t.equal(result.paginatedRoles[0].RoleName, 'R3',
        'should start after marker');
    t.ok(result.isTruncated, 'should be truncated');
    t.end();
});

test('applyPagination: empty array', function (t) {
    var roles = [];
    var result = applyPagination(roles, null, 100);

    t.ok(result, 'should return result');
    t.ok(result.paginatedRoles, 'should have paginatedRoles array');
    t.equal(result.paginatedRoles.length, 0, 'should return empty array');
    t.ok(!result.isTruncated, 'should not be truncated');
    t.end();
});

test('applyPagination: marker at end of list', function (t) {
    var roles = [
        { RoleName: 'First' },
        { RoleName: 'Last' }
    ];
    var result = applyPagination(roles, 'Last', 100);

    t.ok(result, 'should return result');
    t.equal(result.paginatedRoles.length, 0, 'no roles after last marker');
    t.ok(!result.isTruncated, 'should not be truncated');
    t.end();
});

test('applyPagination: marker not found', function (t) {
    var roles = [
        { RoleName: 'Role1' },
        { RoleName: 'Role2' }
    ];
    var result = applyPagination(roles, 'NotExists', 100);

    t.ok(result, 'should return result');
    // Should start from beginning if marker not found
    t.equal(result.paginatedRoles.length, 2, 'should return all roles');
    t.end();
});

/*
 * ==============================
 * SECTION 6: buildSecretConfig Tests
 */

test('buildSecretConfig: valid config', function (t) {
    var sessionConfig = {
        secretKey: 'test-secret-key-12345',
        secretKeyId: 'key-id-1',
        gracePeriod: 3600
    };
    var result = buildSecretConfig(sessionConfig);

    t.ok(result, 'should return config');
    t.ok(result.primarySecret, 'should have primarySecret');
    t.equal(result.primarySecret.key, sessionConfig.secretKey,
            'primarySecret key should match');
    t.equal(result.primarySecret.keyId, sessionConfig.secretKeyId,
            'primarySecret keyId should match');
    t.end();
});

test('buildSecretConfig: missing secretKey throws', function (t) {
    var sessionConfig = {
        secretKeyId: 'key-id',
        gracePeriod: 3600
        // missing secretKey
    };
    try {
        buildSecretConfig(sessionConfig);
        t.ok(false, 'should have thrown');
    } catch (e) {
        t.ok(e.message.indexOf('secret') !== -1,
             'error should mention secret');
    }
    t.end();
});

test('buildSecretConfig: missing gracePeriod throws', function (t) {
    var sessionConfig = {
        secretKey: 'test-secret',
        secretKeyId: 'key-id'
        // missing gracePeriod
    };
    try {
        buildSecretConfig(sessionConfig);
        t.ok(false, 'should have thrown');
    } catch (e) {
        t.ok(e.message.indexOf('grace') !== -1,
             'error should mention grace period');
    }
    t.end();
});

/*
 * ==============================
 * SECTION 7: isMantaInstance Tests
 */

test('isMantaInstance: returns boolean', function (t) {
    var result = isMantaInstance();
    t.ok(typeof (result) === 'boolean', 'should return boolean');
    t.end();
});

console.log('✓ Server helper tests loaded');
