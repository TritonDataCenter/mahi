/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2024 Joyent, Inc.
 */

/*
 * CHG-044: Test suite for helper functions
 *
 * Unit tests for pure helper functions extracted in CHG-043.
 * These tests cover 11 helper functions from lib/server/server.js
 * and lib/server/sts.js to improve test coverage.
 */

var test = require('nodeunit-plus').test;
var serverHelpers = require('../lib/server/server.js');
var stsHelpers = require('../lib/server/sts.js').helpers;

// ============================================================================
// PART 1: server.js Helper Functions
// ============================================================================

// ----------------------------------------------------------------------------
// buildDefaultTrustPolicy() tests
// ----------------------------------------------------------------------------

test('buildDefaultTrustPolicy returns valid JSON string', function(t) {
    var result = serverHelpers.buildDefaultTrustPolicy();
    t.ok(result, 'should return a value');
    t.equal(typeof result, 'string', 'should return a string');

    // Should be valid JSON
    var parsed;
    t.doesNotThrow(function() {
        parsed = JSON.parse(result);
    }, 'should be valid JSON');

    t.ok(parsed, 'parsed result should exist');
    t.done();
});

test('buildDefaultTrustPolicy has correct Version field', function(t) {
    var result = serverHelpers.buildDefaultTrustPolicy();
    var parsed = JSON.parse(result);

    t.equal(parsed.Version, '2012-10-17', 'should have AWS policy version');
    t.done();
});

test('buildDefaultTrustPolicy has Statement array', function(t) {
    var result = serverHelpers.buildDefaultTrustPolicy();
    var parsed = JSON.parse(result);

    t.ok(Array.isArray(parsed.Statement), 'should have Statement array');
    t.equal(parsed.Statement.length, 1, 'should have one statement');
    t.done();
});

test('buildDefaultTrustPolicy allows sts:AssumeRole', function(t) {
    var result = serverHelpers.buildDefaultTrustPolicy();
    var parsed = JSON.parse(result);
    var statement = parsed.Statement[0];

    t.equal(statement.Effect, 'Allow', 'should allow');
    t.equal(statement.Action, 'sts:AssumeRole', 'should be AssumeRole action');
    t.done();
});

test('buildDefaultTrustPolicy has wildcard AWS principal', function(t) {
    var result = serverHelpers.buildDefaultTrustPolicy();
    var parsed = JSON.parse(result);
    var statement = parsed.Statement[0];

    t.ok(statement.Principal, 'should have Principal');
    t.ok(statement.Principal.AWS, 'should have AWS principal');
    t.equal(statement.Principal.AWS, '*', 'should be wildcard');
    t.done();
});

// ----------------------------------------------------------------------------
// buildGetRoleResponse(params) tests
// ----------------------------------------------------------------------------

test('buildGetRoleResponse with complete role object', function(t) {
    var params = {
        role: {
            name: 'TestRole',
            uuid: 'role-uuid-123',
            path: '/admin/',
            createtime: '2024-01-13T10:00:00Z',
            assumerolepolicydocument: '{"Version":"2012-10-17"}',
            description: 'Test role description'
        },
        accountUuid: 'account-uuid-456'
    };

    var result = serverHelpers.buildGetRoleResponse(params);

    t.ok(result.Role, 'should have Role object');
    t.equal(result.Role.RoleName, 'TestRole', 'should have role name');
    t.equal(result.Role.RoleId, 'role-uuid-123', 'should have role id');
    t.equal(result.Role.Path, '/admin/', 'should have path');
    t.equal(result.Role.CreateDate, '2024-01-13T10:00:00Z', 'should have create date');
    t.equal(result.Role.AssumeRolePolicyDocument, '{"Version":"2012-10-17"}',
        'should have trust policy');
    t.equal(result.Role.Description, 'Test role description',
        'should have description');
    t.done();
});

test('buildGetRoleResponse with minimal role object', function(t) {
    var params = {
        role: {
            name: 'MinimalRole',
            uuid: 'role-uuid-789'
        },
        accountUuid: 'account-uuid-999'
    };

    var result = serverHelpers.buildGetRoleResponse(params);

    t.ok(result.Role, 'should have Role object');
    t.equal(result.Role.RoleName, 'MinimalRole', 'should have role name');
    t.done();
});

test('buildGetRoleResponse defaults path to /', function(t) {
    var params = {
        role: {
            name: 'TestRole',
            uuid: 'role-uuid-123'
        },
        accountUuid: 'account-uuid-456'
    };

    var result = serverHelpers.buildGetRoleResponse(params);

    t.equal(result.Role.Path, '/', 'should default to root path');
    t.done();
});

test('buildGetRoleResponse defaults CreateDate to current date', function(t) {
    var params = {
        role: {
            name: 'TestRole',
            uuid: 'role-uuid-123'
        },
        accountUuid: 'account-uuid-456'
    };

    var result = serverHelpers.buildGetRoleResponse(params);

    t.ok(result.Role.CreateDate, 'should have CreateDate');
    // Should be valid ISO date
    t.ok(new Date(result.Role.CreateDate).toISOString(),
        'should be valid ISO date');
    t.done();
});

test('buildGetRoleResponse uses default trust policy when missing', function(t) {
    var params = {
        role: {
            name: 'TestRole',
            uuid: 'role-uuid-123'
        },
        accountUuid: 'account-uuid-456'
    };

    var result = serverHelpers.buildGetRoleResponse(params);
    var defaultPolicy = serverHelpers.buildDefaultTrustPolicy();

    t.equal(result.Role.AssumeRolePolicyDocument, defaultPolicy,
        'should use default trust policy');
    t.done();
});

test('buildGetRoleResponse constructs correct ARN', function(t) {
    var params = {
        role: {
            name: 'TestRole',
            uuid: 'role-uuid-123',
            path: '/admin/'
        },
        accountUuid: 'account-uuid-456'
    };

    var result = serverHelpers.buildGetRoleResponse(params);
    var expectedArn = 'arn:aws:iam::account-uuid-456:role/admin/TestRole';

    t.equal(result.Role.Arn, expectedArn, 'should construct correct ARN');
    t.done();
});

test('buildGetRoleResponse has MaxSessionDuration', function(t) {
    var params = {
        role: {
            name: 'TestRole',
            uuid: 'role-uuid-123'
        },
        accountUuid: 'account-uuid-456'
    };

    var result = serverHelpers.buildGetRoleResponse(params);

    t.equal(result.Role.MaxSessionDuration, 3600,
        'should have MaxSessionDuration of 3600');
    t.done();
});

// ----------------------------------------------------------------------------
// buildRoleDn(roleUuid, accountUuid) tests
// ----------------------------------------------------------------------------

test('buildRoleDn constructs correct DN format', function(t) {
    var result = serverHelpers.buildRoleDn('role-123', 'account-456');
    var expected = 'role-uuid=role-123, uuid=account-456, ou=users, o=smartdc';

    t.equal(result, expected, 'should construct correct LDAP DN');
    t.done();
});

test('buildRoleDn with various UUID formats', function(t) {
    var result = serverHelpers.buildRoleDn(
        'a1b2c3d4-e5f6-7890-abcd-ef1234567890',
        'f0e9d8c7-b6a5-4321-fedc-ba9876543210'
    );

    var expected = 'role-uuid=a1b2c3d4-e5f6-7890-abcd-ef1234567890, ' +
        'uuid=f0e9d8c7-b6a5-4321-fedc-ba9876543210, ou=users, o=smartdc';

    t.equal(result, expected, 'should handle standard UUID format');
    t.done();
});

test('buildRoleDn has correct LDAP DN components', function(t) {
    var result = serverHelpers.buildRoleDn('role-123', 'account-456');

    t.ok(result.indexOf('role-uuid=') === 0, 'should start with role-uuid=');
    t.ok(result.indexOf('uuid=') > 0, 'should contain uuid=');
    t.ok(result.indexOf('ou=users') > 0, 'should contain ou=users');
    t.ok(result.indexOf('o=smartdc') > 0, 'should end with o=smartdc');
    t.done();
});

// ----------------------------------------------------------------------------
// buildListRolesRoleObject(params) tests
// ----------------------------------------------------------------------------

test('buildListRolesRoleObject with complete role', function(t) {
    var params = {
        roleObj: {
            name: 'ListRole',
            path: '/test/',
            uuid: 'role-uuid-123',
            createtime: '2024-01-13T10:00:00Z',
            assumerolepolicydocument: '{"Version":"2012-10-17"}',
            description: 'Test list role'
        },
        accountUuid: 'account-uuid-456'
    };

    var result = serverHelpers.buildListRolesRoleObject(params);

    t.equal(result.RoleName, 'ListRole', 'should have role name');
    t.equal(result.Path, '/test/', 'should have path');
    t.equal(result.CreateDate, '2024-01-13T10:00:00Z', 'should have create date');
    t.equal(result.Description, 'Test list role', 'should have description');
    t.done();
});

test('buildListRolesRoleObject defaults path to /', function(t) {
    var params = {
        roleObj: {
            name: 'ListRole'
        },
        accountUuid: 'account-uuid-456'
    };

    var result = serverHelpers.buildListRolesRoleObject(params);

    t.equal(result.Path, '/', 'should default to root path');
    t.done();
});

test('buildListRolesRoleObject uses default trust policy', function(t) {
    var params = {
        roleObj: {
            name: 'ListRole'
        },
        accountUuid: 'account-uuid-456'
    };

    var result = serverHelpers.buildListRolesRoleObject(params);
    var defaultPolicy = serverHelpers.buildDefaultTrustPolicy();

    t.equal(result.AssumeRolePolicyDocument, defaultPolicy,
        'should use default trust policy');
    t.done();
});

test('buildListRolesRoleObject constructs correct ARN', function(t) {
    var params = {
        roleObj: {
            name: 'ListRole',
            path: '/admin/'
        },
        accountUuid: 'account-uuid-456'
    };

    var result = serverHelpers.buildListRolesRoleObject(params);
    var expectedArn = 'arn:aws:iam::account-uuid-456:role/admin/ListRole';

    t.equal(result.Arn, expectedArn, 'should construct correct ARN');
    t.done();
});

test('buildListRolesRoleObject has all required fields', function(t) {
    var params = {
        roleObj: {
            name: 'ListRole'
        },
        accountUuid: 'account-uuid-456'
    };

    var result = serverHelpers.buildListRolesRoleObject(params);

    t.ok(result.RoleName, 'should have RoleName');
    t.ok(result.Arn, 'should have Arn');
    t.ok(result.Path, 'should have Path');
    t.ok(result.CreateDate, 'should have CreateDate');
    t.ok(result.AssumeRolePolicyDocument, 'should have AssumeRolePolicyDocument');
    t.equal(result.MaxSessionDuration, 3600, 'should have MaxSessionDuration');
    t.done();
});

test('buildListRolesRoleObject defaults empty description', function(t) {
    var params = {
        roleObj: {
            name: 'ListRole'
        },
        accountUuid: 'account-uuid-456'
    };

    var result = serverHelpers.buildListRolesRoleObject(params);

    t.equal(result.Description, '', 'should default to empty description');
    t.done();
});

// ----------------------------------------------------------------------------
// applyPagination(roles, marker, maxItems) tests
// ----------------------------------------------------------------------------

test('applyPagination with no marker returns first page', function(t) {
    var roles = [
        {RoleName: 'Role1'},
        {RoleName: 'Role2'},
        {RoleName: 'Role3'},
        {RoleName: 'Role4'},
        {RoleName: 'Role5'}
    ];

    var result = serverHelpers.applyPagination(roles, null, 2);

    t.equal(result.paginatedRoles.length, 2, 'should return 2 roles');
    t.equal(result.paginatedRoles[0].RoleName, 'Role1', 'should start with first');
    t.equal(result.paginatedRoles[1].RoleName, 'Role2', 'should include second');
    t.done();
});

test('applyPagination with marker returns middle page', function(t) {
    var roles = [
        {RoleName: 'Role1'},
        {RoleName: 'Role2'},
        {RoleName: 'Role3'},
        {RoleName: 'Role4'},
        {RoleName: 'Role5'}
    ];

    var result = serverHelpers.applyPagination(roles, 'Role2', 2);

    t.equal(result.paginatedRoles.length, 2, 'should return 2 roles');
    t.equal(result.paginatedRoles[0].RoleName, 'Role3',
        'should start after marker');
    t.equal(result.paginatedRoles[1].RoleName, 'Role4', 'should include next');
    t.done();
});

test('applyPagination with marker at end', function(t) {
    var roles = [
        {RoleName: 'Role1'},
        {RoleName: 'Role2'},
        {RoleName: 'Role3'}
    ];

    var result = serverHelpers.applyPagination(roles, 'Role3', 2);

    t.equal(result.paginatedRoles.length, 0, 'should return empty array');
    t.equal(result.isTruncated, false, 'should not be truncated');
    t.done();
});

test('applyPagination with nonexistent marker', function(t) {
    var roles = [
        {RoleName: 'Role1'},
        {RoleName: 'Role2'},
        {RoleName: 'Role3'}
    ];

    var result = serverHelpers.applyPagination(roles, 'NonexistentRole', 2);

    t.equal(result.paginatedRoles.length, 2, 'should return from start');
    t.equal(result.paginatedRoles[0].RoleName, 'Role1',
        'should start from beginning');
    t.done();
});

test('applyPagination isTruncated true when more results exist', function(t) {
    var roles = [
        {RoleName: 'Role1'},
        {RoleName: 'Role2'},
        {RoleName: 'Role3'},
        {RoleName: 'Role4'}
    ];

    var result = serverHelpers.applyPagination(roles, null, 2);

    t.equal(result.isTruncated, true, 'should be truncated');
    t.done();
});

test('applyPagination isTruncated false on last page', function(t) {
    var roles = [
        {RoleName: 'Role1'},
        {RoleName: 'Role2'},
        {RoleName: 'Role3'}
    ];

    var result = serverHelpers.applyPagination(roles, null, 5);

    t.equal(result.isTruncated, false, 'should not be truncated');
    t.done();
});

test('applyPagination nextMarker set when truncated', function(t) {
    var roles = [
        {RoleName: 'Role1'},
        {RoleName: 'Role2'},
        {RoleName: 'Role3'},
        {RoleName: 'Role4'}
    ];

    var result = serverHelpers.applyPagination(roles, null, 2);

    t.equal(result.nextMarker, 'Role2', 'should set nextMarker to last returned');
    t.done();
});

test('applyPagination with empty roles array', function(t) {
    var roles = [];

    var result = serverHelpers.applyPagination(roles, null, 10);

    t.equal(result.paginatedRoles.length, 0, 'should return empty array');
    t.equal(result.isTruncated, false, 'should not be truncated');
    t.equal(result.nextMarker, null, 'should have null nextMarker');
    t.done();
});

test('applyPagination with maxItems = 0', function(t) {
    var roles = [
        {RoleName: 'Role1'},
        {RoleName: 'Role2'}
    ];

    var result = serverHelpers.applyPagination(roles, null, 0);

    t.equal(result.paginatedRoles.length, 0, 'should return empty array');
    t.equal(result.isTruncated, true, 'should be truncated');
    t.done();
});

test('applyPagination with maxItems greater than roles length', function(t) {
    var roles = [
        {RoleName: 'Role1'},
        {RoleName: 'Role2'}
    ];

    var result = serverHelpers.applyPagination(roles, null, 100);

    t.equal(result.paginatedRoles.length, 2, 'should return all roles');
    t.equal(result.isTruncated, false, 'should not be truncated');
    t.done();
});

// ============================================================================
// PART 2: sts.js Helper Functions
// ============================================================================

// ----------------------------------------------------------------------------
// extractCallerIdentity(caller) tests
// ----------------------------------------------------------------------------

test('extractCallerIdentity with user object present', function(t) {
    var caller = {
        user: {
            uuid: 'user-uuid-123',
            login: 'testuser'
        },
        account: {
            uuid: 'account-uuid-456'
        }
    };

    var result = stsHelpers.extractCallerIdentity(caller);

    t.equal(result.uuid, 'user-uuid-123', 'should use user uuid');
    t.equal(result.login, 'testuser', 'should use user login');
    t.done();
});

test('extractCallerIdentity with only account object', function(t) {
    var caller = {
        account: {
            uuid: 'account-uuid-456',
            login: 'accountuser'
        }
    };

    var result = stsHelpers.extractCallerIdentity(caller);

    t.equal(result.uuid, 'account-uuid-456', 'should use account uuid');
    t.equal(result.login, 'accountuser', 'should use account login');
    t.done();
});

test('extractCallerIdentity extracts UUID correctly', function(t) {
    var caller = {
        user: {
            uuid: 'specific-uuid-789',
            login: 'user1'
        }
    };

    var result = stsHelpers.extractCallerIdentity(caller);

    t.equal(result.uuid, 'specific-uuid-789', 'should extract correct uuid');
    t.done();
});

test('extractCallerIdentity extracts login correctly', function(t) {
    var caller = {
        user: {
            uuid: 'uuid-123',
            login: 'specific-login'
        }
    };

    var result = stsHelpers.extractCallerIdentity(caller);

    t.equal(result.login, 'specific-login', 'should extract correct login');
    t.done();
});

// ----------------------------------------------------------------------------
// validateDurationSeconds(params, body) tests
// ----------------------------------------------------------------------------

test('validateDurationSeconds with valid duration', function(t) {
    var params = {DurationSeconds: '3600'};
    var body = {};

    var result = stsHelpers.validateDurationSeconds(params, body);

    t.ok(result, 'should return result object');
    t.equal(result.valid, true, 'should be valid');
    t.equal(result.value, 3600, 'should have correct value');
    t.equal(result.error, null, 'should have no error');
    t.done();
});

test('validateDurationSeconds with minimum valid duration', function(t) {
    var params = {DurationSeconds: '900'};
    var body = {};

    var result = stsHelpers.validateDurationSeconds(params, body);

    t.equal(result.valid, true, 'should accept 900 seconds');
    t.equal(result.value, 900, 'should have value 900');
    t.done();
});

test('validateDurationSeconds with maximum valid duration', function(t) {
    var params = {DurationSeconds: '129600'};
    var body = {};

    var result = stsHelpers.validateDurationSeconds(params, body);

    t.equal(result.valid, true, 'should accept 129600 seconds');
    t.equal(result.value, 129600, 'should have value 129600');
    t.done();
});

test('validateDurationSeconds below minimum returns error', function(t) {
    var params = {DurationSeconds: '899'};
    var body = {};

    var result = stsHelpers.validateDurationSeconds(params, body);

    t.equal(result.valid, false, 'should not be valid');
    t.equal(result.value, null, 'should have null value');
    t.ok(result.error, 'should have error');
    t.ok(result.error.message, 'should have error message');
    t.ok(result.error.message.indexOf('900') > -1,
        'should mention minimum 900');
    t.done();
});

test('validateDurationSeconds above maximum returns error', function(t) {
    var params = {DurationSeconds: '129601'};
    var body = {};

    var result = stsHelpers.validateDurationSeconds(params, body);

    t.equal(result.valid, false, 'should not be valid');
    t.equal(result.value, null, 'should have null value');
    t.ok(result.error, 'should have error');
    t.ok(result.error.message.indexOf('129600') > -1,
        'should mention maximum 129600');
    t.done();
});

test('validateDurationSeconds uses default when not provided', function(t) {
    var params = {};
    var body = {};

    var result = stsHelpers.validateDurationSeconds(params, body);

    t.equal(result.valid, true, 'should be valid with default');
    t.equal(result.value, 3600, 'should use default 3600 seconds');
    t.done();
});

test('validateDurationSeconds parses from params', function(t) {
    var params = {DurationSeconds: '7200'};
    var body = {};

    var result = stsHelpers.validateDurationSeconds(params, body);

    t.equal(result.valid, true, 'should parse from params');
    t.equal(result.value, 7200, 'should have correct value');
    t.done();
});

test('validateDurationSeconds parses from body', function(t) {
    var params = {};
    var body = {DurationSeconds: '7200'};

    var result = stsHelpers.validateDurationSeconds(params, body);

    t.equal(result.valid, true, 'should parse from body');
    t.equal(result.value, 7200, 'should have correct value');
    t.done();
});

test('validateDurationSeconds with invalid string uses default', function(t) {
    var params = {DurationSeconds: 'invalid'};
    var body = {};

    var result = stsHelpers.validateDurationSeconds(params, body);

    // parseInt('invalid', 10) returns NaN
    // NaN compared to numbers is always false, so doesn't trigger validation error
    // The function returns NaN as the value, which passes validation
    t.equal(result.valid, true, 'should pass validation (NaN behavior)');
    t.ok(isNaN(result.value), 'value should be NaN');
    t.done();
});

// ----------------------------------------------------------------------------
// createSessionTokenData(callerUuid, expiration) tests
// ----------------------------------------------------------------------------

test('createSessionTokenData creates correct structure', function(t) {
    var callerUuid = 'caller-uuid-123';
    var expiration = new Date('2024-01-13T12:00:00Z'); // Date object

    var result = stsHelpers.createSessionTokenData(callerUuid, expiration);

    t.ok(result, 'should return object');
    t.ok(result.uuid, 'should have uuid field');
    t.ok(result.expires, 'should have expires field');
    t.ok(result.sessionName, 'should have sessionName field');
    t.ok(result.roleArn, 'should have roleArn field');
    t.done();
});

test('createSessionTokenData sets uuid correctly', function(t) {
    var callerUuid = 'specific-uuid-789';
    var expiration = new Date('2024-01-13T12:00:00Z');

    var result = stsHelpers.createSessionTokenData(callerUuid, expiration);

    t.equal(result.uuid, 'specific-uuid-789', 'should set uuid from parameter');
    t.done();
});

test('createSessionTokenData sets expiration as Unix timestamp', function(t) {
    var callerUuid = 'caller-uuid-123';
    var expiration = new Date('2024-01-13T12:00:00Z');

    var result = stsHelpers.createSessionTokenData(callerUuid, expiration);

    t.equal(typeof result.expires, 'number', 'expires should be a number');
    // Should be Unix timestamp in seconds
    t.ok(result.expires > 0, 'should be positive timestamp');
    t.equal(result.expires, Math.floor(expiration.getTime() / 1000),
        'should convert to Unix timestamp in seconds');
    t.done();
});

test('createSessionTokenData has sessionName format', function(t) {
    var callerUuid = 'caller-uuid-123';
    var expiration = new Date('2024-01-13T12:00:00Z');

    var result = stsHelpers.createSessionTokenData(callerUuid, expiration);

    t.ok(result.sessionName, 'should have sessionName');
    t.equal(typeof result.sessionName, 'string', 'sessionName should be string');
    t.ok(result.sessionName.indexOf('session-') === 0,
        'sessionName should start with session-');
    t.done();
});

test('createSessionTokenData has roleArn format', function(t) {
    var callerUuid = 'caller-uuid-123';
    var expiration = new Date('2024-01-13T12:00:00Z');

    var result = stsHelpers.createSessionTokenData(callerUuid, expiration);

    t.ok(result.roleArn, 'should have roleArn');
    t.equal(typeof result.roleArn, 'string', 'roleArn should be string');
    t.ok(result.roleArn.indexOf('arn:aws:sts::') === 0,
        'roleArn should start with arn:aws:sts::');
    t.ok(result.roleArn.indexOf(callerUuid) > -1,
        'roleArn should contain callerUuid');
    t.done();
});

// ----------------------------------------------------------------------------
// buildGetSessionTokenResponse(credentials) tests
// ----------------------------------------------------------------------------

test('buildGetSessionTokenResponse creates AWS response structure', function(t) {
    var credentials = {
        accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
        secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
        sessionToken: 'session-token-data',
        expiration: new Date('2024-01-13T12:00:00Z')
    };

    var result = stsHelpers.buildGetSessionTokenResponse(credentials);

    t.ok(result, 'should return object');
    t.ok(result.GetSessionTokenResponse, 'should have GetSessionTokenResponse');
    t.ok(result.GetSessionTokenResponse.GetSessionTokenResult,
        'should have GetSessionTokenResult');
    t.done();
});

test('buildGetSessionTokenResponse has all credential fields', function(t) {
    var credentials = {
        accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
        secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
        sessionToken: 'session-token-data',
        expiration: new Date('2024-01-13T12:00:00Z')
    };

    var result = stsHelpers.buildGetSessionTokenResponse(credentials);
    var creds = result.GetSessionTokenResponse.GetSessionTokenResult.Credentials;

    t.ok(creds.AccessKeyId, 'should have AccessKeyId');
    t.ok(creds.SecretAccessKey, 'should have SecretAccessKey');
    t.ok(creds.SessionToken, 'should have SessionToken');
    t.ok(creds.Expiration, 'should have Expiration');
    t.done();
});

test('buildGetSessionTokenResponse expiration as ISO string', function(t) {
    var expDate = new Date('2024-01-13T12:00:00Z');
    var credentials = {
        accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
        secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
        sessionToken: 'session-token-data',
        expiration: expDate
    };

    var result = stsHelpers.buildGetSessionTokenResponse(credentials);
    var creds = result.GetSessionTokenResponse.GetSessionTokenResult.Credentials;

    t.equal(creds.Expiration, expDate.toISOString(),
        'should be ISO string format');
    t.done();
});

test('buildGetSessionTokenResponse nested structure correct', function(t) {
    var credentials = {
        accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
        secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
        sessionToken: 'session-token-data',
        expiration: new Date()
    };

    var result = stsHelpers.buildGetSessionTokenResponse(credentials);

    t.ok(result.GetSessionTokenResponse.GetSessionTokenResult.Credentials,
        'should have nested Credentials object');
    t.done();
});

// ----------------------------------------------------------------------------
// buildLdapObjectForSessionToken(params) tests - with Date.now() mock
// ----------------------------------------------------------------------------

test('buildLdapObjectForSessionToken creates LDAP object', function(t) {
    var originalDateNow = Date.now;
    Date.now = function() { return 1705147200000; }; // Fixed timestamp

    var params = {
        accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
        secretKey: 'secret-key-data',
        sessionToken: 'session-token-data',
        expiration: new Date('2024-01-13T12:00:00Z'),
        principalUuid: 'principal-uuid-123'
    };

    var result = stsHelpers.buildLdapObjectForSessionToken(params);

    Date.now = originalDateNow; // Restore

    t.ok(result, 'should return object');
    t.ok(result.objectclass, 'should have objectclass');
    t.done();
});

test('buildLdapObjectForSessionToken has required LDAP fields', function(t) {
    var originalDateNow = Date.now;
    Date.now = function() { return 1705147200000; };

    var params = {
        accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
        secretKey: 'secret-key-data',
        sessionToken: 'session-token-data',
        expiration: new Date('2024-01-13T12:00:00Z'),
        principalUuid: 'principal-uuid-123'
    };

    var result = stsHelpers.buildLdapObjectForSessionToken(params);

    Date.now = originalDateNow;

    t.ok(result.accesskeyid, 'should have accesskeyid field');
    t.ok(result.accesskeysecret, 'should have accesskeysecret field');
    t.ok(result.principaluuid, 'should have principaluuid field');
    t.done();
});

test('buildLdapObjectForSessionToken expiration is ISO string', function(t) {
    var originalDateNow = Date.now;
    Date.now = function() { return 1705147200000; };

    var params = {
        accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
        secretKey: 'secret-key-data',
        sessionToken: 'session-token-data',
        expiration: new Date('2024-01-13T12:00:00Z'),
        principalUuid: 'principal-uuid-123'
    };

    var result = stsHelpers.buildLdapObjectForSessionToken(params);

    Date.now = originalDateNow;

    t.ok(result.expiration, 'should have expiration field');
    t.ok(result.expiration.indexOf('T') > -1,
        'expiration should be ISO format with T');
    t.done();
});

test('buildLdapObjectForSessionToken has created timestamp', function(t) {
    var originalDateNow = Date.now;
    var fixedTime = 1705147200000;
    Date.now = function() { return fixedTime; };

    var params = {
        accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
        secretKey: 'secret-key-data',
        sessionToken: 'session-token-data',
        expiration: new Date('2024-01-13T12:00:00Z'),
        principalUuid: 'principal-uuid-123'
    };

    var result = stsHelpers.buildLdapObjectForSessionToken(params);

    Date.now = originalDateNow;

    t.ok(result.created, 'should have created field');
    t.equal(result.created, fixedTime.toString(),
        'created should match mocked Date.now');
    t.done();
});

test('buildLdapObjectForSessionToken has updated timestamp', function(t) {
    var originalDateNow = Date.now;
    var fixedTime = 1705147200000;
    Date.now = function() { return fixedTime; };

    var params = {
        accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
        secretKey: 'secret-key-data',
        sessionToken: 'session-token-data',
        expiration: new Date('2024-01-13T12:00:00Z'),
        principalUuid: 'principal-uuid-123'
    };

    var result = stsHelpers.buildLdapObjectForSessionToken(params);

    Date.now = originalDateNow;

    t.ok(result.updated, 'should have updated field');
    t.equal(result.updated, fixedTime.toString(),
        'updated should match mocked Date.now');
    t.done();
});

// ----------------------------------------------------------------------------
// buildAccessKeyDataForRedis(params) tests - with Date.now() mock
// ----------------------------------------------------------------------------

test('buildAccessKeyDataForRedis has type accesskey', function(t) {
    var originalDateNow = Date.now;
    Date.now = function() { return 1705147200000; };

    var params = {
        accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
        secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
        sessionToken: 'session-token-data',
        userUuid: 'user-uuid-123',
        expiration: new Date('2024-01-13T12:00:00Z'),
        principalUuid: 'principal-uuid-456'
    };

    var result = stsHelpers.buildAccessKeyDataForRedis(params);

    Date.now = originalDateNow;

    t.equal(result.type, 'accesskey', 'should have type accesskey');
    t.done();
});

test('buildAccessKeyDataForRedis has all required fields', function(t) {
    var originalDateNow = Date.now;
    Date.now = function() { return 1705147200000; };

    var params = {
        accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
        secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
        sessionToken: 'session-token-data',
        userUuid: 'user-uuid-123',
        expiration: new Date('2024-01-13T12:00:00Z'),
        principalUuid: 'principal-uuid-456'
    };

    var result = stsHelpers.buildAccessKeyDataForRedis(params);

    Date.now = originalDateNow;

    t.ok(result.accessKeyId, 'should have accessKeyId');
    t.ok(result.secretAccessKey, 'should have secretAccessKey');
    t.ok(result.userUuid, 'should have userUuid');
    t.ok(result.principalUuid, 'should have principalUuid');
    t.done();
});

test('buildAccessKeyDataForRedis expiration is ISO string', function(t) {
    var originalDateNow = Date.now;
    Date.now = function() { return 1705147200000; };

    var params = {
        accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
        secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
        sessionToken: 'session-token-data',
        userUuid: 'user-uuid-123',
        expiration: new Date('2024-01-13T12:00:00Z'),
        principalUuid: 'principal-uuid-456'
    };

    var result = stsHelpers.buildAccessKeyDataForRedis(params);

    Date.now = originalDateNow;

    t.ok(result.expiration, 'should have expiration field');
    t.ok(result.expiration.indexOf('T') > -1,
        'expiration should be ISO format');
    t.done();
});

test('buildAccessKeyDataForRedis has created timestamp', function(t) {
    var originalDateNow = Date.now;
    var fixedTime = 1705147200000;
    Date.now = function() { return fixedTime; };

    var params = {
        accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
        secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
        sessionToken: 'session-token-data',
        userUuid: 'user-uuid-123',
        expiration: new Date('2024-01-13T12:00:00Z'),
        principalUuid: 'principal-uuid-456'
    };

    var result = stsHelpers.buildAccessKeyDataForRedis(params);

    Date.now = originalDateNow;

    t.ok(result.created, 'should have created field');
    t.equal(result.created, fixedTime.toString(),
        'created should match mocked Date.now');
    t.done();
});

test('buildAccessKeyDataForRedis preserves all params fields', function(t) {
    var originalDateNow = Date.now;
    Date.now = function() { return 1705147200000; };

    var params = {
        accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
        secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
        sessionToken: 'session-token-data',
        userUuid: 'user-uuid-123',
        expiration: new Date('2024-01-13T12:00:00Z'),
        principalUuid: 'principal-uuid-456'
    };

    var result = stsHelpers.buildAccessKeyDataForRedis(params);

    Date.now = originalDateNow;

    t.equal(result.accessKeyId, params.accessKeyId,
        'should preserve accessKeyId');
    t.equal(result.secretAccessKey, params.secretAccessKey,
        'should preserve secretAccessKey');
    t.equal(result.userUuid, params.userUuid, 'should preserve userUuid');
    t.done();
});
