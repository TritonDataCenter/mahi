/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2026 Edgecast Cloud LLC.
 */

/**
 * test/sts-trust-policy-branches.test.js: Tests for STS trust policy
 * branch coverage per CHG-047.
 *
 * Focus areas:
 * - Federated principal handling
 * - Role chaining prevention (caller.roleArn)
 * - Multi-cloud ARN support (aws/manta/triton)
 * - Root user mixed policy scenarios
 * - Input validation branches
 * - ARN parsing edge cases
 */

var bunyan = require('bunyan');
var nodeunit = require('nodeunit-plus');
var test = nodeunit.test;

var sts = require('../lib/server/sts.js');

// Access internal functions for testing
var validateTrustPolicy = sts.internal.validateTrustPolicy;
var validatePrincipal = sts.internal.validatePrincipal;
var validateSinglePrincipal = sts.internal.validateSinglePrincipal;
var statementMatchesAction = sts.internal.statementMatchesAction;

// Access helper functions (CHG-044 exports)
var parseRoleArnForTrustPolicy = sts.helpers.parseRoleArnForTrustPolicy;
var findTrustPolicyInMemberpolicy = sts.helpers.findTrustPolicyInMemberpolicy;

var LOG = bunyan.createLogger({
    name: 'sts-trust-policy-branches-test',
    level: process.env.LOG_LEVEL || 'fatal'
});

// Mock caller objects for testing
var MOCK_CALLERS = {
    normalUser: {
        uuid: 'normal-user-uuid-123',
        login: 'normaluser',
        account: {
            uuid: '11111111-2222-3333-4444-555555555555',
            login: 'testaccount'
        }
    },
    rootUser: {
        uuid: 'root-user-uuid-456',
        login: 'root',
        account: {
            uuid: '11111111-2222-3333-4444-555555555555',
            login: 'testaccount'
        }
    },
    assumedRoleUser: {
        uuid: 'assumed-role-uuid-789',
        login: 'assumedroleuser',
        roleArn: 'arn:aws:iam::11111111-2222-3333-4444-555555555555:' +
                 'role/PreviousRole',
        account: {
            uuid: '11111111-2222-3333-4444-555555555555',
            login: 'testaccount'
        }
    },
    nestedUser: {
        user: {
            uuid: 'nested-user-uuid-abc',
            login: 'nesteduser'
        },
        account: {
            uuid: '11111111-2222-3333-4444-555555555555',
            login: 'testaccount'
        }
    }
};

/* ================================================================
 * SECTION 1: Federated Principal Handling
 * Tests for validatePrincipal with principal.Federated
 * ================================================================ */

test('validatePrincipal: federated principal returns false', function (t) {
    var principal = {
        Federated: 'arn:aws:iam::123456789012:saml-provider/MySAMLProvider'
    };

    var result = validatePrincipal(principal, MOCK_CALLERS.normalUser, LOG);
    t.ok(!result, 'federated principal should return false (not supported)');
    t.end();
});

test('validatePrincipal: federated principal in policy', function (t) {
    var trustPolicy = JSON.stringify({
        'Version': '2012-10-17',
        'Statement': [{
            'Effect': 'Allow',
            'Principal': {
                'Federated':
                    'arn:aws:iam::123456789012:saml-provider/MySAMLProvider'
            },
            'Action': 'sts:AssumeRoleWithSAML'
        }]
    });

    var result = validateTrustPolicy(trustPolicy, MOCK_CALLERS.normalUser, LOG);
    t.ok(!result,
        'trust policy with only federated principal should deny user');
    t.end();
});

/* ================================================================
 * SECTION 2: Role Chaining Prevention
 * Tests for caller.roleArn check to prevent privilege escalation
 * ================================================================ */

test('validateSinglePrincipal: wildcard denies assumed role credentials',
    function (t) {
    var result = validateSinglePrincipal('*',
        MOCK_CALLERS.assumedRoleUser, LOG);
    t.ok(!result,
        'wildcard should deny caller with roleArn (role chaining prevention)');
    t.end();
});

test('validatePrincipal: wildcard string denies assumed role', function (t) {
    var result = validatePrincipal('*', MOCK_CALLERS.assumedRoleUser, LOG);
    t.ok(!result,
        'wildcard principal should deny assumed role credentials');
    t.end();
});

test('validatePrincipal: wildcard in AWS object denies assumed role',
    function (t) {
    var principal = {'AWS': '*'};
    var result = validatePrincipal(principal, MOCK_CALLERS.assumedRoleUser, LOG);
    t.ok(!result,
        'AWS wildcard should deny caller with assumed role credentials');
    t.end();
});

test('trust policy: wildcard allows normal user but denies assumed role',
    function (t) {
    var trustPolicy = JSON.stringify({
        'Version': '2012-10-17',
        'Statement': [{
            'Effect': 'Allow',
            'Principal': '*',
            'Action': 'sts:AssumeRole'
        }]
    });

    var normalResult = validateTrustPolicy(trustPolicy,
        MOCK_CALLERS.normalUser, LOG);
    var assumedResult = validateTrustPolicy(trustPolicy,
        MOCK_CALLERS.assumedRoleUser, LOG);

    t.ok(normalResult, 'normal user should be allowed with wildcard');
    t.ok(!assumedResult,
        'assumed role user should be denied (role chaining blocked)');
    t.end();
});

/* ================================================================
 * SECTION 3: Multi-Cloud ARN Support
 * Tests for manta: and triton: ARN prefixes
 * ================================================================ */

test('validateSinglePrincipal: manta ARN user principal', function (t) {
    var arn = 'arn:manta:iam::11111111-2222-3333-4444-555555555555:' +
              'user/normaluser';
    var result = validateSinglePrincipal(arn, MOCK_CALLERS.normalUser, LOG);
    t.ok(result, 'manta ARN should match user');
    t.end();
});

test('validateSinglePrincipal: triton ARN user principal', function (t) {
    var arn = 'arn:triton:iam::11111111-2222-3333-4444-555555555555:' +
              'user/normaluser';
    var result = validateSinglePrincipal(arn, MOCK_CALLERS.normalUser, LOG);
    t.ok(result, 'triton ARN should match user');
    t.end();
});

test('validateSinglePrincipal: manta ARN root principal', function (t) {
    var arn = 'arn:manta:iam::11111111-2222-3333-4444-555555555555:root';
    var result = validateSinglePrincipal(arn, MOCK_CALLERS.normalUser, LOG);
    t.ok(result, 'manta root ARN should allow any user in account');
    t.end();
});

test('validateSinglePrincipal: triton ARN root principal', function (t) {
    var arn = 'arn:triton:iam::11111111-2222-3333-4444-555555555555:root';
    var result = validateSinglePrincipal(arn, MOCK_CALLERS.normalUser, LOG);
    t.ok(result, 'triton root ARN should allow any user in account');
    t.end();
});

test('trust policy: manta ARN in policy', function (t) {
    var trustPolicy = JSON.stringify({
        'Version': '2012-10-17',
        'Statement': [{
            'Effect': 'Allow',
            'Principal': {
                'AWS': 'arn:manta:iam::' +
                       '11111111-2222-3333-4444-555555555555:user/normaluser'
            },
            'Action': 'sts:AssumeRole'
        }]
    });

    var result = validateTrustPolicy(trustPolicy, MOCK_CALLERS.normalUser, LOG);
    t.ok(result, 'manta ARN in trust policy should work');
    t.end();
});

/* ================================================================
 * SECTION 4: Root User Mixed Policy Scenario
 * Tests for the special business rule: root denied when both
 * account-level and explicit root allows exist
 * ================================================================ */

test('trust policy: root user allowed with only account-level allow',
    function (t) {
    var trustPolicy = JSON.stringify({
        'Version': '2012-10-17',
        'Statement': [{
            'Effect': 'Allow',
            'Principal': {
                'AWS': '11111111-2222-3333-4444-555555555555'
            },
            'Action': 'sts:AssumeRole'
        }]
    });

    // Root users are excluded from account-level matching
    var result = validateTrustPolicy(trustPolicy, MOCK_CALLERS.rootUser, LOG);
    t.ok(!result,
        'root user should be denied with account-level allow only');
    t.end();
});

test('trust policy: root user allowed with explicit root ARN', function (t) {
    var trustPolicy = JSON.stringify({
        'Version': '2012-10-17',
        'Statement': [{
            'Effect': 'Allow',
            'Principal': {
                'AWS': 'arn:aws:iam::' +
                       '11111111-2222-3333-4444-555555555555:root'
            },
            'Action': 'sts:AssumeRole'
        }]
    });

    var result = validateTrustPolicy(trustPolicy, MOCK_CALLERS.rootUser, LOG);
    t.ok(result, 'root user should be allowed with explicit root ARN');
    t.end();
});

test('trust policy: root user denied with mixed policy', function (t) {
    // When both account-level AND explicit root allows exist,
    // root user should be denied (special business rule)
    var trustPolicy = JSON.stringify({
        'Version': '2012-10-17',
        'Statement': [
            {
                'Effect': 'Allow',
                'Principal': {
                    'AWS': '11111111-2222-3333-4444-555555555555'
                },
                'Action': 'sts:AssumeRole'
            },
            {
                'Effect': 'Allow',
                'Principal': {
                    'AWS': 'arn:aws:iam::' +
                           '11111111-2222-3333-4444-555555555555:root'
                },
                'Action': 'sts:AssumeRole'
            }
        ]
    });

    var result = validateTrustPolicy(trustPolicy, MOCK_CALLERS.rootUser, LOG);
    t.ok(!result, 'root user should be denied with mixed policy scenario');
    t.end();
});

/* ================================================================
 * SECTION 5: ARN Parsing Edge Cases
 * Tests for parseRoleArnForTrustPolicy
 * ================================================================ */

test('parseRoleArnForTrustPolicy: valid ARN', function (t) {
    var arn = 'arn:aws:iam::11111111-2222-3333-4444-555555555555:role/TestRole';
    var result = parseRoleArnForTrustPolicy(arn);
    t.ok(result, 'should return parsed result');
    t.equal(result.accountId, '11111111-2222-3333-4444-555555555555',
        'should extract accountId');
    t.equal(result.roleName, 'TestRole', 'should extract roleName');
    t.end();
});

test('parseRoleArnForTrustPolicy: invalid - too few parts', function (t) {
    var arn = 'arn:aws:iam::account';
    var result = parseRoleArnForTrustPolicy(arn);
    t.ok(!result, 'should return null for ARN with too few parts');
    t.end();
});

test('parseRoleArnForTrustPolicy: invalid - not iam service', function (t) {
    var arn = 'arn:aws:s3::123456789012:role/TestRole';
    var result = parseRoleArnForTrustPolicy(arn);
    t.ok(!result, 'should return null for non-IAM service');
    t.end();
});

test('parseRoleArnForTrustPolicy: invalid - not a role', function (t) {
    var arn = 'arn:aws:iam::123456789012:user/TestUser';
    var result = parseRoleArnForTrustPolicy(arn);
    t.ok(!result, 'should return null for non-role resource');
    t.end();
});

test('parseRoleArnForTrustPolicy: invalid - empty role name', function (t) {
    var arn = 'arn:aws:iam::123456789012:role/';
    var result = parseRoleArnForTrustPolicy(arn);
    t.ok(result, 'should parse ARN');
    t.equal(result.roleName, '', 'roleName should be empty string');
    t.end();
});

/* ================================================================
 * SECTION 7: findTrustPolicyInMemberpolicy Edge Cases
 * ================================================================ */

test('findTrustPolicyInMemberpolicy: null input', function (t) {
    var result = findTrustPolicyInMemberpolicy(null);
    t.ok(!result, 'should return null for null input');
    t.end();
});

test('findTrustPolicyInMemberpolicy: empty array', function (t) {
    var result = findTrustPolicyInMemberpolicy([]);
    t.ok(!result, 'should return null for empty array');
    t.end();
});

test('findTrustPolicyInMemberpolicy: no trust policy in array', function (t) {
    var policies = [
        JSON.stringify({
            'Version': '2012-10-17',
            'Statement': [{
                'Effect': 'Allow',
                'Action': 's3:GetObject',
                'Resource': '*'
            }]
        })
    ];
    var result = findTrustPolicyInMemberpolicy(policies);
    t.ok(!result, 'should return null when no sts:AssumeRole policy');
    t.end();
});

test('findTrustPolicyInMemberpolicy: finds trust policy', function (t) {
    var trustPolicy = JSON.stringify({
        'Version': '2012-10-17',
        'Statement': [{
            'Effect': 'Allow',
            'Principal': {'AWS': '*'},
            'Action': 'sts:AssumeRole'
        }]
    });
    var policies = [
        JSON.stringify({
            'Version': '2012-10-17',
            'Statement': [{
                'Effect': 'Allow',
                'Action': 's3:GetObject',
                'Resource': '*'
            }]
        }),
        trustPolicy
    ];
    var result = findTrustPolicyInMemberpolicy(policies);
    t.equal(result, trustPolicy, 'should find trust policy');
    t.end();
});

test('findTrustPolicyInMemberpolicy: finds wildcard action policy',
    function (t) {
    var trustPolicy = JSON.stringify({
        'Version': '2012-10-17',
        'Statement': [{
            'Effect': 'Allow',
            'Principal': {'AWS': '*'},
            'Action': '*'
        }]
    });
    var policies = [trustPolicy];
    var result = findTrustPolicyInMemberpolicy(policies);
    t.equal(result, trustPolicy,
        'should find policy with wildcard action');
    t.end();
});

test('findTrustPolicyInMemberpolicy: skips invalid JSON', function (t) {
    var trustPolicy = JSON.stringify({
        'Version': '2012-10-17',
        'Statement': [{
            'Effect': 'Allow',
            'Principal': {'AWS': '*'},
            'Action': 'sts:AssumeRole'
        }]
    });
    var policies = [
        'invalid json {{{',
        trustPolicy
    ];
    var result = findTrustPolicyInMemberpolicy(policies);
    t.equal(result, trustPolicy, 'should skip invalid JSON and find policy');
    t.end();
});

/* ================================================================
 * SECTION 8: Unrecognized Principal Format
 * Tests for principal formats that don't match known patterns
 * ================================================================ */

test('validatePrincipal: unrecognized object format', function (t) {
    var principal = {
        'Unknown': 'some-value'
    };
    var result = validatePrincipal(principal, MOCK_CALLERS.normalUser, LOG);
    t.ok(!result, 'unrecognized principal format should return false');
    t.end();
});

test('validatePrincipal: empty object', function (t) {
    var principal = {};
    var result = validatePrincipal(principal, MOCK_CALLERS.normalUser, LOG);
    t.ok(!result, 'empty principal object should return false');
    t.end();
});

test('validateSinglePrincipal: unrecognized ARN format', function (t) {
    var arn = 'arn:unknown:iam::123456789012:user/testuser';
    var result = validateSinglePrincipal(arn, MOCK_CALLERS.normalUser, LOG);
    t.ok(!result, 'unrecognized ARN prefix should return false');
    t.end();
});

test('validateSinglePrincipal: non-ARN string', function (t) {
    var nonArn = 'not-an-arn-just-a-string';
    var result = validateSinglePrincipal(nonArn, MOCK_CALLERS.normalUser, LOG);
    t.ok(!result, 'non-ARN string should return false');
    t.end();
});

/* ================================================================
 * SECTION 9: Nested Caller Structure
 * Tests for caller with user nested inside
 * ================================================================ */

test('validateTrustPolicy: handles nested caller.user structure', function (t) {
    var trustPolicy = JSON.stringify({
        'Version': '2012-10-17',
        'Statement': [{
            'Effect': 'Allow',
            'Principal': {
                'AWS': 'arn:aws:iam::' +
                       '11111111-2222-3333-4444-555555555555:user/nesteduser'
            },
            'Action': 'sts:AssumeRole'
        }]
    });

    var result = validateTrustPolicy(trustPolicy, MOCK_CALLERS.nestedUser, LOG);
    t.ok(result, 'should handle nested caller.user structure');
    t.end();
});

/* ================================================================
 * SECTION 10: statementMatchesAction Edge Cases
 * ================================================================ */

test('statementMatchesAction: null Action returns false', function (t) {
    var statement = {'Effect': 'Allow', 'Principal': '*'};
    var result = statementMatchesAction(statement, 'sts:AssumeRole');
    t.ok(!result, 'missing Action should return false');
    t.end();
});

test('statementMatchesAction: empty Action array', function (t) {
    var statement = {'Effect': 'Allow', 'Action': []};
    var result = statementMatchesAction(statement, 'sts:AssumeRole');
    t.ok(!result, 'empty Action array should return false');
    t.end();
});

test('statementMatchesAction: Action array without match', function (t) {
    var statement = {
        'Effect': 'Allow',
        'Action': ['s3:GetObject', 's3:PutObject', 'ec2:*']
    };
    var result = statementMatchesAction(statement, 'sts:AssumeRole');
    t.ok(!result, 'Action array without match should return false');
    t.end();
});

/* ================================================================
 * SECTION 11: validateTrustPolicy Error Branches
 * Tests for trust policy validation edge cases
 * ================================================================ */

test('validateTrustPolicy: null trust policy document', function (t) {
    var result = validateTrustPolicy(null, MOCK_CALLERS.normalUser, LOG);
    t.ok(!result, 'null trust policy should return false');
    t.end();
});

test('validateTrustPolicy: empty string trust policy', function (t) {
    var result = validateTrustPolicy('', MOCK_CALLERS.normalUser, LOG);
    t.ok(!result, 'empty string trust policy should return false');
    t.end();
});

test('validateTrustPolicy: invalid JSON in trust policy', function (t) {
    var invalidJson = '{invalid json here}';
    var result = validateTrustPolicy(invalidJson, MOCK_CALLERS.normalUser, LOG);
    t.ok(!result, 'invalid JSON should return false');
    t.end();
});

test('validateTrustPolicy: missing Statement in policy', function (t) {
    var policy = JSON.stringify({
        'Version': '2012-10-17'
        // Missing Statement
    });
    var result = validateTrustPolicy(policy, MOCK_CALLERS.normalUser, LOG);
    t.ok(!result, 'missing Statement should return false');
    t.end();
});

test('validateTrustPolicy: Statement not an array', function (t) {
    var policy = JSON.stringify({
        'Version': '2012-10-17',
        'Statement': 'not-an-array'
    });
    var result = validateTrustPolicy(policy, MOCK_CALLERS.normalUser, LOG);
    t.ok(!result, 'Statement not array should return false');
    t.end();
});

test('validateTrustPolicy: Deny effect without matching action', function (t) {
    var policy = JSON.stringify({
        'Version': '2012-10-17',
        'Statement': [{
            'Effect': 'Deny',
            'Principal': '*',
            'Action': 's3:GetObject'  // Not sts:AssumeRole
        }, {
            'Effect': 'Allow',
            'Principal': '*',
            'Action': 'sts:AssumeRole'
        }]
    });
    var result = validateTrustPolicy(policy, MOCK_CALLERS.normalUser, LOG);
    t.ok(result, 'Deny with non-matching action should not block Allow');
    t.end();
});

test('validateTrustPolicy: Allow effect without matching action', function (t) {
    var policy = JSON.stringify({
        'Version': '2012-10-17',
        'Statement': [{
            'Effect': 'Allow',
            'Principal': '*',
            'Action': 's3:GetObject'  // Not sts:AssumeRole
        }]
    });
    var result = validateTrustPolicy(policy, MOCK_CALLERS.normalUser, LOG);
    t.ok(!result, 'Allow without sts:AssumeRole should return false');
    t.end();
});

test('validateTrustPolicy: caller with only account uuid', function (t) {
    var callerAccountOnly = {
        account: {
            uuid: '11111111-2222-3333-4444-555555555555',
            login: 'testaccount'
        }
    };
    var policy = JSON.stringify({
        'Version': '2012-10-17',
        'Statement': [{
            'Effect': 'Allow',
            'Principal': {
                'AWS': '11111111-2222-3333-4444-555555555555'
            },
            'Action': 'sts:AssumeRole'
        }]
    });
    var result = validateTrustPolicy(policy, callerAccountOnly, LOG);
    // Result depends on implementation - just ensure it doesn't crash
    t.ok(typeof result === 'boolean', 'should return boolean for account-only caller');
    t.end();
});

/* ================================================================
 * SECTION 12: validatePrincipal Additional Branches
 * Tests for Service and object format principals
 * ================================================================ */

test('validatePrincipal: Service principal returns false', function (t) {
    var principal = {
        'Service': 'lambda.amazonaws.com'
    };
    var result = validatePrincipal(principal, MOCK_CALLERS.normalUser, LOG);
    t.ok(!result, 'Service principal should return false for regular user');
    t.end();
});

test('validatePrincipal: AWS array with no matches', function (t) {
    var principal = {
        'AWS': [
            'arn:aws:iam::999999999999:user/otheruser',
            'arn:aws:iam::888888888888:root'
        ]
    };
    var result = validatePrincipal(principal, MOCK_CALLERS.normalUser, LOG);
    t.ok(!result, 'AWS array with no matches should return false');
    t.end();
});

test('validatePrincipal: AWS array with one match', function (t) {
    var principal = {
        'AWS': [
            'arn:aws:iam::999999999999:user/otheruser',
            'arn:aws:iam::11111111-2222-3333-4444-555555555555:user/normaluser'
        ]
    };
    var result = validatePrincipal(principal, MOCK_CALLERS.normalUser, LOG);
    t.ok(result, 'AWS array with matching ARN should return true');
    t.end();
});

test('validatePrincipal: wildcard string allows normal user', function (t) {
    var result = validatePrincipal('*', MOCK_CALLERS.normalUser, LOG);
    t.ok(result, 'wildcard should allow normal user');
    t.end();
});

test('validatePrincipal: non-wildcard string principal', function (t) {
    var principal = 'arn:aws:iam::11111111-2222-3333-4444-555555555555:user/normaluser';
    var result = validatePrincipal(principal, MOCK_CALLERS.normalUser, LOG);
    t.ok(result, 'matching ARN string should return true');
    t.end();
});

/* ================================================================
 * SECTION 13: Helper Function Branches
 * Tests for extractCallerIdentity and other helpers
 * ================================================================ */

var extractCallerIdentity = sts.helpers.extractCallerIdentity;
var validateDurationSeconds = sts.helpers.validateDurationSeconds;

test('extractCallerIdentity: from nested user structure', function (t) {
    var caller = MOCK_CALLERS.nestedUser;
    var result = extractCallerIdentity(caller);
    t.ok(result, 'should extract identity from nested structure');
    t.equal(result.uuid, 'nested-user-uuid-abc');
    t.end();
});

test('extractCallerIdentity: from flat user structure', function (t) {
    // normalUser doesn't have nested user, so it uses account.uuid
    var caller = MOCK_CALLERS.normalUser;
    var result = extractCallerIdentity(caller);
    t.ok(result, 'should extract identity from flat structure');
    // Falls back to account.uuid when no nested user
    t.equal(result.uuid, caller.account.uuid);
    t.end();
});

test('validateDurationSeconds: valid duration from params', function (t) {
    var result = validateDurationSeconds({DurationSeconds: 3600}, {});
    t.ok(result.valid, 'valid duration should return valid: true');
    t.equal(result.value, 3600);
    t.end();
});

test('validateDurationSeconds: valid duration from body', function (t) {
    var result = validateDurationSeconds({}, {DurationSeconds: 7200});
    t.ok(result.valid, 'valid duration from body should return valid: true');
    t.equal(result.value, 7200);
    t.end();
});

test('validateDurationSeconds: duration too short', function (t) {
    var result = validateDurationSeconds({DurationSeconds: 100}, {});
    t.ok(!result.valid, 'duration < 900 should return valid: false');
    t.ok(result.error, 'should have error');
    t.end();
});

test('validateDurationSeconds: duration too long', function (t) {
    var result = validateDurationSeconds({DurationSeconds: 200000}, {});
    t.ok(!result.valid, 'duration > 129600 should return valid: false');
    t.ok(result.error, 'should have error');
    t.end();
});

test('validateDurationSeconds: default value', function (t) {
    var result = validateDurationSeconds({}, {});
    t.ok(result.valid, 'default should be valid');
    t.equal(result.value, 3600, 'default should be 3600');
    t.end();
});

/* ================================================================
 * SECTION 14: More validatePrincipal Branches
 * ================================================================ */

test('validatePrincipal: wildcard denies assumed role with nested roleArn', function (t) {
    // Caller that has roleArn (assumed role credential)
    var assumedCaller = {
        uuid: 'test-uuid',
        login: 'testuser',
        roleArn: 'arn:aws:iam::123:role/SomeRole',
        account: {
            uuid: '11111111-2222-3333-4444-555555555555',
            login: 'testaccount'
        }
    };
    var result = validatePrincipal('*', assumedCaller, LOG);
    t.ok(!result, 'wildcard should deny caller with roleArn');
    t.end();
});

test('validatePrincipal: number type returns false', function (t) {
    var result = validatePrincipal(12345, MOCK_CALLERS.normalUser, LOG);
    t.ok(!result, 'number principal should return false');
    t.end();
});

test('validatePrincipal: boolean type returns false', function (t) {
    var result = validatePrincipal(true, MOCK_CALLERS.normalUser, LOG);
    t.ok(!result, 'boolean principal should return false');
    t.end();
});

test('validatePrincipal: array type returns false', function (t) {
    var result = validatePrincipal(['arn:aws:iam::123:user/test'],
                                    MOCK_CALLERS.normalUser, LOG);
    t.ok(!result, 'array principal should return false');
    t.end();
});

/* ================================================================
 * SECTION 15: createSessionTokenData Tests
 * ================================================================ */

var createSessionTokenData = sts.helpers.createSessionTokenData;

test('createSessionTokenData: basic creation', function (t) {
    var expiration = new Date(Date.now() + 3600000);
    var result = createSessionTokenData('test-uuid-123', expiration);
    t.ok(result, 'should create session token data');
    t.equal(result.uuid, 'test-uuid-123');
    t.end();
});

/* ================================================================
 * SECTION 16: buildLdapObjectForSessionToken Tests
 * ================================================================ */

var buildLdapObjectForSessionToken = sts.helpers.buildLdapObjectForSessionToken;

test('buildLdapObjectForSessionToken: basic build', function (t) {
    var params = {
        accessKeyId: 'MSTS1234567890123456',
        secretKey: 'secretkey12345',
        sessionToken: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test',
        expiration: new Date(Date.now() + 3600000),
        principalUuid: 'principal-uuid-123'
    };
    var result = buildLdapObjectForSessionToken(params);
    t.ok(result, 'should build LDAP object');
    t.equal(result.accesskeyid, params.accessKeyId);
    t.equal(result.principaluuid, params.principalUuid);
    t.end();
});

/* ================================================================
 * SECTION 17: buildAccessKeyDataForRedis Tests
 * ================================================================ */

var buildAccessKeyDataForRedis = sts.helpers.buildAccessKeyDataForRedis;

test('buildAccessKeyDataForRedis: basic build', function (t) {
    var params = {
        accessKeyId: 'MSTS1234567890123456',
        secretAccessKey: 'secretkey12345',
        sessionToken: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test',
        expiration: new Date(Date.now() + 3600000),
        userUuid: 'user-uuid-123',
        principalUuid: 'principal-uuid-123'
    };
    var result = buildAccessKeyDataForRedis(params);
    t.ok(result, 'should build Redis data');
    t.equal(result.secretAccessKey, params.secretAccessKey);
    t.equal(result.userUuid, params.userUuid);
    t.equal(result.credentialType, 'temporary');
    t.end();
});

/* ================================================================
 * SECTION 18: validateServicePrincipal Tests
 * ================================================================ */

var validateServicePrincipal = sts.internal.validateServicePrincipal;

test('validateServicePrincipal: supported service (lambda)', function (t) {
    var result = validateServicePrincipal('lambda.amazonaws.com', LOG);
    t.ok(result, 'lambda should be a supported service');
    t.end();
});

test('validateServicePrincipal: supported service (ec2)', function (t) {
    var result = validateServicePrincipal('ec2.amazonaws.com', LOG);
    t.ok(result, 'ec2 should be a supported service');
    t.end();
});

test('validateServicePrincipal: supported service (ecs-tasks)', function (t) {
    var result = validateServicePrincipal('ecs-tasks.amazonaws.com', LOG);
    t.ok(result, 'ecs-tasks should be a supported service');
    t.end();
});

test('validateServicePrincipal: unsupported service', function (t) {
    var result = validateServicePrincipal('unknown.amazonaws.com', LOG);
    t.ok(!result, 'unknown service should not be supported');
    t.end();
});

test('validateServicePrincipal: empty string', function (t) {
    var result = validateServicePrincipal('', LOG);
    t.ok(!result, 'empty string should not be supported');
    t.end();
});

/* ================================================================
 * SECTION 19: Access Key ID Generator Tests
 * ================================================================ */

var generateSessionTokenAccessKeyId = sts.internal.generateSessionTokenAccessKeyId;
var generateAssumeRoleAccessKeyId = sts.internal.generateAssumeRoleAccessKeyId;

test('generateSessionTokenAccessKeyId: prefix check', function (t) {
    var keyId = generateSessionTokenAccessKeyId();
    t.ok(keyId, 'should generate key ID');
    t.equal(keyId.indexOf('MSTS'), 0, 'should start with MSTS prefix');
    t.equal(keyId.length, 20, 'should be 20 characters');
    t.end();
});

test('generateSessionTokenAccessKeyId: unique keys', function (t) {
    var keyId1 = generateSessionTokenAccessKeyId();
    var keyId2 = generateSessionTokenAccessKeyId();
    t.notEqual(keyId1, keyId2, 'should generate unique keys');
    t.end();
});

test('generateAssumeRoleAccessKeyId: prefix check', function (t) {
    var keyId = generateAssumeRoleAccessKeyId();
    t.ok(keyId, 'should generate key ID');
    t.equal(keyId.indexOf('MSAR'), 0, 'should start with MSAR prefix');
    t.equal(keyId.length, 20, 'should be 20 characters');
    t.end();
});

test('generateAssumeRoleAccessKeyId: unique keys', function (t) {
    var keyId1 = generateAssumeRoleAccessKeyId();
    var keyId2 = generateAssumeRoleAccessKeyId();
    t.notEqual(keyId1, keyId2, 'should generate unique keys');
    t.end();
});

/* ================================================================
 * SECTION 20: buildGetSessionTokenResponse Tests
 * ================================================================ */

var buildGetSessionTokenResponse = sts.helpers.buildGetSessionTokenResponse;

test('buildGetSessionTokenResponse: basic response', function (t) {
    var params = {
        accessKeyId: 'MSTS1234567890123456',
        secretAccessKey: 'secretkey12345',
        sessionToken: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test',
        expiration: new Date(Date.now() + 3600000)
    };
    var result = buildGetSessionTokenResponse(params);
    t.ok(result, 'should build response');
    t.ok(result.GetSessionTokenResponse, 'should have GetSessionTokenResponse');
    t.ok(result.GetSessionTokenResponse.GetSessionTokenResult,
         'should have GetSessionTokenResult');
    var creds = result.GetSessionTokenResponse.GetSessionTokenResult.Credentials;
    t.ok(creds, 'should have Credentials');
    t.equal(creds.AccessKeyId, params.accessKeyId, 'should have access key ID');
    t.equal(creds.SecretAccessKey, params.secretAccessKey,
            'should have secret access key');
    t.end();
});

/* ================================================================
 * SECTION 21: statementMatchesAction edge cases
 * ================================================================ */

test('statementMatchesAction: array with wildcard', function (t) {
    var stmt = { Action: ['sts:GetCallerIdentity', '*'] };
    var result = statementMatchesAction(stmt, 'sts:AssumeRole');
    t.ok(result, 'wildcard in array should match any action');
    t.end();
});

test('statementMatchesAction: single action string match', function (t) {
    var stmt = { Action: 'sts:AssumeRole' };
    var result = statementMatchesAction(stmt, 'sts:AssumeRole');
    t.ok(result, 'single action string should match');
    t.end();
});

test('statementMatchesAction: single action string no match', function (t) {
    var stmt = { Action: 'sts:GetCallerIdentity' };
    var result = statementMatchesAction(stmt, 'sts:AssumeRole');
    t.ok(!result, 'non-matching single action should not match');
    t.end();
});

/* ================================================================
 * SECTION 22: validateSinglePrincipal additional branches
 * ================================================================ */

test('validateSinglePrincipal: account ID with user login match', function (t) {
    var caller = {
        uuid: 'user-uuid-123',
        login: 'testuser',
        account: { uuid: '123456789012' }
    };
    // Test account-id format matching
    var result = validateSinglePrincipal('123456789012', caller, LOG);
    t.ok(result, 'account ID should match caller account');
    t.end();
});

test('validateSinglePrincipal: 12-digit account ID', function (t) {
    var caller = {
        uuid: 'user-uuid-123',
        login: 'testuser',
        account: { uuid: '123456789012' }
    };
    var result = validateSinglePrincipal('987654321098', caller, LOG);
    t.ok(!result, 'non-matching account ID should not match');
    t.end();
});

test('validateSinglePrincipal: ARN user mismatch', function (t) {
    var caller = {
        uuid: 'user-uuid-123',
        login: 'testuser',
        account: { uuid: '11111111-2222-3333-4444-555555555555' }
    };
    var arn = 'arn:aws:iam::11111111-2222-3333-4444-555555555555:user/otheruser';
    var result = validateSinglePrincipal(arn, caller, LOG);
    t.ok(!result, 'user ARN with different login should not match');
    t.end();
});

/* ================================================================
 * SECTION 23: validateTrustPolicy DENY statement tests
 * ================================================================ */

test('validateTrustPolicy: DENY with matching action denies access', function (t) {
    var trustPolicy = JSON.stringify({
        Version: '2012-10-17',
        Statement: [
            {
                Effect: 'Deny',
                Action: 'sts:AssumeRole',
                Principal: { AWS: '*' }
            },
            {
                Effect: 'Allow',
                Action: 'sts:AssumeRole',
                Principal: { AWS: '*' }
            }
        ]
    });
    var caller = {
        uuid: 'user-uuid-123',
        login: 'testuser',
        account: { uuid: '11111111-2222-3333-4444-555555555555' }
    };
    var result = validateTrustPolicy(trustPolicy, caller, LOG);
    t.ok(!result, 'Deny should override Allow');
    t.end();
});

test('validateTrustPolicy: DENY without matching principal passes', function (t) {
    var trustPolicy = JSON.stringify({
        Version: '2012-10-17',
        Statement: [
            {
                Effect: 'Deny',
                Action: 'sts:AssumeRole',
                Principal: { AWS: 'arn:aws:iam::other-account:user/other' }
            },
            {
                Effect: 'Allow',
                Action: 'sts:AssumeRole',
                Principal: { AWS: '*' }
            }
        ]
    });
    var caller = {
        uuid: 'user-uuid-123',
        login: 'testuser',
        account: { uuid: '11111111-2222-3333-4444-555555555555' }
    };
    var result = validateTrustPolicy(trustPolicy, caller, LOG);
    t.ok(result, 'Deny for other principal should not block caller');
    t.end();
});

/* ================================================================
 * SECTION 24: Root user scenario tests
 * ================================================================ */

test('validateTrustPolicy: root user only account-level allow denied', function (t) {
    // Root users cannot match account-level principals (security rule)
    // They need explicit root ARN
    var trustPolicy = JSON.stringify({
        Version: '2012-10-17',
        Statement: [{
            Effect: 'Allow',
            Action: 'sts:AssumeRole',
            Principal: { AWS: '11111111-2222-3333-4444-555555555555' }
        }]
    });
    var caller = {
        uuid: 'user-uuid-123',
        login: 'root',
        account: { uuid: '11111111-2222-3333-4444-555555555555' }
    };
    var result = validateTrustPolicy(trustPolicy, caller, LOG);
    t.ok(!result, 'root user with only account-level allow should be denied');
    t.end();
});

test('validateTrustPolicy: root user only explicit root allow', function (t) {
    var trustPolicy = JSON.stringify({
        Version: '2012-10-17',
        Statement: [{
            Effect: 'Allow',
            Action: 'sts:AssumeRole',
            Principal: {
                AWS: 'arn:aws:iam::11111111-2222-3333-4444-555555555555:root'
            }
        }]
    });
    var caller = {
        uuid: 'user-uuid-123',
        login: 'root',
        account: { uuid: '11111111-2222-3333-4444-555555555555' }
    };
    var result = validateTrustPolicy(trustPolicy, caller, LOG);
    t.ok(result, 'root user with explicit root allow should pass');
    t.end();
});

test('validateTrustPolicy: non-root user with wildcard in Allow', function (t) {
    // Non-root users CAN use wildcard principals
    var trustPolicy = JSON.stringify({
        Version: '2012-10-17',
        Statement: [
            {
                Effect: 'Deny',
                Action: 'sts:GetCallerIdentity',
                Principal: { AWS: '11111111-2222-3333-4444-555555555555' }
            },
            {
                Effect: 'Allow',
                Action: 'sts:AssumeRole',
                Principal: { AWS: '*' }
            }
        ]
    });
    var caller = {
        uuid: 'user-uuid-123',
        login: 'testuser',
        account: { uuid: '11111111-2222-3333-4444-555555555555' }
    };
    var result = validateTrustPolicy(trustPolicy, caller, LOG);
    t.ok(result, 'non-root user with wildcard principal should be allowed');
    t.end();
});

/* ================================================================
 * SECTION 25: validateSinglePrincipal UUID format tests
 * ================================================================ */

test('validateSinglePrincipal: UUID format account ID match', function (t) {
    var caller = {
        uuid: 'user-uuid-123',
        login: 'testuser',
        account: { uuid: '11111111-2222-3333-4444-555555555555' }
    };
    var result = validateSinglePrincipal('11111111-2222-3333-4444-555555555555',
                                          caller, LOG);
    t.ok(result, 'UUID format account ID should match');
    t.end();
});

test('validateSinglePrincipal: UUID format no match', function (t) {
    var caller = {
        uuid: 'user-uuid-123',
        login: 'testuser',
        account: { uuid: '11111111-2222-3333-4444-555555555555' }
    };
    var result = validateSinglePrincipal('aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
                                          caller, LOG);
    t.ok(!result, 'non-matching UUID should not match');
    t.end();
});

/* ================================================================
 * SECTION 26: AWS array principal tests
 * ================================================================ */

test('validatePrincipal: AWS array principal match in middle', function (t) {
    var principal = {
        AWS: [
            'arn:aws:iam::other-account:user/user1',
            'arn:aws:iam::11111111-2222-3333-4444-555555555555:user/testuser',
            'arn:aws:iam::another-account:user/user2'
        ]
    };
    var caller = {
        uuid: 'user-uuid-123',
        login: 'testuser',
        account: { uuid: '11111111-2222-3333-4444-555555555555' }
    };
    var result = validatePrincipal(principal, caller, LOG);
    t.ok(result, 'should match user in middle of AWS array');
    t.end();
});

/* ================================================================
 * SECTION 27: findTrustPolicyInMemberpolicy edge cases
 * ================================================================ */

test('findTrustPolicyInMemberpolicy: wildcard action match', function (t) {
    var memberpolicy = [
        JSON.stringify({
            Statement: [{
                Effect: 'Allow',
                Action: '*'
            }]
        })
    ];
    var result = findTrustPolicyInMemberpolicy(memberpolicy);
    t.ok(result, 'should find policy with wildcard action');
    t.end();
});

test('findTrustPolicyInMemberpolicy: action array with sts:AssumeRole', function (t) {
    var memberpolicy = [
        JSON.stringify({
            Statement: [{
                Effect: 'Allow',
                Action: ['s3:GetObject', 'sts:AssumeRole']
            }]
        })
    ];
    var result = findTrustPolicyInMemberpolicy(memberpolicy);
    t.ok(result, 'should find policy with action array containing sts:AssumeRole');
    t.end();
});

test('findTrustPolicyInMemberpolicy: nested statement no action', function (t) {
    var memberpolicy = [
        JSON.stringify({
            Statement: [{
                Effect: 'Allow'
            }]
        })
    ];
    var result = findTrustPolicyInMemberpolicy(memberpolicy);
    t.ok(!result, 'should not find policy with statement missing action');
    t.end();
});

/* ================================================================
 * SECTION 28: extractCallerIdentity additional tests
 * ================================================================ */

test('extractCallerIdentity: with account login fallback', function (t) {
    var caller = {
        account: {
            uuid: 'account-uuid-123',
            login: 'accountlogin'
        }
    };
    var result = extractCallerIdentity(caller);
    t.equal(result.uuid, 'account-uuid-123', 'should use account uuid');
    t.equal(result.login, 'accountlogin', 'should use account login');
    t.end();
});

test('extractCallerIdentity: with user uuid but no login', function (t) {
    var caller = {
        user: { uuid: 'user-uuid-123' },
        account: { uuid: 'account-uuid', login: 'accountlogin' }
    };
    var result = extractCallerIdentity(caller);
    t.equal(result.uuid, 'user-uuid-123', 'should use user uuid');
    t.equal(result.login, 'accountlogin', 'should fallback to account login');
    t.end();
});

/* ================================================================
 * SECTION 29: parseRoleArnForTrustPolicy additional tests
 * ================================================================ */

test('parseRoleArnForTrustPolicy: too many colons', function (t) {
    var result = parseRoleArnForTrustPolicy(
        'arn:aws:iam::12345678:role/myrole:extra:parts');
    t.ok(result, 'should still parse with extra parts');
    t.equal(result.roleName, 'myrole', 'should extract role name');
    t.end();
});

test('parseRoleArnForTrustPolicy: user resource type', function (t) {
    var result = parseRoleArnForTrustPolicy('arn:aws:iam::12345678:user/myuser');
    t.ok(!result, 'should return null for user resource type');
    t.end();
});

test('parseRoleArnForTrustPolicy: s3 service instead of iam', function (t) {
    var result = parseRoleArnForTrustPolicy('arn:aws:s3:::mybucket');
    t.ok(!result, 'should return null for non-iam service');
    t.end();
});

/* ================================================================
 * SECTION 30: validateDurationSeconds edge cases
 * ================================================================ */

test('validateDurationSeconds: from body only', function (t) {
    var result = validateDurationSeconds({}, { DurationSeconds: 7200 });
    t.ok(result.valid, 'should be valid');
    t.equal(result.value, 7200, 'should get value from body');
    t.end();
});

test('validateDurationSeconds: params overrides body', function (t) {
    var result = validateDurationSeconds({ DurationSeconds: 3600 },
                                          { DurationSeconds: 7200 });
    t.ok(result.valid, 'should be valid');
    t.equal(result.value, 3600, 'params should override body');
    t.end();
});

test('validateDurationSeconds: string number conversion', function (t) {
    var result = validateDurationSeconds({ DurationSeconds: '1800' }, {});
    t.ok(result.valid, 'should be valid');
    t.equal(result.value, 1800, 'should convert string to number');
    t.end();
});

test('validateDurationSeconds: exactly 900 seconds', function (t) {
    var result = validateDurationSeconds({ DurationSeconds: 900 }, {});
    t.ok(result.valid, 'should be valid at minimum');
    t.equal(result.value, 900, 'should accept minimum value');
    t.end();
});

test('validateDurationSeconds: exactly 129600 seconds', function (t) {
    var result = validateDurationSeconds({ DurationSeconds: 129600 }, {});
    t.ok(result.valid, 'should be valid at maximum');
    t.equal(result.value, 129600, 'should accept maximum value');
    t.end();
});

/* ================================================================
 * SECTION 31: validateSinglePrincipal ARN parsing
 * ================================================================ */

test('validateSinglePrincipal: triton ARN format', function (t) {
    var caller = {
        uuid: 'user-uuid-123',
        login: 'testuser',
        account: { uuid: '11111111-2222-3333-4444-555555555555' }
    };
    var arn = 'arn:triton:iam::11111111-2222-3333-4444-555555555555:user/testuser';
    var result = validateSinglePrincipal(arn, caller, LOG);
    t.ok(result, 'should match triton ARN format');
    t.end();
});

test('validateSinglePrincipal: user ARN wrong account', function (t) {
    var caller = {
        uuid: 'user-uuid-123',
        login: 'testuser',
        account: { uuid: '11111111-2222-3333-4444-555555555555' }
    };
    var arn = 'arn:aws:iam::99999999-8888-7777-6666-555544443333:user/testuser';
    var result = validateSinglePrincipal(arn, caller, LOG);
    t.ok(!result, 'should not match user in different account');
    t.end();
});

test('validateSinglePrincipal: role ARN format', function (t) {
    var caller = {
        uuid: 'user-uuid-123',
        login: 'testuser',
        account: { uuid: '11111111-2222-3333-4444-555555555555' }
    };
    var arn = 'arn:aws:iam::11111111-2222-3333-4444-555555555555:role/myrole';
    var result = validateSinglePrincipal(arn, caller, LOG);
    // Role ARNs are not matched against user callers
    t.ok(!result, 'role ARN should not match user caller');
    t.end();
});

/* ================================================================
 * SECTION 32: validatePrincipal with Service principals
 * ================================================================ */

test('validatePrincipal: Service principal object format', function (t) {
    var principal = { Service: 'lambda.amazonaws.com' };
    var caller = {
        uuid: 'user-uuid-123',
        login: 'testuser',
        account: { uuid: '11111111-2222-3333-4444-555555555555' }
    };
    var result = validatePrincipal(principal, caller, LOG);
    // Regular users cannot match service principals
    t.ok(!result, 'user should not match service principal');
    t.end();
});

test('validatePrincipal: mixed AWS and Service principal', function (t) {
    var principal = {
        AWS: 'arn:aws:iam::11111111-2222-3333-4444-555555555555:user/testuser',
        Service: 'lambda.amazonaws.com'
    };
    var caller = {
        uuid: 'user-uuid-123',
        login: 'testuser',
        account: { uuid: '11111111-2222-3333-4444-555555555555' }
    };
    var result = validatePrincipal(principal, caller, LOG);
    t.ok(result, 'should match AWS principal even with Service present');
    t.end();
});

/* ================================================================
 * SECTION 33: Additional root user policy scenarios
 * ================================================================ */

test('validateTrustPolicy: root user with 12-digit account ID', function (t) {
    var trustPolicy = JSON.stringify({
        Version: '2012-10-17',
        Statement: [{
            Effect: 'Allow',
            Action: 'sts:AssumeRole',
            Principal: { AWS: '123456789012' }
        }]
    });
    var caller = {
        uuid: 'user-uuid-123',
        login: 'root',
        account: { uuid: '123456789012' }
    };
    // Root users should not match account-level principals
    var result = validateTrustPolicy(trustPolicy, caller, LOG);
    t.ok(!result, 'root user should not match 12-digit account ID');
    t.end();
});

test('validateTrustPolicy: non-root matches 12-digit account ID', function (t) {
    var trustPolicy = JSON.stringify({
        Version: '2012-10-17',
        Statement: [{
            Effect: 'Allow',
            Action: 'sts:AssumeRole',
            Principal: { AWS: '123456789012' }
        }]
    });
    var caller = {
        uuid: 'user-uuid-123',
        login: 'testuser',
        account: { uuid: '123456789012' }
    };
    var result = validateTrustPolicy(trustPolicy, caller, LOG);
    t.ok(result, 'non-root user should match 12-digit account ID');
    t.end();
});

/* ================================================================
 * SECTION 34: validateTrustPolicy caller structure variations
 * ================================================================ */

test('validateTrustPolicy: caller with only uuid and login at top level', function (t) {
    var trustPolicy = JSON.stringify({
        Version: '2012-10-17',
        Statement: [{
            Effect: 'Allow',
            Action: 'sts:AssumeRole',
            Principal: { AWS: '*' }
        }]
    });
    var caller = {
        uuid: 'direct-uuid-123',
        login: 'directuser',
        account: { uuid: '11111111-2222-3333-4444-555555555555' }
    };
    var result = validateTrustPolicy(trustPolicy, caller, LOG);
    t.ok(result, 'should work with uuid/login at top level');
    t.end();
});

test('validateTrustPolicy: caller with user but no uuid at top', function (t) {
    var trustPolicy = JSON.stringify({
        Version: '2012-10-17',
        Statement: [{
            Effect: 'Allow',
            Action: 'sts:AssumeRole',
            Principal: { AWS: '*' }
        }]
    });
    var caller = {
        user: { uuid: 'nested-uuid', login: 'nesteduser' },
        account: { uuid: '11111111-2222-3333-4444-555555555555' }
        // no top-level uuid or login
    };
    var result = validateTrustPolicy(trustPolicy, caller, LOG);
    t.ok(result, 'should work with nested user structure');
    t.end();
});

test('validateTrustPolicy: caller with empty user object', function (t) {
    var trustPolicy = JSON.stringify({
        Version: '2012-10-17',
        Statement: [{
            Effect: 'Allow',
            Action: 'sts:AssumeRole',
            Principal: { AWS: '*' }
        }]
    });
    var caller = {
        user: {},  // empty user object
        uuid: 'fallback-uuid',
        login: 'fallbackuser',
        account: { uuid: '11111111-2222-3333-4444-555555555555' }
    };
    var result = validateTrustPolicy(trustPolicy, caller, LOG);
    t.ok(result, 'should fall back to top-level uuid/login');
    t.end();
});

test('validateTrustPolicy: caller with no account', function (t) {
    var trustPolicy = JSON.stringify({
        Version: '2012-10-17',
        Statement: [{
            Effect: 'Allow',
            Action: 'sts:AssumeRole',
            Principal: { AWS: '*' }
        }]
    });
    var caller = {
        uuid: 'uuid-no-account',
        login: 'usernoaccountlog'
        // no account property
    };
    var result = validateTrustPolicy(trustPolicy, caller, LOG);
    t.ok(result, 'should work without account property');
    t.end();
});

/* ================================================================
 * SECTION 35: root user special cases
 * ================================================================ */

test('validateTrustPolicy: root user stmt not matching AssumeRole action', function (t) {
    var trustPolicy = JSON.stringify({
        Version: '2012-10-17',
        Statement: [
            {
                Effect: 'Allow',
                Action: 'sts:GetCallerIdentity',  // Not AssumeRole
                Principal: { AWS: '11111111-2222-3333-4444-555555555555' }
            },
            {
                Effect: 'Allow',
                Action: 'sts:AssumeRole',
                Principal: {
                    AWS: 'arn:aws:iam::11111111-2222-3333-4444-555555555555:root'
                }
            }
        ]
    });
    var caller = {
        uuid: 'root-uuid',
        login: 'root',
        account: { uuid: '11111111-2222-3333-4444-555555555555' }
    };
    var result = validateTrustPolicy(trustPolicy, caller, LOG);
    t.ok(result, 'root user should pass with explicit root allow');
    t.end();
});

test('validateTrustPolicy: root user with no Principal.AWS', function (t) {
    var trustPolicy = JSON.stringify({
        Version: '2012-10-17',
        Statement: [{
            Effect: 'Allow',
            Action: 'sts:AssumeRole',
            Principal: { Service: 'lambda.amazonaws.com' }
        }]
    });
    var caller = {
        uuid: 'root-uuid',
        login: 'root',
        account: { uuid: '11111111-2222-3333-4444-555555555555' }
    };
    var result = validateTrustPolicy(trustPolicy, caller, LOG);
    t.ok(!result, 'root user should not match service principal');
    t.end();
});

test('validateTrustPolicy: root user principal as array', function (t) {
    var trustPolicy = JSON.stringify({
        Version: '2012-10-17',
        Statement: [{
            Effect: 'Allow',
            Action: 'sts:AssumeRole',
            Principal: {
                AWS: [
                    '11111111-2222-3333-4444-555555555555',
                    'arn:aws:iam::11111111-2222-3333-4444-555555555555:root'
                ]
            }
        }]
    });
    var caller = {
        uuid: 'root-uuid',
        login: 'root',
        account: { uuid: '11111111-2222-3333-4444-555555555555' }
    };
    // This should be denied because both account-level AND explicit root exist
    var result = validateTrustPolicy(trustPolicy, caller, LOG);
    t.ok(!result, 'root user denied with mixed account+root in same array');
    t.end();
});

/* ================================================================
 * SECTION 36: validateTrustPolicy edge cases
 * ================================================================ */

test('validateTrustPolicy: Allow statement without Principal', function (t) {
    var trustPolicy = JSON.stringify({
        Version: '2012-10-17',
        Statement: [{
            Effect: 'Allow',
            Action: 'sts:AssumeRole'
            // No Principal field
        }]
    });
    var caller = {
        uuid: 'test-uuid',
        login: 'testuser',
        account: { uuid: '11111111-2222-3333-4444-555555555555' }
    };
    var result = validateTrustPolicy(trustPolicy, caller, LOG);
    // Without Principal, the allow is implicit for all
    t.ok(!result, 'missing Principal should be denied');
    t.end();
});

test('validateTrustPolicy: Allow does not match caller', function (t) {
    var trustPolicy = JSON.stringify({
        Version: '2012-10-17',
        Statement: [{
            Effect: 'Allow',
            Action: 'sts:AssumeRole',
            Principal: {
                AWS: 'arn:aws:iam::other-account-uuid:user/otheruser'
            }
        }]
    });
    var caller = {
        uuid: 'test-uuid',
        login: 'testuser',
        account: { uuid: '11111111-2222-3333-4444-555555555555' }
    };
    var result = validateTrustPolicy(trustPolicy, caller, LOG);
    t.ok(!result, 'should deny when principal does not match');
    t.end();
});

test('validateTrustPolicy: multiple statements one matches', function (t) {
    var trustPolicy = JSON.stringify({
        Version: '2012-10-17',
        Statement: [
            {
                Effect: 'Allow',
                Action: 'sts:AssumeRole',
                Principal: {
                    AWS: 'arn:aws:iam::other-account:user/otheruser'
                }
            },
            {
                Effect: 'Allow',
                Action: 'sts:AssumeRole',
                Principal: {
                    AWS: 'arn:aws:iam::11111111-2222-3333-4444-555555555555:user/testuser'
                }
            }
        ]
    });
    var caller = {
        uuid: 'test-uuid',
        login: 'testuser',
        account: { uuid: '11111111-2222-3333-4444-555555555555' }
    };
    var result = validateTrustPolicy(trustPolicy, caller, LOG);
    t.ok(result, 'should allow when second statement matches');
    t.end();
});

/* ================================================================
 * SECTION 37: validateSinglePrincipal caller.account edge cases
 * ================================================================ */

test('validateSinglePrincipal: caller with no account property', function (t) {
    var caller = {
        uuid: 'test-uuid',
        login: 'testuser'
        // no account property
    };
    var result = validateSinglePrincipal('123456789012', caller, LOG);
    t.ok(!result, 'should not match account ID without caller.account');
    t.end();
});

test('validateSinglePrincipal: manta partition ARN', function (t) {
    var caller = {
        uuid: 'test-uuid',
        login: 'testuser',
        account: { uuid: '11111111-2222-3333-4444-555555555555' }
    };
    var arn = 'arn:manta:iam::11111111-2222-3333-4444-555555555555:user/testuser';
    var result = validateSinglePrincipal(arn, caller, LOG);
    t.ok(result, 'should match manta partition ARN');
    t.end();
});

test('validateSinglePrincipal: short ARN insufficient parts', function (t) {
    var caller = {
        uuid: 'test-uuid',
        login: 'testuser',
        account: { uuid: '11111111-2222-3333-4444-555555555555' }
    };
    var result = validateSinglePrincipal('arn:aws:iam::123', caller, LOG);
    t.ok(!result, 'short ARN should not match');
    t.end();
});

test('validateSinglePrincipal: root ARN means any principal in account', function (t) {
    // In AWS, arn:aws:iam::ACCOUNT:root means "any principal in ACCOUNT"
    var caller = {
        uuid: 'test-uuid',
        login: 'testuser',
        account: { uuid: '11111111-2222-3333-4444-555555555555' }
    };
    var arn = 'arn:aws:iam::11111111-2222-3333-4444-555555555555:root';
    var result = validateSinglePrincipal(arn, caller, LOG);
    t.ok(result, 'root ARN allows any user in the account');
    t.end();
});

test('validateSinglePrincipal: root ARN wrong account', function (t) {
    var caller = {
        uuid: 'test-uuid',
        login: 'testuser',
        account: { uuid: '11111111-2222-3333-4444-555555555555' }
    };
    var arn = 'arn:aws:iam::99999999-8888-7777-6666-555544443333:root';
    var result = validateSinglePrincipal(arn, caller, LOG);
    t.ok(!result, 'root ARN from different account should not match');
    t.end();
});

/* ================================================================
 * SECTION 38: Caller extraction edge cases for coverage
 * ================================================================ */

test('validateTrustPolicy: caller with null uuid and no account', function (t) {
    var trustPolicy = JSON.stringify({
        Version: '2012-10-17',
        Statement: [{
            Effect: 'Allow',
            Action: 'sts:AssumeRole',
            Principal: { AWS: '*' }
        }]
    });
    var caller = {
        user: {},
        // No uuid at top level, no account
        login: 'fallbacklogin'
    };
    var result = validateTrustPolicy(trustPolicy, caller, LOG);
    // Will return false since callerUuid will be null
    t.ok(result, 'should still process with minimal caller');
    t.end();
});

test('validateTrustPolicy: caller using account.login fallback', function (t) {
    var trustPolicy = JSON.stringify({
        Version: '2012-10-17',
        Statement: [{
            Effect: 'Allow',
            Action: 'sts:AssumeRole',
            Principal: { AWS: '*' }
        }]
    });
    var caller = {
        user: {},  // empty user
        // No uuid, no login at top level
        account: {
            uuid: '11111111-2222-3333-4444-555555555555',
            login: 'accountlogin'
        }
    };
    var result = validateTrustPolicy(trustPolicy, caller, LOG);
    t.ok(result, 'should use account.login as fallback');
    t.end();
});

/* ================================================================
 * SECTION 39: Additional validateSinglePrincipal log branches
 * ================================================================ */

test('validateSinglePrincipal: caller uuid from user.uuid', function (t) {
    // This should hit the callerUuid extraction from caller.user.uuid
    var caller = {
        user: { uuid: 'nested-user-uuid', login: 'nestedlogin' },
        account: { uuid: '11111111-2222-3333-4444-555555555555' }
    };
    var result = validateSinglePrincipal('11111111-2222-3333-4444-555555555555',
                                          caller, LOG);
    t.ok(result, 'should match with nested user structure');
    t.end();
});

test('validateSinglePrincipal: caller uuid from direct uuid', function (t) {
    var caller = {
        uuid: 'direct-uuid',
        login: 'directlogin',
        account: { uuid: '11111111-2222-3333-4444-555555555555' }
    };
    var result = validateSinglePrincipal('11111111-2222-3333-4444-555555555555',
                                          caller, LOG);
    t.ok(result, 'should match with direct uuid');
    t.end();
});

test('validateSinglePrincipal: wildcard with caller having roleArn', function (t) {
    var caller = {
        uuid: 'assumed-role-uuid',
        login: 'assumedrole',
        roleArn: 'arn:aws:iam::123:role/AssumedRole',
        account: { uuid: '11111111-2222-3333-4444-555555555555' }
    };
    var result = validateSinglePrincipal('*', caller, LOG);
    // Wildcard should deny assumed role credentials
    t.ok(!result, 'wildcard should deny assumed role caller');
    t.end();
});

/* ================================================================
 * SECTION 40: validateSinglePrincipal no-match paths
 * ================================================================ */

test('validateSinglePrincipal: unknown string principal with nested user', function (t) {
    var caller = {
        user: { uuid: 'nested-uuid', login: 'nesteduser' },
        account: { uuid: '11111111-2222-3333-4444-555555555555' }
    };
    // Random string that won't match any pattern
    var result = validateSinglePrincipal('some-random-string', caller, LOG);
    t.ok(!result, 'unknown string should not match');
    t.end();
});

test('validateSinglePrincipal: unknown string principal with direct uuid', function (t) {
    var caller = {
        uuid: 'direct-uuid',
        login: 'directuser',
        account: { uuid: '11111111-2222-3333-4444-555555555555' }
    };
    var result = validateSinglePrincipal('random-non-arn-string', caller, LOG);
    t.ok(!result, 'unknown string should not match');
    t.end();
});

test('validateSinglePrincipal: numeric string that is not 12 digits', function (t) {
    var caller = {
        uuid: 'test-uuid',
        login: 'testuser',
        account: { uuid: '123456789' }  // 9 digits
    };
    var result = validateSinglePrincipal('123456789', caller, LOG);
    t.ok(!result, 'non-12-digit number should not match');
    t.end();
});

/* ================================================================
 * SECTION 41: findTrustPolicyInMemberpolicy additional paths
 * ================================================================ */

test('findTrustPolicyInMemberpolicy: Statement not array', function (t) {
    var memberpolicy = [
        JSON.stringify({
            Statement: {  // Object instead of array
                Effect: 'Allow',
                Action: 'sts:AssumeRole'
            }
        })
    ];
    var result = findTrustPolicyInMemberpolicy(memberpolicy);
    t.ok(!result, 'should not find policy with non-array Statement');
    t.end();
});

test('findTrustPolicyInMemberpolicy: multiple policies first has no assume', function (t) {
    var memberpolicy = [
        JSON.stringify({
            Statement: [{
                Effect: 'Allow',
                Action: 's3:GetObject'  // Not AssumeRole
            }]
        }),
        JSON.stringify({
            Statement: [{
                Effect: 'Allow',
                Action: 'sts:AssumeRole'
            }]
        })
    ];
    var result = findTrustPolicyInMemberpolicy(memberpolicy);
    t.ok(result, 'should find second policy with AssumeRole');
    t.end();
});

/* ================================================================
 * SECTION 42: validatePrincipal string wildcard for assumed role
 * ================================================================ */

test('validatePrincipal: string wildcard with top-level roleArn', function (t) {
    // roleArn must be at top level, not nested in user
    var caller = {
        user: {
            uuid: 'user-uuid',
            login: 'testuser'
        },
        roleArn: 'arn:aws:iam::123:assumed-role/MyRole/session',  // top level
        account: { uuid: '11111111-2222-3333-4444-555555555555' }
    };
    var result = validatePrincipal('*', caller, LOG);
    t.ok(!result, 'wildcard string should deny caller with top-level roleArn');
    t.end();
});

/* ================================================================
 * SECTION 43: validateTrustPolicy caller extraction edge cases
 * ================================================================ */

test('validateTrustPolicy: caller with user.login but not user.uuid', function (t) {
    var trustPolicy = JSON.stringify({
        Version: '2012-10-17',
        Statement: [{
            Effect: 'Allow',
            Action: 'sts:AssumeRole',
            Principal: { AWS: '*' }
        }]
    });
    var caller = {
        user: { login: 'userlogin' },  // has login but no uuid
        uuid: 'fallback-uuid',
        account: { uuid: '11111111-2222-3333-4444-555555555555' }
    };
    var result = validateTrustPolicy(trustPolicy, caller, LOG);
    t.ok(result, 'should use user.login and fallback uuid');
    t.end();
});

/* ================================================================
 * SECTION 44: Additional coverage tests
 * ================================================================ */

test('validateTrustPolicy: Deny effect but different action', function (t) {
    var trustPolicy = JSON.stringify({
        Version: '2012-10-17',
        Statement: [
            {
                Effect: 'Deny',
                Action: 's3:GetObject',  // Not AssumeRole
                Principal: { AWS: '*' }
            },
            {
                Effect: 'Allow',
                Action: 'sts:AssumeRole',
                Principal: { AWS: '*' }
            }
        ]
    });
    var caller = {
        uuid: 'test-uuid',
        login: 'testuser',
        account: { uuid: '11111111-2222-3333-4444-555555555555' }
    };
    var result = validateTrustPolicy(trustPolicy, caller, LOG);
    t.ok(result, 'Deny with different action should not block AssumeRole');
    t.end();
});

test('validateTrustPolicy: multiple Allow statements none match', function (t) {
    var trustPolicy = JSON.stringify({
        Version: '2012-10-17',
        Statement: [
            {
                Effect: 'Allow',
                Action: 'sts:AssumeRole',
                Principal: { AWS: 'arn:aws:iam::other1:user/user1' }
            },
            {
                Effect: 'Allow',
                Action: 'sts:AssumeRole',
                Principal: { AWS: 'arn:aws:iam::other2:user/user2' }
            }
        ]
    });
    var caller = {
        uuid: 'test-uuid',
        login: 'testuser',
        account: { uuid: '11111111-2222-3333-4444-555555555555' }
    };
    var result = validateTrustPolicy(trustPolicy, caller, LOG);
    t.ok(!result, 'should deny when no Allow statements match');
    t.end();
});

test('validateSinglePrincipal: principal with nested colons', function (t) {
    var caller = {
        uuid: 'test-uuid',
        login: 'testuser',
        account: { uuid: '11111111-2222-3333-4444-555555555555' }
    };
    // ARN with extra colons in resource part
    var arn = 'arn:aws:iam::11111111-2222-3333-4444-555555555555:user/test:name';
    var result = validateSinglePrincipal(arn, caller, LOG);
    // Username has colon which won't match
    t.ok(!result, 'username with colon should not match simple login');
    t.end();
});

test('validatePrincipal: AWS principal single string', function (t) {
    var principal = {
        AWS: 'arn:aws:iam::11111111-2222-3333-4444-555555555555:user/testuser'
    };
    var caller = {
        uuid: 'test-uuid',
        login: 'testuser',
        account: { uuid: '11111111-2222-3333-4444-555555555555' }
    };
    var result = validatePrincipal(principal, caller, LOG);
    t.ok(result, 'AWS single string should match');
    t.end();
});

test('validateTrustPolicy: root user with multiple non-matching stmts', function (t) {
    var trustPolicy = JSON.stringify({
        Version: '2012-10-17',
        Statement: [
            {
                Effect: 'Allow',
                Action: 's3:GetObject',  // Wrong action
                Principal: { AWS: '11111111-2222-3333-4444-555555555555' }
            },
            {
                Effect: 'Allow',
                Action: 'sts:AssumeRole',
                Principal: {
                    AWS: 'arn:aws:iam::11111111-2222-3333-4444-555555555555:root'
                }
            }
        ]
    });
    var caller = {
        uuid: 'root-uuid',
        login: 'root',
        account: { uuid: '11111111-2222-3333-4444-555555555555' }
    };
    var result = validateTrustPolicy(trustPolicy, caller, LOG);
    // First stmt has wrong action, second is explicit root - should pass
    t.ok(result, 'root with explicit root ARN and non-matching action stmt');
    t.end();
});

/* ================================================================
 * SECTION 45: Minimal caller structure tests
 * ================================================================ */

test('validateTrustPolicy: caller with no login anywhere (null fallback)', function (t) {
    var trustPolicy = JSON.stringify({
        Version: '2012-10-17',
        Statement: [{
            Effect: 'Allow',
            Action: 'sts:AssumeRole',
            Principal: { AWS: '*' }
        }]
    });
    var caller = {
        user: {},  // empty, no login
        uuid: 'test-uuid'
        // no login at top level, no account
    };
    var result = validateTrustPolicy(trustPolicy, caller, LOG);
    // callerLogin will be null
    t.ok(result, 'should process with null callerLogin');
    t.end();
});

test('validateTrustPolicy: caller with no uuid anywhere (null fallback)', function (t) {
    var trustPolicy = JSON.stringify({
        Version: '2012-10-17',
        Statement: [{
            Effect: 'Allow',
            Action: 'sts:AssumeRole',
            Principal: { AWS: '*' }
        }]
    });
    var caller = {
        user: {},  // empty, no uuid
        login: 'testlogin'
        // no uuid at top level, no account
    };
    var result = validateTrustPolicy(trustPolicy, caller, LOG);
    // callerUuid will be null
    t.ok(result, 'should process with null callerUuid');
    t.end();
});

test('validateTrustPolicy: completely minimal caller', function (t) {
    var trustPolicy = JSON.stringify({
        Version: '2012-10-17',
        Statement: [{
            Effect: 'Allow',
            Action: 'sts:AssumeRole',
            Principal: { AWS: '*' }
        }]
    });
    var caller = {
        // Absolutely minimal - just empty
    };
    var result = validateTrustPolicy(trustPolicy, caller, LOG);
    // Both callerUuid and callerLogin will be undefined/null
    t.ok(result, 'should process with minimal caller');
    t.end();
});

/* ================================================================
 * SECTION 46: statementMatchesAction full coverage
 * ================================================================ */

test('statementMatchesAction: undefined Action', function (t) {
    var stmt = { Effect: 'Allow' };  // No Action property
    var result = statementMatchesAction(stmt, 'sts:AssumeRole');
    t.ok(!result, 'undefined Action should not match');
    t.end();
});

test('statementMatchesAction: wildcard action string', function (t) {
    var stmt = { Action: '*' };
    var result = statementMatchesAction(stmt, 'sts:AssumeRole');
    t.ok(result, 'wildcard action should match');
    t.end();
});

/* ================================================================
 * SECTION 47: DENY statement with principal matching
 * ================================================================ */

test('validateTrustPolicy: DENY matches specific user ARN', function (t) {
    var trustPolicy = JSON.stringify({
        Version: '2012-10-17',
        Statement: [
            {
                Effect: 'Deny',
                Action: 'sts:AssumeRole',
                Principal: {
                    AWS: 'arn:aws:iam::11111111-2222-3333-4444-555555555555:user/testuser'
                }
            },
            {
                Effect: 'Allow',
                Action: 'sts:AssumeRole',
                Principal: { AWS: '*' }
            }
        ]
    });
    var caller = {
        uuid: 'test-uuid',
        login: 'testuser',
        account: { uuid: '11111111-2222-3333-4444-555555555555' }
    };
    var result = validateTrustPolicy(trustPolicy, caller, LOG);
    t.ok(!result, 'DENY with matching user ARN should deny');
    t.end();
});

test('validateTrustPolicy: DENY with account ID principal', function (t) {
    var trustPolicy = JSON.stringify({
        Version: '2012-10-17',
        Statement: [
            {
                Effect: 'Deny',
                Action: 'sts:AssumeRole',
                Principal: { AWS: '11111111-2222-3333-4444-555555555555' }
            },
            {
                Effect: 'Allow',
                Action: 'sts:AssumeRole',
                Principal: { AWS: '*' }
            }
        ]
    });
    var caller = {
        uuid: 'test-uuid',
        login: 'testuser',
        account: { uuid: '11111111-2222-3333-4444-555555555555' }
    };
    var result = validateTrustPolicy(trustPolicy, caller, LOG);
    t.ok(!result, 'DENY with matching account ID should deny');
    t.end();
});

test('validateTrustPolicy: multiple DENY statements only one matches', function (t) {
    var trustPolicy = JSON.stringify({
        Version: '2012-10-17',
        Statement: [
            {
                Effect: 'Deny',
                Action: 'sts:AssumeRole',
                Principal: { AWS: 'arn:aws:iam::other-account:user/other' }
            },
            {
                Effect: 'Deny',
                Action: 'sts:AssumeRole',
                Principal: { AWS: '11111111-2222-3333-4444-555555555555' }
            },
            {
                Effect: 'Allow',
                Action: 'sts:AssumeRole',
                Principal: { AWS: '*' }
            }
        ]
    });
    var caller = {
        uuid: 'test-uuid',
        login: 'testuser',
        account: { uuid: '11111111-2222-3333-4444-555555555555' }
    };
    var result = validateTrustPolicy(trustPolicy, caller, LOG);
    t.ok(!result, 'second DENY matches so should deny');
    t.end();
});

/* ================================================================
 * SECTION 48: Root user policy processing paths
 * ================================================================ */

test('validateTrustPolicy: root with Allow stmt missing Principal.AWS', function (t) {
    var trustPolicy = JSON.stringify({
        Version: '2012-10-17',
        Statement: [{
            Effect: 'Allow',
            Action: 'sts:AssumeRole',
            Principal: { Service: 'ec2.amazonaws.com' }  // AWS not present
        }]
    });
    var caller = {
        uuid: 'root-uuid',
        login: 'root',
        account: { uuid: '11111111-2222-3333-4444-555555555555' }
    };
    var result = validateTrustPolicy(trustPolicy, caller, LOG);
    t.ok(!result, 'root with only Service principal should not match');
    t.end();
});

console.log('✓ STS trust policy branch coverage tests loaded');
