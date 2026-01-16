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

console.log('✓ STS trust policy branch coverage tests loaded');
