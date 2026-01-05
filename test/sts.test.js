/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2026 Edgecast Cloud LLC.
 */

/**
 * Unit tests for STS (Security Token Service) functionality
 * Tests AWS IAM trust policy validation including new 'Deny' support
 */

var bunyan = require('bunyan');
var nodeunit = require('nodeunit-plus');
var test = nodeunit.test;

// Import the STS functions directly for unit testing
var sts = require('../lib/server/sts.js');

// Access internal functions for testing
var validateTrustPolicy = sts.internal.validateTrustPolicy;
var validatePrincipal = sts.internal.validatePrincipal;
var validateSinglePrincipal = sts.internal.validateSinglePrincipal;
var validateServicePrincipal = sts.internal.validateServicePrincipal;
var statementMatchesAction = sts.internal.statementMatchesAction;
var generateUUID = sts.internal.generateUUID;
var generateSessionTokenAccessKeyId =
        sts.internal.generateSessionTokenAccessKeyId;
var accesskey = require('ufds/lib/accesskey');
// Removed: generateSessionToken (insecure Base64 method)
// Use session-token.js module for secure JWT generation

// Create a mock logger for tests
var LOG = bunyan.createLogger({
    name: 'sts-test',
    level: process.env.LOG_LEVEL || 'fatal'
});

// Mock caller objects for testing
var MOCK_CALLERS = {
    testUser: {
        uuid: 'test-user-uuid-123',
        login: 'testuser',
        account: {
            uuid: '123456789012',
            login: 'testaccount'
        }
    },
    maliciousUser: {
        uuid: 'malicious-user-uuid-456',
        login: 'malicious',
        account: {
            uuid: '123456789012',
            login: 'testaccount'
        }
    },
    contractor1: {
        uuid: 'contractor1-uuid-789',
        login: 'contractor1',
        account: {
            uuid: '123456789012',
            login: 'testaccount'
        }
    },
    contractor2: {
        uuid: 'contractor2-uuid-abc',
        login: 'contractor2',
        account: {
            uuid: '123456789012',
            login: 'testaccount'
        }
    },
    otherAccountUser: {
        uuid: 'other-user-uuid-def',
        login: 'otheruser',
        account: {
            uuid: '999888777666',
            login: 'otherapcount'
        }
    },
    rootUser: {
        uuid: 'root-user-uuid-ghi',
        login: 'root',
        account: {
            uuid: '123456789012',
            login: 'testaccount'
        }
    }
};

//
// Test Suite 0: Helper Function Tests
//

test('statementMatchesAction: matches single action', function (t) {
    var statement = { 'Action': 'sts:AssumeRole' };
    var result = statementMatchesAction(statement, 'sts:AssumeRole');
    t.ok(result, 'should match single action');
    t.end();
});

test('statementMatchesAction: matches wildcard action', function (t) {
    var statement = { 'Action': '*' };
    var result = statementMatchesAction(statement, 'sts:AssumeRole');
    t.ok(result, 'should match wildcard action');
    t.end();
});

test('statementMatchesAction: matches action in array', function (t) {
    var statement = { 'Action': ['s3:GetObject', 'sts:AssumeRole',
                                 'iam:ListRoles'] };
    var result = statementMatchesAction(statement, 'sts:AssumeRole');
    t.ok(result, 'should match action in array');
    t.end();
});

test('statementMatchesAction: does not match different action', function (t) {
    var statement = { 'Action': 's3:GetObject' };
    var result = statementMatchesAction(statement, 'sts:AssumeRole');
    t.ok(!result, 'should not match different action');
    t.end();
});

test('validateSinglePrincipal: matches wildcard', function (t) {
    var result = validateSinglePrincipal('*', MOCK_CALLERS.testUser, LOG);
    t.ok(result, 'should match wildcard principal');
    t.end();
});

test('validateSinglePrincipal: matches user ARN', function (t) {
    var arn = 'arn:aws:iam::123456789012:user/testuser';
    var result = validateSinglePrincipal(arn, MOCK_CALLERS.testUser, LOG);
    t.ok(result, 'should match user ARN');
    t.end();
});

test('validateSinglePrincipal: does not match wrong user ARN', function (t) {
    var arn = 'arn:aws:iam::123456789012:user/wronguser';
    var result = validateSinglePrincipal(arn, MOCK_CALLERS.testUser, LOG);
    t.ok(!result, 'should not match wrong user ARN');
    t.end();
});

test('credential generation functions work', function (t) {
    var uuid = generateUUID();
    var tempAccessKey = generateSessionTokenAccessKeyId();

    t.ok(uuid && uuid.length === 36, 'UUID should be 36 characters');
    t.ok(tempAccessKey.indexOf('MSTS') === 0,
         'temp access key should start with MSTS');

    // Test secret key generation using node-ufds accesskey module
    accesskey.generate(accesskey.DEFAULT_PREFIX, accesskey.DEFAULT_BYTE_LENGTH,
        function (err, tempSecret) {
        t.ifError(err, 'should generate secret without error');
        t.ok(tempSecret && tempSecret.indexOf('tdc_') === 0,
             'temp secret should start with tdc_ prefix');
        t.ok(accesskey.validate(accesskey.DEFAULT_PREFIX,
             accesskey.DEFAULT_BYTE_LENGTH, tempSecret),
             'temp secret should pass validation');
        t.end();
    });
});

//
// Service Principal Validation Tests
//

test('validateServicePrincipal: allows whitelisted services', function (t) {
    var allowedServices = [
        'lambda.amazonaws.com',
        'ec2.amazonaws.com',
        'glue.amazonaws.com',
        'datapipeline.amazonaws.com',
        'elasticmapreduce.amazonaws.com',
        'batch.amazonaws.com',
        'ecs-tasks.amazonaws.com',
        'states.amazonaws.com'
    ];

    allowedServices.forEach(function (service) {
        var result = validateServicePrincipal(service, LOG);
        t.ok(result, service + ' should be allowed (whitelisted)');
    });

    t.end();
});

test('validateServicePrincipal: denies unknown services', function (t) {
    var deniedServices = [
        'malicious-service.com',
        'unknown.amazonaws.com',
        'rogue.service.net',
        'attacker.amazonaws.com',
        '',
        null,
        undefined
    ];

    deniedServices.forEach(function (service) {
        var result = validateServicePrincipal(service, LOG);
        t.ok(!result, (service || 'null/undefined') +
             ' should be denied (not whitelisted)');
    });

    t.end();
});

test('validateServicePrincipal: case sensitive validation', function (t) {
    // Correct case
    var correctResult = validateServicePrincipal('lambda.amazonaws.com', LOG);
    t.ok(correctResult, 'correct case should be allowed');

    // Wrong case should be denied
    var wrongCaseResults = [
        validateServicePrincipal('Lambda.amazonaws.com', LOG),
        validateServicePrincipal('LAMBDA.AMAZONAWS.COM', LOG),
        validateServicePrincipal('lambda.AMAZONAWS.COM', LOG)
    ];

    wrongCaseResults.forEach(function (result, idx) {
        t.ok(!result, 'wrong case variant ' + idx +
             ' should be denied (case sensitive)');
    });

    t.end();
});

//
// Test Suite 1: Basic Trust Policy Validation (Backwards Compatibility)
//

test('trust policy: simple allow policy works', function (t) {
    var trustPolicy = JSON.stringify({
        'Version': '2012-10-17',
        'Statement': [ {
            'Effect': 'Allow',
            'Principal': {'AWS': 'arn:aws:iam::123456789012:user/testuser'},
            'Action': 'sts:AssumeRole'
        }]
    });

    var result = validateTrustPolicy(trustPolicy, MOCK_CALLERS.testUser, LOG);
    t.ok(result, 'testuser should be allowed by simple allow policy');
    t.end();
});

test('trust policy: allow policy denies wrong user', function (t) {
    var trustPolicy = JSON.stringify({
        'Version': '2012-10-17',
        'Statement': [ {
            'Effect': 'Allow',
            'Principal': {'AWS': 'arn:aws:iam::123456789012:user/testuser'},
            'Action': 'sts:AssumeRole'
        }]
    });

    var result = validateTrustPolicy(trustPolicy,
                                     MOCK_CALLERS.maliciousUser, LOG);
    t.ok(!result, 'malicious user should be denied by specific allow policy');
    t.end();
});

test('trust policy: wildcard allow policy allows anyone', function (t) {
    var trustPolicy = JSON.stringify({
        'Version': '2012-10-17',
        'Statement': [ {
            'Effect': 'Allow',
            'Principal': {'AWS': '*'},
            'Action': 'sts:AssumeRole'
        }]
    });

    var result1 = validateTrustPolicy(trustPolicy, MOCK_CALLERS.testUser, LOG);
    var result2 = validateTrustPolicy(trustPolicy, MOCK_CALLERS.maliciousUser,
                                      LOG);
    var result3 = validateTrustPolicy(trustPolicy,
                                      MOCK_CALLERS.otherAccountUser, LOG);

    t.ok(result1, 'testuser should be allowed by wildcard policy');
    t.ok(result2, 'malicious user should be allowed by wildcard policy');
    t.ok(result3, 'other account user should be allowed by wildcard policy');
    t.end();
});

//
// Test Suite 2: NEW - Explicit Deny Support
//

test('trust policy: explicit deny overrides allow', function (t) {
    var trustPolicy = JSON.stringify({
        'Version': '2012-10-17',
        'Statement': [
            {
                'Effect': 'Allow',
                'Principal': {'AWS': '*'},
                'Action': 'sts:AssumeRole'
            },
            {
                'Effect': 'Deny',
                'Principal':
                {'AWS': 'arn:aws:iam::123456789012:user/malicious'},
                'Action': 'sts:AssumeRole'
            }
        ]
    });

    var allowResult = validateTrustPolicy(trustPolicy,
                                          MOCK_CALLERS.testUser, LOG);
    var denyResult = validateTrustPolicy(trustPolicy,
                                         MOCK_CALLERS.maliciousUser, LOG);

    t.ok(allowResult, 'testuser should be allowed (not in deny list)');
    t.ok(!denyResult,
         'malicious user should be denied (explicit deny overrides allow)');
    t.end();
});

test('trust policy: multiple deny statements', function (t) {
    var trustPolicy = JSON.stringify({
        'Version': '2012-10-17',
        'Statement': [
            {
                'Effect': 'Allow',
                'Principal': {'AWS': '123456789012'},
                'Action': 'sts:AssumeRole'
            },
            {
                'Effect': 'Deny',
                'Principal': {'AWS':
                              'arn:aws:iam::123456789012:user/contractor1'},
                'Action': '*'
            },
            {
                'Effect': 'Deny',
                'Principal': {'AWS':
                              'arn:aws:iam::123456789012:user/contractor2'},
                'Action': 'sts:AssumeRole'
            }
        ]
    });

    var allowedUser = validateTrustPolicy(trustPolicy, MOCK_CALLERS.testUser,
                                          LOG);
    var deniedContractor1 = validateTrustPolicy(trustPolicy,
                                                MOCK_CALLERS.contractor1, LOG);
    var deniedContractor2 = validateTrustPolicy(trustPolicy,
                                                MOCK_CALLERS.contractor2, LOG);

    t.ok(allowedUser, 'testuser should be allowed (not in any deny list)');
    t.ok(!deniedContractor1, 'contractor1 should be denied (wildcard deny)');
    t.ok(!deniedContractor2, 'contractor2 should be denied (specific deny)');
    t.end();
});

test('trust policy: deny with wildcard action', function (t) {
    var trustPolicy = JSON.stringify({
        'Version': '2012-10-17',
        'Statement': [
            {
                'Effect': 'Allow',
                'Principal': {'AWS': 'arn:aws:iam::123456789012:user/testuser'},
                'Action': 'sts:AssumeRole'
            },
            {
                'Effect': 'Deny',
                'Principal': {'AWS': 'arn:aws:iam::123456789012:user/testuser'},
                'Action': '*'
            }
        ]
    });

    var result = validateTrustPolicy(trustPolicy, MOCK_CALLERS.testUser, LOG);
    t.ok(!result,
         'testuser should be denied (wildcard deny overrides specific allow)');
    t.end();
});

test('trust policy: deny with array of principals', function (t) {
    var trustPolicy = JSON.stringify({
        'Version': '2012-10-17',
        'Statement': [
            {
                'Effect': 'Allow',
                'Principal': {'AWS': '123456789012'},
                'Action': 'sts:AssumeRole'
            },
            {
                'Effect': 'Deny',
                'Principal': {'AWS': [
                    'arn:aws:iam::123456789012:user/contractor1',
                    'arn:aws:iam::123456789012:user/contractor2'
                ]},
                'Action': 'sts:AssumeRole'
            }
        ]
    });

    var allowedUser = validateTrustPolicy(trustPolicy, MOCK_CALLERS.testUser,
                                          LOG);
    var deniedContractor1 = validateTrustPolicy(trustPolicy,
                                                MOCK_CALLERS.contractor1, LOG);
    var deniedContractor2 = validateTrustPolicy(trustPolicy,
                                                MOCK_CALLERS.contractor2, LOG);

    t.ok(allowedUser, 'testuser should be allowed (not in deny array)');
    t.ok(!deniedContractor1, 'contractor1 should be denied (in deny array)');
    t.ok(!deniedContractor2, 'contractor2 should be denied (in deny array)');
    t.end();
});

//
// Test Suite 3: Edge Cases and Policy Evaluation Order
//

test('trust policy: only deny statements (implicit deny)', function (t) {
    var trustPolicy = JSON.stringify({
        'Version': '2012-10-17',
        'Statement': [ {
            'Effect': 'Deny',
            'Principal': {'AWS': '*'},
            'Action': '*'
        }]
    });

    var result1 = validateTrustPolicy(trustPolicy, MOCK_CALLERS.testUser, LOG);
    var result2 = validateTrustPolicy(trustPolicy,
                                      MOCK_CALLERS.maliciousUser, LOG);

    t.ok(!result1, 'testuser should be denied (no explicit allow)');
    t.ok(!result2, 'malicious user should be denied (no explicit allow)');
    t.end();
});

test('trust policy: deny non-matching action should not affect result',
     function (t) {
    var trustPolicy = JSON.stringify({
        'Version': '2012-10-17',
        'Statement': [
            {
                'Effect': 'Allow',
                'Principal': {'AWS': 'arn:aws:iam::123456789012:user/testuser'},
                'Action': 'sts:AssumeRole'
            },
            {
                'Effect': 'Deny',
                'Principal': {'AWS': 'arn:aws:iam::123456789012:user/testuser'},
                'Action': 's3:GetObject'  // Different action
            }
        ]
    });

    var result = validateTrustPolicy(trustPolicy, MOCK_CALLERS.testUser, LOG);
    t.ok(result,
         'testuser should be allowed (deny applies to different action)');
    t.end();
});

test('trust policy: deny non-matching principal should not affect result',
     function (t) {
    var trustPolicy = JSON.stringify({
        'Version': '2012-10-17',
        'Statement': [
            {
                'Effect': 'Allow',
                'Principal': {'AWS': 'arn:aws:iam::123456789012:user/testuser'},
                'Action': 'sts:AssumeRole'
            },
            {
                'Effect': 'Deny',
                'Principal': {'AWS': 'arn:aws:iam::999888777666:user/testuser'},
                'Action': 'sts:AssumeRole'  // Different account
            }
        ]
    });

    var result = validateTrustPolicy(trustPolicy, MOCK_CALLERS.testUser, LOG);
    t.ok(result,
         'testuser should be allowed (deny applies to different account)');
    t.end();
});

//
// Test Suite 4: Complex Policies and Policy Evaluation Order
//

test('trust policy: complex policy with multiple effects', function (t) {
    var trustPolicy = JSON.stringify({
        'Version': '2012-10-17',
        'Statement': [
            {
                'Effect': 'Allow',
                'Principal': {'AWS': '123456789012'},
                'Action': 'sts:AssumeRole'
            },
            {
                'Effect': 'Deny',
                'Principal': {'AWS':
                              'arn:aws:iam::123456789012:user/contractor1'},
                'Action': '*'
            },
            {
                'Effect': 'Allow',
                'Principal': {'AWS': 'arn:aws:iam::123456789012:root'},
                'Action': '*'
            },
            {
                'Effect': 'Deny',
                'Principal': {'AWS':
                              'arn:aws:iam::123456789012:user/contractor2'},
                'Action': 'sts:AssumeRole'
            }
        ]
    });

    var normalUser = validateTrustPolicy(trustPolicy,
                                         MOCK_CALLERS.testUser, LOG);
    var contractor1 = validateTrustPolicy(trustPolicy,
                                          MOCK_CALLERS.contractor1, LOG);
    var contractor2 = validateTrustPolicy(trustPolicy,
                                          MOCK_CALLERS.contractor2, LOG);
    var rootUser = validateTrustPolicy(trustPolicy,
                                       MOCK_CALLERS.rootUser, LOG);

    t.ok(normalUser, 'normal user should be allowed');
    t.ok(!contractor1, 'contractor1 should be denied (wildcard deny)');
    t.ok(!contractor2, 'contractor2 should be denied (specific deny)');
    t.ok(!rootUser, 'root user should be denied' +
         ' (account-level allow but deny doesn\'t match)');
    t.end();
});

test('trust policy: statement order should not matter', function (t) {
    // Test with deny first, then allow
    var trustPolicy1 = JSON.stringify({
        'Version': '2012-10-17',
        'Statement': [
            {
                'Effect': 'Deny',
                'Principal': {'AWS':
                              'arn:aws:iam::123456789012:user/malicious'},
                'Action': 'sts:AssumeRole'
            },
            {
                'Effect': 'Allow',
                'Principal': {'AWS': '*'},
                'Action': 'sts:AssumeRole'
            }
        ]
    });

    // Test with allow first, then deny
    var trustPolicy2 = JSON.stringify({
        'Version': '2012-10-17',
        'Statement': [
            {
                'Effect': 'Allow',
                'Principal': {'AWS': '*'},
                'Action': 'sts:AssumeRole'
            },
            {
                'Effect': 'Deny',
                'Principal': {'AWS':
                              'arn:aws:iam::123456789012:user/malicious'},
                'Action': 'sts:AssumeRole'
            }
        ]
    });

    var result1Allowed = validateTrustPolicy(trustPolicy1,
                                             MOCK_CALLERS.testUser, LOG);
    var result1Denied = validateTrustPolicy(trustPolicy1,
                                            MOCK_CALLERS.maliciousUser, LOG);
    var result2Allowed = validateTrustPolicy(trustPolicy2,
                                             MOCK_CALLERS.testUser, LOG);
    var result2Denied = validateTrustPolicy(trustPolicy2,
                                            MOCK_CALLERS.maliciousUser, LOG);

    t.ok(result1Allowed, 'testuser should be allowed (deny first policy)');
    t.ok(!result1Denied, 'malicious user should be denied (deny first policy)');
    t.ok(result2Allowed, 'testuser should be allowed (allow first policy)');
    t.ok(!result2Denied,
         'malicious user should be denied (allow first policy)');

    // Results should be identical regardless of statement order
    t.equal(result1Allowed, result2Allowed,
            'allow results should match regardless of order');
    t.equal(result1Denied, result2Denied,
            'deny results should match regardless of order');
    t.end();
});

//
// Test Suite 5: Error Handling and Malformed Policies
//

test('trust policy: invalid JSON should be rejected', function (t) {
    var invalidPolicy =
        {'Version': '2012-10-17', 'Statement': 'invalid json' };

    var result = validateTrustPolicy(invalidPolicy, MOCK_CALLERS.testUser, LOG);
    t.ok(!result, 'invalid JSON policy should be rejected');
    t.end();
});

test('trust policy: missing Statement should be rejected', function (t) {
    var invalidPolicy = JSON.stringify({
        'Version': '2012-10-17'
        // Missing Statement array
    });

    var result = validateTrustPolicy(invalidPolicy, MOCK_CALLERS.testUser, LOG);
    t.ok(!result, 'policy missing Statement should be rejected');
    t.end();
});

test('trust policy: non-array Statement should be rejected', function (t) {
    var invalidPolicy = JSON.stringify({
        'Version': '2012-10-17',
        'Statement': 'not an array'
    });

    var result = validateTrustPolicy(invalidPolicy, MOCK_CALLERS.testUser, LOG);
    t.ok(!result, 'policy with non-array Statement should be rejected');
    t.end();
});

test('trust policy: empty policy should deny all', function (t) {
    var emptyPolicy = JSON.stringify({
        'Version': '2012-10-17',
        'Statement': []
    });

    var result = validateTrustPolicy(emptyPolicy, MOCK_CALLERS.testUser, LOG);
    t.ok(!result, 'empty policy should deny all (implicit deny)');
    t.end();
});

//
// Test Suite 6: Principal Validation Edge Cases
//

test('principal validation: account UUID format', function (t) {
    var trustPolicy = JSON.stringify({
        'Version': '2012-10-17',
        'Statement': [ {
            'Effect': 'Allow',
            'Principal': {'AWS': '123456789012'},
            'Action': 'sts:AssumeRole'
        }]
    });

    var sameAccount = validateTrustPolicy(trustPolicy,
                                          MOCK_CALLERS.testUser, LOG);
    var otherAccount = validateTrustPolicy(trustPolicy,
                                           MOCK_CALLERS.otherAccountUser, LOG);

    t.ok(sameAccount, 'user from same account should be allowed');
    t.ok(!otherAccount, 'user from different account should be denied');
    t.end();
});

test('principal validation: service principal support', function (t) {
    var serviceTrustPolicy = JSON.stringify({
        'Version': '2012-10-17',
        'Statement': [ {
            'Effect': 'Allow',
            'Principal': {'Service': 'lambda.amazonaws.com'},
            'Action': 'sts:AssumeRole'
        }]
    });

    // Service principals should be validated by the new logic
    var serviceResult = validateTrustPolicy(serviceTrustPolicy,
                                            MOCK_CALLERS.testUser, LOG);

    // Note: This tests the integration - service principals
    // go through validatePrincipal -> validateServicePrincipal
    t.ok(!serviceResult, 'service principal should be processed ' +
         '(returns false as user is not service)');
    t.end();
});

test('principal validation: multiple service principals', function (t) {
    var multiServicePolicy = JSON.stringify({
        'Version': '2012-10-17',
        'Statement': [ {
            'Effect': 'Allow',
            'Principal': {
                'Service': [
                    'lambda.amazonaws.com',
                    'ec2.amazonaws.com'
                ]
            },
            'Action': 'sts:AssumeRole'
        }]
    });

    var result = validateTrustPolicy(multiServicePolicy,
                                     MOCK_CALLERS.testUser, LOG);
    t.ok(!result, 'multiple service principals should be processed');
    t.end();
});

test('principal validation: unknown service principal denied', function (t) {
    var unknownServicePolicy = JSON.stringify({
        'Version': '2012-10-17',
        'Statement': [ {
            'Effect': 'Allow',
            'Principal': {'Service': 'malicious-service.com'},
            'Action': 'sts:AssumeRole'
        }]
    });

    var result = validateTrustPolicy(unknownServicePolicy,
                                     MOCK_CALLERS.testUser, LOG);
    t.ok(!result, 'unknown service principal should be denied');
    t.end();
});

test('principal validation: root principal format', function (t) {
    var trustPolicy = JSON.stringify({
        'Version': '2012-10-17',
        'Statement': [ {
            'Effect': 'Allow',
            'Principal': {'AWS': 'arn:aws:iam::123456789012:root'},
            'Action': 'sts:AssumeRole'
        }]
    });

    var rootUser = validateTrustPolicy(trustPolicy, MOCK_CALLERS.rootUser, LOG);
    var normalUser = validateTrustPolicy(trustPolicy,
                                         MOCK_CALLERS.testUser, LOG);

    // Note: In AWS, arn:aws:iam::ACCOUNT:root means "any principal in ACCOUNT"
    // not specifically a user with login === 'root'. Both root and normal
    // users in the same account should be allowed.
    t.ok(rootUser, 'root user should be allowed by :root principal');
    t.ok(normalUser, 'normal user should be allowed by :root principal ' +
                     '(AWS semantics: :root = any principal in account)');
    t.end();
});

console.log('✓ STS trust policy validation tests loaded');
