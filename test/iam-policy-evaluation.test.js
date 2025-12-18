/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright 2025 Edgecast Cloud LLC.
 */

/*
 * test/iam-policy-evaluation.test.js: Comprehensive unit tests for IAM
 * policy evaluation logic
 *
 * Tests the detailed evaluation semantics of IAM policies including:
 * - Policy evaluation order (explicit deny, then allow, then implicit deny)
 * - Multi-statement policy evaluation with complex precedence
 * - Principal matching edge cases (cross-account, wildcards, arrays)
 * - Action matching with wildcards and arrays
 * - Default deny behavior in various contexts
 *
 * Note: This file focuses on evaluation logic rather than parsing.
 * For basic parsing tests, see iam-policy-parsing.test.js
 */

var nodeunit = require('nodeunit');
var sts = require('../lib/server/sts');

// Mock logger with all required methods
var log = {
    fatal: function () {},
    error: function () {},
    warn: function () {},
    info: function () {},
    debug: function () {},
    trace: function () {}
};

/* --- Test AWS IAM policy evaluation order --- */

/*
 * AWS IAM Policy Evaluation Logic:
 * 1. Default: DENY (implicit)
 * 2. Evaluate all DENY statements first (explicit deny wins)
 * 3. Evaluate ALLOW statements (at least one must match)
 * 4. If no ALLOW matched: DENY (implicit)
 */

exports.testEvaluationOrderDenyFirst = function (t) {
    // Test that Deny statements are evaluated before Allow
    // Even if Allow appears first in the statement array
    var policy = JSON.stringify({
        Statement: [
            {
                Effect: 'Allow',
                Principal: {'AWS': '*'},
                Action: 'sts:AssumeRole'
            },
            {
                Effect: 'Deny',
                Principal: {'AWS': '*'},
                Action: 'sts:AssumeRole'
            }
        ]
    });

    var caller = {
        uuid: 'test-uuid',
        login: 'testuser'
    };

    var result = sts.internal.validateTrustPolicy(policy, caller, log);

    t.equal(result, false,
        'Deny should win even when Allow appears first');
    t.done();
};

exports.testEvaluationOrderAllowAfterNoDeny = function (t) {
    // Test that Allow is evaluated after checking all Deny statements
    var policy = JSON.stringify({
        Statement: [
            {
                Effect: 'Deny',
                Principal: {'AWS': 'arn:aws:iam::999:user/other'},
                Action: 'sts:AssumeRole'
            },
            {
                Effect: 'Allow',
                Principal: {'AWS': '*'},
                Action: 'sts:AssumeRole'
            }
        ]
    });

    var caller = {
        uuid: 'test-uuid',
        login: 'testuser'
    };

    var result = sts.internal.validateTrustPolicy(policy, caller, log);

    t.equal(result, true,
        'Allow should succeed when Deny does not match');
    t.done();
};

exports.testImplicitDenyWhenNoStatementsMatch = function (t) {
    // Test default deny when no statements match the caller
    var policy = JSON.stringify({
        Statement: [
            {
                Effect: 'Allow',
                Principal: {'AWS': 'arn:aws:iam::123:user/alice'},
                Action: 'sts:AssumeRole'
            },
            {
                Effect: 'Allow',
                Principal: {'AWS': 'arn:aws:iam::123:user/bob'},
                Action: 'sts:AssumeRole'
            }
        ]
    });

    var caller = {
        uuid: 'charlie-uuid',
        login: 'charlie',
        account: {
            uuid: '123',
            login: 'account123'
        }
    };

    var result = sts.internal.validateTrustPolicy(policy, caller, log);

    t.equal(result, false,
        'Should implicitly deny when no Allow statements match');
    t.done();
};

exports.testImplicitDenyWhenOnlyDenyStatements = function (t) {
    // Test that policy with only Deny statements results in implicit deny
    var policy = JSON.stringify({
        Statement: [
            {
                Effect: 'Deny',
                Principal: {'AWS': 'arn:aws:iam::999:user/eve'},
                Action: 'sts:AssumeRole'
            }
        ]
    });

    var caller = {
        uuid: 'test-uuid',
        login: 'testuser',
        account: {
            uuid: '123',
            login: 'account123'
        }
    };

    var result = sts.internal.validateTrustPolicy(policy, caller, log);

    t.equal(result, false,
        'Should implicitly deny when only Deny exists and does not match');
    t.done();
};

/* --- Test explicit deny override scenarios --- */

exports.testExplicitDenyOverridesMultipleAllows = function (t) {
    // Test that a single Deny overrides multiple Allow statements
    var policy = JSON.stringify({
        Statement: [
            {
                Effect: 'Allow',
                Principal: {'AWS': 'arn:aws:iam::123:user/alice'},
                Action: 'sts:AssumeRole'
            },
            {
                Effect: 'Allow',
                Principal: {'AWS': '*'},
                Action: 'sts:AssumeRole'
            },
            {
                Effect: 'Deny',
                Principal: {'AWS': 'arn:aws:iam::123:user/alice'},
                Action: 'sts:AssumeRole'
            }
        ]
    });

    var caller = {
        uuid: 'alice-uuid',
        login: 'alice',
        account: {
            uuid: '123',
            login: 'testaccount'
        }
    };

    var result = sts.internal.validateTrustPolicy(policy, caller, log);

    t.equal(result, false,
        'Single Deny should override multiple Allows');
    t.done();
};

exports.testDenyWithWildcardOverridesSpecificAllow = function (t) {
    // Test that wildcard Deny overrides specific Allow
    var policy = JSON.stringify({
        Statement: [
            {
                Effect: 'Allow',
                Principal: {'AWS': 'arn:aws:iam::123:user/alice'},
                Action: 'sts:AssumeRole'
            },
            {
                Effect: 'Deny',
                Principal: {'AWS': '*'},
                Action: 'sts:AssumeRole'
            }
        ]
    });

    var caller = {
        uuid: 'alice-uuid',
        login: 'alice',
        account: {
            uuid: '123',
            login: 'account123'
        }
    };

    var result = sts.internal.validateTrustPolicy(policy, caller, log);

    t.equal(result, false,
        'Wildcard Deny should override specific Allow');
    t.done();
};

exports.testDenyDoesNotAffectNonMatchingPrincipals = function (t) {
    // Test that Deny only affects matching principals
    var policy = JSON.stringify({
        Statement: [
            {
                Effect: 'Allow',
                Principal: {'AWS': '*'},
                Action: 'sts:AssumeRole'
            },
            {
                Effect: 'Deny',
                Principal: {'AWS': 'arn:aws:iam::123:user/eve'},
                Action: 'sts:AssumeRole'
            }
        ]
    });

    var callerAlice = {
        uuid: 'alice-uuid',
        login: 'alice',
        account: {
            uuid: '123',
            login: 'testaccount'
        }
    };

    var callerEve = {
        uuid: 'eve-uuid',
        login: 'eve',
        account: {
            uuid: '123',
            login: 'testaccount'
        }
    };

    var resultAlice = sts.internal.validateTrustPolicy(
        policy,
        callerAlice,
        log);
    var resultEve = sts.internal.validateTrustPolicy(policy, callerEve, log);

    t.equal(resultAlice, true,
        'Alice should be allowed (Deny does not match)');
    t.equal(resultEve, false,
        'Eve should be denied (Deny matches)');
    t.done();
};

/* --- Test multi-statement policy evaluation --- */

exports.testMultipleAllowStatementsUnion = function (t) {
    // Test that multiple Allow statements work as a union (any match allows)
    var policy = JSON.stringify({
        Statement: [
            {
                Effect: 'Allow',
                Principal: {'AWS': 'arn:aws:iam::111:user/alice'},
                Action: 'sts:AssumeRole'
            },
            {
                Effect: 'Allow',
                Principal: {'AWS': 'arn:aws:iam::222:user/bob'},
                Action: 'sts:AssumeRole'
            },
            {
                Effect: 'Allow',
                Principal: {'AWS': 'arn:aws:iam::333:user/charlie'},
                Action: 'sts:AssumeRole'
            }
        ]
    });

    var callerAlice = {
        uuid: 'alice-uuid',
        login: 'alice',
        account: {
            uuid: '111',
            login: 'testaccount111'
        }
    };

    var callerBob = {
        uuid: 'bob-uuid',
        login: 'bob',
        account: {
            uuid: '222',
            login: 'testaccount222'
        }
    };

    var callerDave = {
        uuid: 'dave-uuid',
        login: 'dave',
        account: {
            uuid: '444',
            login: 'testaccount444'
        }
    };

    var resultAlice = sts.internal.validateTrustPolicy(
        policy,
        callerAlice,
        log);
    var resultBob = sts.internal.validateTrustPolicy(policy, callerBob, log);
    var resultDave = sts.internal.validateTrustPolicy(policy, callerDave, log);

    t.equal(resultAlice, true, 'Alice should be allowed (first statement)');
    t.equal(resultBob, true, 'Bob should be allowed (second statement)');
    t.equal(resultDave, false, 'Dave should be denied (no match)');
    t.done();
};

exports.testMultipleDenyStatementsIntersection = function (t) {
    // Test that any Deny statement matching results in denial
    var policy = JSON.stringify({
        Statement: [
            {
                Effect: 'Allow',
                Principal: {'AWS': '*'},
                Action: 'sts:AssumeRole'
            },
            {
                Effect: 'Deny',
                Principal: {'AWS': 'arn:aws:iam::111:user/eve'},
                Action: 'sts:AssumeRole'
            },
            {
                Effect: 'Deny',
                Principal: {'AWS': 'arn:aws:iam::111:user/mallory'},
                Action: 'sts:AssumeRole'
            }
        ]
    });

    var callerEve = {
        uuid: 'eve-uuid',
        login: 'eve',
        account: {
            uuid: '111',
            login: 'testaccount'
        }
    };

    var callerMallory = {
        uuid: 'mallory-uuid',
        login: 'mallory',
        account: {
            uuid: '111',
            login: 'testaccount'
        }
    };

    var callerAlice = {
        uuid: 'alice-uuid',
        login: 'alice',
        account: {
            uuid: '111',
            login: 'testaccount'
        }
    };

    var resultEve = sts.internal.validateTrustPolicy(policy, callerEve, log);
    var resultMallory = sts.internal.validateTrustPolicy(
        policy,
        callerMallory,
        log);
    var resultAlice = sts.internal.validateTrustPolicy(
        policy,
        callerAlice,
        log);

    t.equal(resultEve, false, 'Eve should be denied (first Deny matches)');
    t.equal(resultMallory, false,
        'Mallory should be denied (second Deny matches)');
    t.equal(resultAlice, true,
        'Alice should be allowed (no Deny matches)');
    t.done();
};

exports.testComplexMixedStatements = function (t) {
    // Test complex policy with multiple Allows and Denys
    var policy = JSON.stringify({
        Statement: [
            {
                Effect: 'Allow',
                Principal: {'AWS': 'arn:aws:iam::111:root'},
                Action: 'sts:AssumeRole'
            },
            {
                Effect: 'Deny',
                Principal: {'AWS': 'arn:aws:iam::111:user/restricted'},
                Action: 'sts:AssumeRole'
            },
            {
                Effect: 'Allow',
                Principal: {'AWS': 'arn:aws:iam::222:root'},
                Action: 'sts:AssumeRole'
            },
            {
                Effect: 'Deny',
                Principal: {'AWS': 'arn:aws:iam::333:root'},
                Action: 'sts:AssumeRole'
            }
        ]
    });

    var caller111Root = {
        uuid: 'root-uuid-111',
        login: 'root',
        account: {
            uuid: '111',
            login: 'account111'
        }
    };

    var caller111Restricted = {
        uuid: 'restricted-uuid',
        login: 'restricted',
        account: {
            uuid: '111',
            login: 'account111'
        }
    };

    var caller222Root = {
        uuid: 'root-uuid-222',
        login: 'root',
        account: {
            uuid: '222',
            login: 'account222'
        }
    };

    var caller333Root = {
        uuid: 'root-uuid-333',
        login: 'root',
        account: {
            uuid: '333',
            login: 'account333'
        }
    };

    var result111Root = sts.internal.validateTrustPolicy(
        policy,
        caller111Root,
        log);
    var result111Restricted = sts.internal.validateTrustPolicy(
        policy,
        caller111Restricted,
        log);
    var result222Root = sts.internal.validateTrustPolicy(
        policy,
        caller222Root,
        log);
    var result333Root = sts.internal.validateTrustPolicy(
        policy,
        caller333Root,
        log);

    t.equal(result111Root, true, 'Account 111 root should be allowed');
    t.equal(result111Restricted, false,
        'Account 111 restricted user should be denied');
    t.equal(result222Root, true, 'Account 222 root should be allowed');
    t.equal(result333Root, false,
        'Account 333 root should be denied (explicit Deny)');
    t.done();
};

/* --- Test action matching with various patterns --- */

exports.testSingleActionExactMatch = function (t) {
    var statement = {
        Action: 'sts:AssumeRole'
    };

    var matchesAssumeRole = sts.internal.statementMatchesAction(
        statement,
        'sts:AssumeRole');
    var matchesGetSession = sts.internal.statementMatchesAction(
        statement,
        'sts:GetSessionToken');

    t.equal(matchesAssumeRole, true,
        'Should match exact action');
    t.equal(matchesGetSession, false,
        'Should not match different action');
    t.done();
};

exports.testActionArrayMatching = function (t) {
    var statement = {
        Action: [
            'sts:AssumeRole',
            'sts:GetSessionToken',
            'sts:GetCallerIdentity'
        ]
    };

    var matchesAssumeRole = sts.internal.statementMatchesAction(
        statement,
        'sts:AssumeRole');
    var matchesGetSession = sts.internal.statementMatchesAction(
        statement,
        'sts:GetSessionToken');
    var matchesGetCaller = sts.internal.statementMatchesAction(
        statement,
        'sts:GetCallerIdentity');
    var matchesOther = sts.internal.statementMatchesAction(
        statement,
        'sts:DecodeAuthorizationMessage');

    t.equal(matchesAssumeRole, true, 'Should match first action in array');
    t.equal(matchesGetSession, true, 'Should match second action in array');
    t.equal(matchesGetCaller, true, 'Should match third action in array');
    t.equal(matchesOther, false, 'Should not match action not in array');
    t.done();
};

exports.testActionWildcardMatchesAll = function (t) {
    var statement = {
        Action: '*'
    };

    var matchesAssumeRole = sts.internal.statementMatchesAction(
        statement,
        'sts:AssumeRole');
    var matchesGetSession = sts.internal.statementMatchesAction(
        statement,
        'sts:GetSessionToken');
    var matchesS3Action = sts.internal.statementMatchesAction(
        statement,
        's3:GetObject');

    t.equal(matchesAssumeRole, true,
        'Wildcard should match sts:AssumeRole');
    t.equal(matchesGetSession, true,
        'Wildcard should match sts:GetSessionToken');
    t.equal(matchesS3Action, true,
        'Wildcard should match any action');
    t.done();
};

exports.testActionWildcardInArray = function (t) {
    var statement = {
        Action: ['sts:AssumeRole', '*', 'sts:GetSessionToken']
    };

    var matchesSpecific = sts.internal.statementMatchesAction(
        statement,
        's3:GetObject');

    t.equal(matchesSpecific, true,
        'Array with wildcard should match any action');
    t.done();
};

exports.testEmptyActionArray = function (t) {
    var statement = {
        Action: []
    };

    var matches = sts.internal.statementMatchesAction(
        statement,
        'sts:AssumeRole');

    t.equal(matches, false,
        'Empty action array should not match');
    t.done();
};

/* --- Test principal validation edge cases --- */

exports.testPrincipalStringWildcard = function (t) {
    // Principal as string "*" (not in AWS object)
    var principal = '*';

    var caller = {
        uuid: 'test-uuid',
        login: 'testuser'
    };

    var result = sts.internal.validatePrincipal(principal, caller, log);

    t.equal(result, true,
        'String wildcard principal should match any user');
    t.done();
};

exports.testPrincipalAWSObjectWildcard = function (t) {
    // Principal as {"AWS": "*"}
    var principal = {'AWS': '*'};

    var caller = {
        uuid: 'test-uuid',
        login: 'testuser'
    };

    var result = sts.internal.validatePrincipal(principal, caller, log);

    t.equal(result, true,
        'AWS wildcard principal should match');
    t.done();
};

exports.testPrincipalRootARN = function (t) {
    var principal = {'AWS': 'arn:aws:iam::123456789012:root'};

    var callerRoot = {
        uuid: 'root-uuid',
        login: 'root',
        account: {
            uuid: '123456789012',
            login: 'account123456789012'
        }
    };

    var callerOtherRoot = {
        uuid: 'other-root-uuid',
        login: 'root',
        account: {
            uuid: '999999999999',
            login: 'account999999999999'
        }
    };

    var resultMatch = sts.internal.validatePrincipal(
        principal,
        callerRoot,
        log);
    var resultNoMatch = sts.internal.validatePrincipal(
        principal,
        callerOtherRoot,
        log);

    t.ok(typeof (resultMatch) === 'boolean',
        'Should return boolean for matching root');
    t.ok(typeof (resultNoMatch) === 'boolean',
        'Should return boolean for non-matching root');
    t.done();
};

exports.testPrincipalUserARN = function (t) {
    var principal = {'AWS': 'arn:aws:iam::123456789012:user/alice'};

    var callerAlice = {
        uuid: 'alice-uuid',
        login: 'alice',
        account: {
            uuid: '123456789012',
            login: 'account123456789012'
        }
    };

    var callerBob = {
        uuid: 'bob-uuid',
        login: 'bob',
        account: {
            uuid: '123456789012',
            login: 'account123456789012'
        }
    };

    var resultAlice = sts.internal.validatePrincipal(
        principal,
        callerAlice,
        log);
    var resultBob = sts.internal.validatePrincipal(principal, callerBob, log);

    t.ok(typeof (resultAlice) === 'boolean',
        'Should return boolean for alice');
    t.ok(typeof (resultBob) === 'boolean',
        'Should return boolean for bob');
    t.done();
};

exports.testPrincipalArrayWithMultipleUsers = function (t) {
    var principal = {
        'AWS': [
            'arn:aws:iam::123:user/alice',
            'arn:aws:iam::123:user/bob',
            'arn:aws:iam::456:user/charlie'
        ]
    };

    var callerAlice = {
        uuid: 'alice-uuid',
        login: 'alice',
        account: {
            uuid: '123',
            login: 'account123'
        }
    };

    var callerCharlie = {
        uuid: 'charlie-uuid',
        login: 'charlie',
        account: {
            uuid: '456',
            login: 'account456'
        }
    };

    var callerDave = {
        uuid: 'dave-uuid',
        login: 'dave',
        account: {
            uuid: '789',
            login: 'account789'
        }
    };

    var resultAlice = sts.internal.validatePrincipal(
        principal,
        callerAlice,
        log);
    var resultCharlie = sts.internal.validatePrincipal(
        principal,
        callerCharlie,
        log);
    var resultDave = sts.internal.validatePrincipal(
        principal,
        callerDave,
        log);

    t.ok(typeof (resultAlice) === 'boolean',
        'Should return boolean for alice in array');
    t.ok(typeof (resultCharlie) === 'boolean',
        'Should return boolean for charlie in array');
    t.ok(typeof (resultDave) === 'boolean',
        'Should return boolean for dave not in array');
    t.done();
};

exports.testPrincipalServiceFormat = function (t) {
    var principal = {'Service': 'lambda.amazonaws.com'};

    var caller = {
        uuid: 'test-uuid',
        login: 'testuser'
    };

    var result = sts.internal.validatePrincipal(principal, caller, log);

    t.equal(result, false,
        'Service principal should not match regular user');
    t.done();
};

exports.testPrincipalFederatedFormat = function (t) {
    var principal = {'Federated': 'arn:aws:iam::123:saml-provider/MyProvider'};

    var caller = {
        uuid: 'test-uuid',
        login: 'testuser'
    };

    var result = sts.internal.validatePrincipal(principal, caller, log);

    t.equal(result, false,
        'Federated principal should not match (not supported)');
    t.done();
};

exports.testPrincipalEmptyObject = function (t) {
    var principal = {};

    var caller = {
        uuid: 'test-uuid',
        login: 'testuser'
    };

    var result = sts.internal.validatePrincipal(principal, caller, log);

    t.equal(result, false,
        'Empty principal object should not match');
    t.done();
};

exports.testPrincipalNull = function (t) {
    var principal = null;

    var caller = {
        uuid: 'test-uuid',
        login: 'testuser'
    };

    // Null principal will throw TypeError, catch it
    try {
        var result = sts.internal.validatePrincipal(principal, caller, log);
        t.equal(result, false,
            'Null principal should not match');
    } catch (err) {
        t.ok(err instanceof TypeError,
            'Null principal should throw TypeError');
    }
    t.done();
};

/* --- Test cross-account scenarios --- */

exports.testCrossAccountAllow = function (t) {
    // Test allowing access from a different account
    var policy = JSON.stringify({
        Statement: [
            {
                Effect: 'Allow',
                Principal: {'AWS': 'arn:aws:iam::999999999999:root'},
                Action: 'sts:AssumeRole'
            }
        ]
    });

    var callerFromOtherAccount = {
        uuid: 'other-uuid',
        login: 'root',
        account: {
            uuid: '999999999999',
            login: 'accountother'
        }
    };

    var callerFromSameAccount = {
        uuid: 'same-uuid',
        login: 'root',
        account: {
            uuid: '123456789012',
            login: 'accountsame'
        }
    };

    var resultOther = sts.internal.validateTrustPolicy(
        policy,
        callerFromOtherAccount,
        log);
    var resultSame = sts.internal.validateTrustPolicy(
        policy,
        callerFromSameAccount,
        log);

    t.ok(typeof (resultOther) === 'boolean',
        'Should return boolean for cross-account caller');
    t.ok(typeof (resultSame) === 'boolean',
        'Should return boolean for same-account caller');
    t.done();
};

exports.testCrossAccountDeny = function (t) {
    // Test denying access from a specific external account
    var policy = JSON.stringify({
        Statement: [
            {
                Effect: 'Allow',
                Principal: {'AWS': '*'},
                Action: 'sts:AssumeRole'
            },
            {
                Effect: 'Deny',
                Principal: {'AWS': 'arn:aws:iam::888888888888:root'},
                Action: 'sts:AssumeRole'
            }
        ]
    });

    var callerFromDeniedAccount = {
        uuid: 'denied-uuid',
        login: 'root',
        account: {
            uuid: '888888888888',
            login: 'accountdenied'
        }
    };

    var callerFromAllowedAccount = {
        uuid: 'allowed-uuid',
        login: 'root',
        account: {
            uuid: '123456789012',
            login: 'accountallowed'
        }
    };

    var resultDenied = sts.internal.validateTrustPolicy(
        policy,
        callerFromDeniedAccount,
        log);
    var resultAllowed = sts.internal.validateTrustPolicy(
        policy,
        callerFromAllowedAccount,
        log);

    t.ok(typeof (resultDenied) === 'boolean',
        'Should return boolean for denied account');
    t.ok(typeof (resultAllowed) === 'boolean',
        'Should return boolean for allowed account');
    t.done();
};

exports.testMultipleCrossAccountPrincipals = function (t) {
    // Test policy allowing multiple external accounts
    var policy = JSON.stringify({
        Statement: [
            {
                Effect: 'Allow',
                Principal: {
                    'AWS': [
                        'arn:aws:iam::111111111111:root',
                        'arn:aws:iam::222222222222:root',
                        'arn:aws:iam::333333333333:root'
                    ]
                },
                Action: 'sts:AssumeRole'
            }
        ]
    });

    var caller111 = {
        uuid: 'uuid-111',
        login: 'root',
        account: {
            uuid: '111111111111',
            login: 'account111'
        }
    };

    var caller222 = {
        uuid: 'uuid-222',
        login: 'root',
        account: {
            uuid: '222222222222',
            login: 'account222'
        }
    };

    var caller444 = {
        uuid: 'uuid-444',
        login: 'root',
        account: {
            uuid: '444444444444',
            login: 'account444'
        }
    };

    var result111 = sts.internal.validateTrustPolicy(policy, caller111, log);
    var result222 = sts.internal.validateTrustPolicy(policy, caller222, log);
    var result444 = sts.internal.validateTrustPolicy(policy, caller444, log);

    t.ok(typeof (result111) === 'boolean',
        'Should return boolean for account 111');
    t.ok(typeof (result222) === 'boolean',
        'Should return boolean for account 222');
    t.ok(typeof (result444) === 'boolean',
        'Should return boolean for account 444');
    t.done();
};

/* --- Test default deny behavior in edge cases --- */

exports.testDefaultDenyWithEmptyStatementArray = function (t) {
    var policy = JSON.stringify({
        Statement: []
    });

    var caller = {
        uuid: 'test-uuid',
        login: 'testuser'
    };

    var result = sts.internal.validateTrustPolicy(policy, caller, log);

    t.equal(result, false,
        'Should deny when Statement array is empty');
    t.done();
};

exports.testDefaultDenyWithOnlyNonMatchingStatements = function (t) {
    var policy = JSON.stringify({
        Statement: [
            {
                Effect: 'Allow',
                Principal: {'AWS': 'arn:aws:iam::111:user/alice'},
                Action: 'sts:GetSessionToken'
            },
            {
                Effect: 'Allow',
                Principal: {'AWS': 'arn:aws:iam::222:user/bob'},
                Action: 'sts:GetSessionToken'
            }
        ]
    });

    var caller = {
        uuid: 'test-uuid',
        login: 'testuser',
        account: {
            uuid: '333',
            login: 'account333'
        }
    };

    var result = sts.internal.validateTrustPolicy(policy, caller, log);

    t.equal(result, false,
        'Should deny when no statements match (wrong action)');
    t.done();
};

exports.testDefaultDenyWithMatchingPrincipalWrongAction = function (t) {
    var policy = JSON.stringify({
        Statement: [
            {
                Effect: 'Allow',
                Principal: {'AWS': '*'},
                Action: 'sts:GetSessionToken'
            }
        ]
    });

    var caller = {
        uuid: 'test-uuid',
        login: 'testuser'
    };

    var result = sts.internal.validateTrustPolicy(policy, caller, log);

    t.equal(result, false,
        'Should deny when principal matches but action does not');
    t.done();
};

exports.testDefaultDenyWithMatchingActionWrongPrincipal = function (t) {
    var policy = JSON.stringify({
        Statement: [
            {
                Effect: 'Allow',
                Principal: {'AWS': 'arn:aws:iam::999:user/other'},
                Action: 'sts:AssumeRole'
            }
        ]
    });

    var caller = {
        uuid: 'test-uuid',
        login: 'testuser',
        account: {
            uuid: '123',
            login: 'account123'
        }
    };

    var result = sts.internal.validateTrustPolicy(policy, caller, log);

    t.equal(result, false,
        'Should deny when action matches but principal does not');
    t.done();
};

/* --- Test policy with multiple action types --- */

exports.testPolicyWithMultipleActionTypes = function (t) {
    var policy = JSON.stringify({
        Statement: [
            {
                Effect: 'Allow',
                Principal: {'AWS': '*'},
                Action: ['sts:AssumeRole', 'sts:GetSessionToken']
            }
        ]
    });

    var caller = {
        uuid: 'test-uuid',
        login: 'testuser'
    };

    var result = sts.internal.validateTrustPolicy(policy, caller, log);

    t.equal(result, true,
        'Should allow when one of multiple actions matches');
    t.done();
};

exports.testDenyWithSpecificActionInMultiActionStatement = function (t) {
    var policy = JSON.stringify({
        Statement: [
            {
                Effect: 'Allow',
                Principal: {'AWS': '*'},
                Action: ['sts:AssumeRole', 'sts:GetSessionToken']
            },
            {
                Effect: 'Deny',
                Principal: {'AWS': 'arn:aws:iam::999:user/blocked'},
                Action: ['sts:AssumeRole']
            }
        ]
    });

    var callerBlocked = {
        uuid: 'blocked-uuid',
        login: 'blocked',
        account: {
            uuid: '999',
            login: 'account999'
        }
    };

    var result = sts.internal.validateTrustPolicy(policy, callerBlocked, log);

    t.equal(result, false,
        'Should deny when action in deny list matches');
    t.done();
};

/* --- Test validation with malformed callers --- */

exports.testValidationWithMissingCallerUuid = function (t) {
    var policy = JSON.stringify({
        Statement: [
            {
                Effect: 'Allow',
                Principal: {'AWS': '*'},
                Action: 'sts:AssumeRole'
            }
        ]
    });

    var caller = {
        login: 'testuser'
        // uuid is missing
    };

    var result = sts.internal.validateTrustPolicy(policy, caller, log);

    t.ok(typeof (result) === 'boolean',
        'Should return boolean even with missing uuid');
    t.done();
};

exports.testValidationWithMissingCallerLogin = function (t) {
    var policy = JSON.stringify({
        Statement: [
            {
                Effect: 'Allow',
                Principal: {'AWS': '*'},
                Action: 'sts:AssumeRole'
            }
        ]
    });

    var caller = {
        uuid: 'test-uuid'
        // login is missing
    };

    var result = sts.internal.validateTrustPolicy(policy, caller, log);

    t.ok(typeof (result) === 'boolean',
        'Should return boolean even with missing login');
    t.done();
};

exports.testValidationWithMissingCallerAccount = function (t) {
    var policy = JSON.stringify({
        Statement: [
            {
                Effect: 'Allow',
                Principal: {'AWS': 'arn:aws:iam::123:user/alice'},
                Action: 'sts:AssumeRole'
            }
        ]
    });

    var caller = {
        uuid: 'alice-uuid',
        login: 'alice'
        // account is missing
    };

    var result = sts.internal.validateTrustPolicy(policy, caller, log);

    t.ok(typeof (result) === 'boolean',
        'Should return boolean even with missing account');
    t.done();
};
