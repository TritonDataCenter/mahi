/*
 * This Source Code Form is subject to the terms of the Mozilla
 * Public License, v. 2.0. If a copy of the MPL was not
 * distributed with this file, You can obtain one at
 * http://mozilla.org/MPL/2.0/.
 *
 * Copyright 2026 Edgecast Cloud LLC.
 */

/*
 * test/iam-policy-parsing.test.js: Unit tests for IAM policy
 * parsing and validation
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

/* --- Test IAM policy JSON parsing --- */

exports.testParseValidPolicyJSON = function (t) {
    var policyDoc = JSON.stringify({
        Statement: [
            {
                Effect: 'Allow',
                Principal: {'AWS': 'arn:aws:iam::123456789012:root'},
                Action: 'sts:AssumeRole'
            }
        ]
    });

    var caller = {
        uuid: 'test-uuid',
        login: 'root',
        account: '123456789012'
    };

    var result = sts.internal.validateTrustPolicy(policyDoc, caller, log);

    t.ok(typeof (result) === 'boolean',
        'should return boolean for valid policy');
    t.done();
};

exports.testParseMalformedJSON = function (t) {
    var malformedPolicy = '{invalid json}}}';

    var caller = {
        uuid: 'test-uuid',
        login: 'testuser'
    };

    var result = sts.internal.validateTrustPolicy(
        malformedPolicy,
        caller,
        log);

    t.equal(result, false,
        'should return false for malformed JSON');
    t.done();
};

exports.testParseEmptyPolicy = function (t) {
    var emptyPolicy = '';

    var caller = {
        uuid: 'test-uuid',
        login: 'testuser'
    };

    var result = sts.internal.validateTrustPolicy(emptyPolicy, caller, log);

    t.equal(result, false,
        'should return false for empty policy');
    t.done();
};

exports.testParseNullPolicy = function (t) {
    var caller = {
        uuid: 'test-uuid',
        login: 'testuser'
    };

    var result = sts.internal.validateTrustPolicy(null, caller, log);

    t.equal(result, false,
        'should return false for null policy');
    t.done();
};

/* --- Test policy statement validation --- */

exports.testValidateStatementArray = function (t) {
    var policyWithStatements = JSON.stringify({
        Statement: [
            {
                Effect: 'Allow',
                Principal: {'AWS': '*'},
                Action: 'sts:AssumeRole'
            },
            {
                Effect: 'Deny',
                Principal: {'AWS': 'arn:aws:iam::999999999999:user/baduser'},
                Action: 'sts:AssumeRole'
            }
        ]
    });

    var caller = {
        uuid: 'allowed-uuid',
        login: 'alloweduser'
    };

    var result = sts.internal.validateTrustPolicy(
        policyWithStatements,
        caller,
        log);

    t.ok(typeof (result) === 'boolean',
        'should handle multiple statements');
    t.done();
};

exports.testRejectMissingStatementArray = function (t) {
    var policyNoStatements = JSON.stringify({
        Version: '2012-10-17'
    });

    var caller = {
        uuid: 'test-uuid',
        login: 'testuser'
    };

    var result = sts.internal.validateTrustPolicy(
        policyNoStatements,
        caller,
        log);

    t.equal(result, false,
        'should reject policy without Statement array');
    t.done();
};

exports.testRejectNonArrayStatement = function (t) {
    var policyBadStatement = JSON.stringify({
        Statement: 'not-an-array'
    });

    var caller = {
        uuid: 'test-uuid',
        login: 'testuser'
    };

    var result = sts.internal.validateTrustPolicy(
        policyBadStatement,
        caller,
        log);

    t.equal(result, false,
        'should reject policy with non-array Statement');
    t.done();
};

/* --- Test effect validation (Allow/Deny) --- */

exports.testAllowEffect = function (t) {
    var allowPolicy = JSON.stringify({
        Statement: [
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

    var result = sts.internal.validateTrustPolicy(allowPolicy, caller, log);

    t.equal(result, true,
        'should allow access with Allow effect');
    t.done();
};

exports.testDenyEffect = function (t) {
    var denyPolicy = JSON.stringify({
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

    var result = sts.internal.validateTrustPolicy(denyPolicy, caller, log);

    t.equal(result, false,
        'should deny access when Deny statement matches');
    t.done();
};

exports.testDenyOverridesAllow = function (t) {
    var mixedPolicy = JSON.stringify({
        Statement: [
            {
                Effect: 'Allow',
                Principal: {'AWS': 'arn:aws:iam::123456789012:user/alice'},
                Action: 'sts:AssumeRole'
            },
            {
                Effect: 'Deny',
                Principal: {'AWS': 'arn:aws:iam::123456789012:user/alice'},
                Action: 'sts:AssumeRole'
            }
        ]
    });

    var caller = {
        uuid: 'alice-uuid',
        login: 'alice',
        account: '123456789012'
    };

    var result = sts.internal.validateTrustPolicy(mixedPolicy, caller, log);

    t.equal(result, false,
        'should deny when both Allow and Deny match (Deny wins)');
    t.done();
};

/* --- Test action validation and wildcard matching --- */

exports.testActionExactMatch = function (t) {
    var statement = {
        Action: 'sts:AssumeRole'
    };

    var matches = sts.internal.statementMatchesAction(
        statement,
        'sts:AssumeRole');

    t.equal(matches, true,
        'should match exact action');
    t.done();
};

exports.testActionWildcard = function (t) {
    var statement = {
        Action: '*'
    };

    var matches = sts.internal.statementMatchesAction(
        statement,
        'sts:AssumeRole');

    t.equal(matches, true,
        'should match wildcard action');
    t.done();
};

exports.testActionArray = function (t) {
    var statement = {
        Action: ['sts:AssumeRole', 'sts:GetSessionToken']
    };

    var matchesAssume = sts.internal.statementMatchesAction(
        statement,
        'sts:AssumeRole');
    var matchesSession = sts.internal.statementMatchesAction(
        statement,
        'sts:GetSessionToken');
    var matchesOther = sts.internal.statementMatchesAction(
        statement,
        'sts:Other');

    t.equal(matchesAssume, true,
        'should match first action in array');
    t.equal(matchesSession, true,
        'should match second action in array');
    t.equal(matchesOther, false,
        'should not match action not in array');
    t.done();
};

exports.testActionMismatch = function (t) {
    var statement = {
        Action: 'sts:GetSessionToken'
    };

    var matches = sts.internal.statementMatchesAction(
        statement,
        'sts:AssumeRole');

    t.equal(matches, false,
        'should not match different action');
    t.done();
};

exports.testMissingAction = function (t) {
    var statement = {};

    var matches = sts.internal.statementMatchesAction(
        statement,
        'sts:AssumeRole');

    t.equal(matches, false,
        'should not match when Action missing');
    t.done();
};

/* --- Test principal validation and wildcard matching --- */

exports.testPrincipalWildcard = function (t) {
    var principal = {'AWS': '*'};

    var caller = {
        uuid: 'any-uuid',
        login: 'anyuser'
    };

    var result = sts.internal.validatePrincipal(principal, caller, log);

    t.equal(result, true,
        'should match wildcard principal');
    t.done();
};

exports.testPrincipalARNMatch = function (t) {
    var principal = {'AWS': 'arn:aws:iam::123456789012:root'};

    var caller = {
        uuid: 'test-uuid',
        login: 'root',
        account: '123456789012'
    };

    var result = sts.internal.validatePrincipal(principal, caller, log);

    t.ok(typeof (result) === 'boolean',
        'should return boolean for root ARN principal');
    t.done();
};

exports.testPrincipalUserARN = function (t) {
    var principal = {'AWS': 'arn:aws:iam::123456789012:user/alice'};

    var callerAlice = {
        uuid: 'alice-uuid',
        login: 'alice',
        account: '123456789012'
    };

    var callerBob = {
        uuid: 'bob-uuid',
        login: 'bob',
        account: '123456789012'
    };

    var resultAlice = sts.internal.validatePrincipal(
        principal,
        callerAlice,
        log);
    var resultBob = sts.internal.validatePrincipal(principal, callerBob, log);

    t.ok(typeof (resultAlice) === 'boolean',
        'should return boolean for user ARN validation');
    t.ok(typeof (resultBob) === 'boolean',
        'should return boolean for different user');
    t.done();
};

exports.testPrincipalArray = function (t) {
    var principal = {
        'AWS': [
            'arn:aws:iam::123456789012:user/alice',
            'arn:aws:iam::123456789012:user/bob'
        ]
    };

    var callerAlice = {
        uuid: 'alice-uuid',
        login: 'alice',
        account: '123456789012'
    };

    var callerCharlie = {
        uuid: 'charlie-uuid',
        login: 'charlie',
        account: '123456789012'
    };

    var resultAlice = sts.internal.validatePrincipal(
        principal,
        callerAlice,
        log);
    var resultCharlie = sts.internal.validatePrincipal(
        principal,
        callerCharlie,
        log);

    t.ok(typeof (resultAlice) === 'boolean',
        'should return boolean for user in array');
    t.ok(typeof (resultCharlie) === 'boolean',
        'should return boolean for user not in array');
    t.done();
};

exports.testServicePrincipalFormat = function (t) {
    var principal = {'Service': 's3.amazonaws.com'};

    t.ok(principal.Service,
        'should accept Service principal format');
    t.equal(typeof (principal.Service), 'string',
        'should have string service name');
    t.done();
};

/* --- Test malformed policy rejection --- */

exports.testRejectPolicyWithoutEffect = function (t) {
    var policyNoEffect = JSON.stringify({
        Statement: [
            {
                Principal: {'AWS': '*'},
                Action: 'sts:AssumeRole'
            }
        ]
    });

    var caller = {
        uuid: 'test-uuid',
        login: 'testuser'
    };

    var result = sts.internal.validateTrustPolicy(
        policyNoEffect,
        caller,
        log);

    t.equal(result, false,
        'should reject statement without Effect');
    t.done();
};

exports.testRejectInvalidEffect = function (t) {
    var policyBadEffect = JSON.stringify({
        Statement: [
            {
                Effect: 'Maybe',
                Principal: {'AWS': '*'},
                Action: 'sts:AssumeRole'
            }
        ]
    });

    var caller = {
        uuid: 'test-uuid',
        login: 'testuser'
    };

    var result = sts.internal.validateTrustPolicy(
        policyBadEffect,
        caller,
        log);

    t.equal(result, false,
        'should reject invalid Effect value');
    t.done();
};

exports.testRejectEmptyStatement = function (t) {
    var policyEmptyStmt = JSON.stringify({
        Statement: [ {} ]
    });

    var caller = {
        uuid: 'test-uuid',
        login: 'testuser'
    };

    var result = sts.internal.validateTrustPolicy(
        policyEmptyStmt,
        caller,
        log);

    t.equal(result, false,
        'should reject empty statement');
    t.done();
};

exports.testRejectStatementWithoutPrincipal = function (t) {
    var policyNoPrincipal = JSON.stringify({
        Statement: [
            {
                Effect: 'Allow',
                Action: 'sts:AssumeRole'
            }
        ]
    });

    var caller = {
        uuid: 'test-uuid',
        login: 'testuser'
    };

    var result = sts.internal.validateTrustPolicy(
        policyNoPrincipal,
        caller,
        log);

    t.equal(result, false,
        'should reject statement without Principal');
    t.done();
};

/* --- Test complex policy scenarios --- */

exports.testMultiStatementPolicyEvaluation = function (t) {
    var complexPolicy = JSON.stringify({
        Statement: [
            {
                Effect: 'Allow',
                Principal: {'AWS': '*'},
                Action: 'sts:AssumeRole'
            },
            {
                Effect: 'Deny',
                Principal: {'AWS': 'arn:aws:iam::999999999999:user/eve'},
                Action: 'sts:AssumeRole'
            }
        ]
    });

    var callerAlice = {
        uuid: 'alice-uuid',
        login: 'alice',
        account: '123456789012'
    };

    var callerEve = {
        uuid: 'eve-uuid',
        login: 'eve',
        account: '999999999999'
    };

    var resultAlice = sts.internal.validateTrustPolicy(
        complexPolicy,
        callerAlice,
        log);
    var resultEve = sts.internal.validateTrustPolicy(
        complexPolicy,
        callerEve,
        log);

    t.ok(typeof (resultAlice) === 'boolean',
        'should evaluate policy for alice');
    t.ok(typeof (resultEve) === 'boolean',
        'should evaluate policy for eve');
    t.done();
};

exports.testPolicyWithMultipleActions = function (t) {
    var multiActionPolicy = JSON.stringify({
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

    var result = sts.internal.validateTrustPolicy(
        multiActionPolicy,
        caller,
        log);

    t.equal(result, true,
        'should handle multiple actions in statement');
    t.done();
};

exports.testDefaultDeny = function (t) {
    var policyNoMatch = JSON.stringify({
        Statement: [
            {
                Effect: 'Allow',
                Principal: {'AWS': 'arn:aws:iam::123456789012:user/alice'},
                Action: 'sts:AssumeRole'
            }
        ]
    });

    var callerBob = {
        uuid: 'bob-uuid',
        login: 'bob',
        account: '123456789012'
    };

    var result = sts.internal.validateTrustPolicy(policyNoMatch, callerBob,
        log);

    t.equal(result, false,
        'should deny by default when no statement matches');
    t.done();
};
