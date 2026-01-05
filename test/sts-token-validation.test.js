/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2026 Edgecast Cloud LLC.
 */

/**
 * test/sts-token-validation.test.js: Unit tests for STS token validation
 *
 * Tests JWT decoding, verification, expiration checking, signature validation,
 * format validation, and rejection of invalid tokens.
 */

var _nodeunit = require('nodeunit');
var jwt = require('jsonwebtoken');
var crypto = require('crypto');

// Import session token module for testing
var sessionTokenModule = require('../lib/server/session-token.js');

/* --- Test JWT decoding and verification --- */

exports.testJWTDecoding = function (t) {
    var now = Math.floor(Date.now() / 1000);
    var sessionData = {
        uuid: 'test-user-uuid-123',
        roleArn: 'arn:aws:iam::123456789012:role/TestRole',
        sessionName: 'test-session',
        expires: now + 3600
    };

    var secretKey = {
        key: crypto.randomBytes(32).toString('hex'),
        keyId: 'test-key-001'
    };

    var token = sessionTokenModule.generateSessionToken(
        sessionData,
        secretKey,
        { issuer: 'manta-mahi', audience: 'manta-s3' });

    // Decode without verification
    var decoded = sessionTokenModule.decodeSessionToken(token);
    t.ok(decoded, 'should decode token');
    t.equal(decoded.uuid, sessionData.uuid,
        'decoded UUID should match');
    t.equal(decoded.roleArn, sessionData.roleArn,
        'decoded roleArn should match');
    t.equal(decoded.sessionName, sessionData.sessionName,
        'decoded sessionName should match');
    t.equal(decoded.tokenType, 'sts-session',
        'should have correct token type');
    t.equal(decoded.tokenVersion, '1.1',
        'should have correct version');

    t.done();
};

exports.testJWTVerification = function (t) {
    var now = Math.floor(Date.now() / 1000);
    var sessionData = {
        uuid: 'test-user-uuid-456',
        roleArn: 'arn:aws:iam::123456789012:role/VerifyTest',
        sessionName: 'verify-session',
        expires: now + 3600
    };

    var secretKey = {
        key: crypto.randomBytes(32).toString('hex'),
        keyId: 'test-key-002'
    };

    var token = sessionTokenModule.generateSessionToken(
        sessionData,
        secretKey,
        { issuer: 'manta-mahi', audience: 'manta-s3' });

    // Build secret config for verification
    var secretConfig = {
        secrets: {},
        gracePeriod: 86400
    };
    secretConfig.secrets[secretKey.keyId] = {
        key: secretKey.key,
        keyId: secretKey.keyId,
        isPrimary: true,
        addedAt: Date.now()
    };

    // Verify token with callback
    sessionTokenModule.verifySessionToken(
        token,
        secretConfig,
        { issuer: 'manta-mahi', audience: 'manta-s3' },
        function (err, verified) {
            t.ifError(err, 'should verify without error');
            t.ok(verified, 'should return verified data');
            t.equal(verified.uuid, sessionData.uuid,
                'verified UUID should match');
            t.equal(verified.roleArn, sessionData.roleArn,
                'verified roleArn should match');
            t.equal(verified.sessionName, sessionData.sessionName,
                'verified sessionName should match');
            t.done();
        });
};

/* --- Test token expiration checking --- */

exports.testExpiredTokenRejection = function (t) {
    var now = Math.floor(Date.now() / 1000);
    var sessionData = {
        uuid: 'test-user-uuid-expired',
        roleArn: 'arn:aws:iam::123456789012:role/ExpiredTest',
        sessionName: 'expired-session',
        expires: now - 3600  // Expired 1 hour ago
    };

    var secretKey = {
        key: crypto.randomBytes(32).toString('hex'),
        keyId: 'test-key-003'
    };

    // Generate token with past expiration
    // Note: generateSessionToken validates expiration, so we need to
    // bypass it by creating a JWT directly with past expiration
    var payload = {
        uuid: sessionData.uuid,
        roleArn: sessionData.roleArn,
        sessionName: sessionData.sessionName,
        tokenType: 'sts-session',
        tokenVersion: '1.1',
        keyId: secretKey.keyId,
        iss: 'manta-mahi',
        aud: 'manta-s3',
        iat: now - 7200,
        exp: now - 3600,  // Expired
        nbf: now - 7200
    };

    var expiredToken = jwt.sign(payload, secretKey.key,
        {algorithm: 'HS256'});

    var secretConfig = {
        secrets: {},
        gracePeriod: 86400
    };
    secretConfig.secrets[secretKey.keyId] = {
        key: secretKey.key,
        keyId: secretKey.keyId,
        isPrimary: true,
        addedAt: Date.now()
    };

    // Verify should fail with expired token
    sessionTokenModule.verifySessionToken(
        expiredToken,
        secretConfig,
        { issuer: 'manta-mahi', audience: 'manta-s3' },
        function (err, verified) {
            t.ok(err, 'should return error for expired token');
            t.ok(err.message.indexOf('expired') !== -1,
                'error should mention expiration');
            t.ok(!verified, 'should not return verified data');
            t.done();
        });
};

exports.testNotYetValidTokenRejection = function (t) {
    var now = Math.floor(Date.now() / 1000);
    var secretKey = {
        key: crypto.randomBytes(32).toString('hex'),
        keyId: 'test-key-004'
    };

    // Create token that's not valid yet (nbf in future)
    var payload = {
        uuid: 'test-user-uuid-future',
        roleArn: 'arn:aws:iam::123456789012:role/FutureTest',
        sessionName: 'future-session',
        tokenType: 'sts-session',
        tokenVersion: '1.1',
        keyId: secretKey.keyId,
        iss: 'manta-mahi',
        aud: 'manta-s3',
        iat: now,
        exp: now + 7200,
        nbf: now + 3600  // Not valid for another hour
    };

    var futureToken = jwt.sign(payload, secretKey.key,
        {algorithm: 'HS256'});

    var secretConfig = {
        secrets: {},
        gracePeriod: 86400
    };
    secretConfig.secrets[secretKey.keyId] = {
        key: secretKey.key,
        keyId: secretKey.keyId,
        isPrimary: true,
        addedAt: Date.now()
    };

    sessionTokenModule.verifySessionToken(
        futureToken,
        secretConfig,
        { issuer: 'manta-mahi', audience: 'manta-s3' },
        function (err, verified) {
            t.ok(err, 'should return error for not-yet-valid token');
            t.ok(err.message.indexOf('not yet valid') !== -1,
                'error should mention not yet valid');
            t.ok(!verified, 'should not return verified data');
            t.done();
        });
};

/* --- Test signature verification --- */

exports.testInvalidSignatureRejection = function (t) {
    var now = Math.floor(Date.now() / 1000);
    var sessionData = {
        uuid: 'test-user-uuid-sig',
        roleArn: 'arn:aws:iam::123456789012:role/SigTest',
        sessionName: 'sig-session',
        expires: now + 3600
    };

    var correctKey = {
        key: crypto.randomBytes(32).toString('hex'),
        keyId: 'test-key-005'
    };

    var wrongKey = {
        key: crypto.randomBytes(32).toString('hex'),
        keyId: 'test-key-wrong'
    };

    // Generate token with correct key
    var token = sessionTokenModule.generateSessionToken(
        sessionData,
        correctKey);

    // Try to verify with wrong key
    var secretConfig = {
        secrets: {},
        gracePeriod: 86400
    };
    secretConfig.secrets[wrongKey.keyId] = {
        key: wrongKey.key,
        keyId: wrongKey.keyId,
        isPrimary: true,
        addedAt: Date.now()
    };

    sessionTokenModule.verifySessionToken(
        token,
        secretConfig,
        {},
        function (err, verified) {
            t.ok(err, 'should return error for invalid signature');
            t.ok(!verified, 'should not return verified data');
            t.done();
        });
};

exports.testTamperedTokenRejection = function (t) {
    var now = Math.floor(Date.now() / 1000);
    var sessionData = {
        uuid: 'test-user-uuid-tamper',
        roleArn: 'arn:aws:iam::123456789012:role/TamperTest',
        sessionName: 'tamper-session',
        expires: now + 3600
    };

    var secretKey = {
        key: crypto.randomBytes(32).toString('hex'),
        keyId: 'test-key-006'
    };

    var token = sessionTokenModule.generateSessionToken(
        sessionData,
        secretKey);

    // Tamper with the token by modifying the payload (Node v0.10.48 compatible)
    var parts = token.split('.');
    var payload = JSON.parse(
        new Buffer(parts[1], 'base64').toString('utf8'));
    payload.uuid = 'tampered-uuid';
    var eqRegex = new RegExp('=', 'g');
    var plusRegex = new RegExp('\\+', 'g');
    var slashRegex = new RegExp('/', 'g');
    parts[1] = new Buffer(JSON.stringify(payload)).toString('base64')
        .replace(eqRegex, '').replace(plusRegex, '-')
        .replace(slashRegex, '_');
    var tamperedToken = parts.join('.');

    var secretConfig = {
        secrets: {},
        gracePeriod: 86400
    };
    secretConfig.secrets[secretKey.keyId] = {
        key: secretKey.key,
        keyId: secretKey.keyId,
        isPrimary: true,
        addedAt: Date.now()
    };

    sessionTokenModule.verifySessionToken(
        tamperedToken,
        secretConfig,
        {},
        function (err, verified) {
            t.ok(err, 'should return error for tampered token');
            t.ok(!verified, 'should not return verified data');
            t.done();
        });
};

/* --- Test token format validation --- */

exports.testMalformedTokenRejection = function (t) {
    var secretKey = {
        key: crypto.randomBytes(32).toString('hex'),
        keyId: 'test-key-007'
    };

    var secretConfig = {
        secrets: {},
        gracePeriod: 86400
    };
    secretConfig.secrets[secretKey.keyId] = {
        key: secretKey.key,
        keyId: secretKey.keyId,
        isPrimary: true,
        addedAt: Date.now()
    };

    // Test various malformed tokens
    var malformedTokens = [
        'not.a.valid.jwt.token',
        'only-one-part',
        'two.parts',
        '',
        'invalid-base64!@#$',
        'header.payload.'  // Missing signature
    ];

    var completed = 0;
    malformedTokens.forEach(function (malformedToken) {
        sessionTokenModule.verifySessionToken(
            malformedToken,
            secretConfig,
            {},
            function (err, verified) {
                t.ok(err,
                    'should return error for malformed token: ' +
                    malformedToken);
                t.ok(!verified, 'should not return verified data');
                completed++;
                if (completed === malformedTokens.length) {
                    t.done();
                }
            });
    });
};

exports.testInvalidJSONPayloadRejection = function (t) {
    // Create a JWT-like token with invalid JSON payload
    var eqRegex = new RegExp('=', 'g');
    var plusRegex = new RegExp('\\+', 'g');
    var slashRegex = new RegExp('/', 'g');
    var header = new Buffer(JSON.stringify({alg: 'HS256', typ: 'JWT'}))
        .toString('base64').replace(eqRegex, '').replace(plusRegex, '-')
        .replace(slashRegex, '_');

    var invalidPayload = new Buffer('not valid json {{{')
        .toString('base64').replace(eqRegex, '').replace(plusRegex, '-')
        .replace(slashRegex, '_');

    var signature = new Buffer('fake-signature').toString('base64')
        .replace(eqRegex, '').replace(plusRegex, '-')
        .replace(slashRegex, '_');

    var invalidToken = header + '.' + invalidPayload + '.' + signature;

    t.throws(function () {
        sessionTokenModule.decodeSessionToken(invalidToken);
    }, 'should throw error for invalid JSON payload');

    t.done();
};

/* --- Test unknown token version rejection --- */

exports.testUnknownVersionRejection = function (t) {
    var now = Math.floor(Date.now() / 1000);
    var secretKey = {
        key: crypto.randomBytes(32).toString('hex'),
        keyId: 'test-key-009'
    };

    // Create token with unsupported version
    var payload = {
        uuid: 'test-user-uuid-version',
        roleArn: 'arn:aws:iam::123456789012:role/VersionTest',
        sessionName: 'version-session',
        tokenType: 'sts-session',
        tokenVersion: '2.0',  // Unsupported version
        keyId: secretKey.keyId,
        iss: 'manta-mahi',
        aud: 'manta-s3',
        iat: now,
        exp: now + 3600,
        nbf: now
    };

    var unsupportedToken = jwt.sign(payload, secretKey.key,
        {algorithm: 'HS256'});

    var secretConfig = {
        secrets: {},
        gracePeriod: 86400
    };
    secretConfig.secrets[secretKey.keyId] = {
        key: secretKey.key,
        keyId: secretKey.keyId,
        isPrimary: true,
        addedAt: Date.now()
    };

    sessionTokenModule.verifySessionToken(
        unsupportedToken,
        secretConfig,
        {},
        function (err, verified) {
            t.ok(err, 'should return error for unsupported version');
            t.ok(err.message.indexOf('Unsupported token version') !==
                -1, 'error should mention unsupported version');
            t.ok(!verified, 'should not return verified data');
            t.done();
        });
};

exports.testInvalidTokenTypeRejection = function (t) {
    var now = Math.floor(Date.now() / 1000);
    var secretKey = {
        key: crypto.randomBytes(32).toString('hex'),
        keyId: 'test-key-010'
    };

    // Create token with wrong token type
    var payload = {
        uuid: 'test-user-uuid-type',
        roleArn: 'arn:aws:iam::123456789012:role/TypeTest',
        sessionName: 'type-session',
        tokenType: 'invalid-type',  // Wrong type
        tokenVersion: '1.1',
        keyId: secretKey.keyId,
        iss: 'manta-mahi',
        aud: 'manta-s3',
        iat: now,
        exp: now + 3600,
        nbf: now
    };

    var invalidTypeToken = jwt.sign(payload, secretKey.key,
        {algorithm: 'HS256'});

    var secretConfig = {
        secrets: {},
        gracePeriod: 86400
    };
    secretConfig.secrets[secretKey.keyId] = {
        key: secretKey.key,
        keyId: secretKey.keyId,
        isPrimary: true,
        addedAt: Date.now()
    };

    sessionTokenModule.verifySessionToken(
        invalidTypeToken,
        secretConfig,
        {},
        function (err, verified) {
            t.ok(err, 'should return error for invalid token type');
            t.ok(err.message.indexOf('Invalid token type') !== -1,
                'error should mention invalid token type');
            t.ok(!verified, 'should not return verified data');
            t.done();
        });
};

/* --- Test issuer/audience validation --- */

exports.testInvalidIssuerRejection = function (t) {
    var now = Math.floor(Date.now() / 1000);
    var sessionData = {
        uuid: 'test-user-uuid-issuer',
        roleArn: 'arn:aws:iam::123456789012:role/IssuerTest',
        sessionName: 'issuer-session',
        expires: now + 3600
    };

    var secretKey = {
        key: crypto.randomBytes(32).toString('hex'),
        keyId: 'test-key-011'
    };

    var token = sessionTokenModule.generateSessionToken(
        sessionData,
        secretKey,
        { issuer: 'manta-mahi', audience: 'manta-s3' });

    var secretConfig = {
        secrets: {},
        gracePeriod: 86400
    };
    secretConfig.secrets[secretKey.keyId] = {
        key: secretKey.key,
        keyId: secretKey.keyId,
        isPrimary: true,
        addedAt: Date.now()
    };

    // Verify with wrong issuer
    sessionTokenModule.verifySessionToken(
        token,
        secretConfig,
        { issuer: 'wrong-issuer', audience: 'manta-s3' },
        function (err, verified) {
            t.ok(err, 'should return error for invalid issuer');
            t.ok(err.message.indexOf('Invalid issuer') !== -1,
                'error should mention invalid issuer');
            t.ok(!verified, 'should not return verified data');
            t.done();
        });
};

exports.testInvalidAudienceRejection = function (t) {
    var now = Math.floor(Date.now() / 1000);
    var sessionData = {
        uuid: 'test-user-uuid-audience',
        roleArn: 'arn:aws:iam::123456789012:role/AudienceTest',
        sessionName: 'audience-session',
        expires: now + 3600
    };

    var secretKey = {
        key: crypto.randomBytes(32).toString('hex'),
        keyId: 'test-key-012'
    };

    var token = sessionTokenModule.generateSessionToken(
        sessionData,
        secretKey,
        { issuer: 'manta-mahi', audience: 'manta-s3' });

    var secretConfig = {
        secrets: {},
        gracePeriod: 86400
    };
    secretConfig.secrets[secretKey.keyId] = {
        key: secretKey.key,
        keyId: secretKey.keyId,
        isPrimary: true,
        addedAt: Date.now()
    };

    // Verify with wrong audience
    sessionTokenModule.verifySessionToken(
        token,
        secretConfig,
        { issuer: 'manta-mahi', audience: 'wrong-audience' },
        function (err, verified) {
            t.ok(err, 'should return error for invalid audience');
            t.ok(err.message.indexOf('Invalid audience') !== -1,
                'error should mention invalid audience');
            t.ok(!verified, 'should not return verified data');
            t.done();
        });
};

/* --- Test secret rotation and multi-secret validation --- */

exports.testMultipleSecretsValidation = function (t) {
    var now = Math.floor(Date.now() / 1000);
    var sessionData = {
        uuid: 'test-user-uuid-multi',
        roleArn: 'arn:aws:iam::123456789012:role/MultiSecretTest',
        sessionName: 'multi-secret-session',
        expires: now + 3600
    };

    var oldSecretKey = {
        key: crypto.randomBytes(32).toString('hex'),
        keyId: 'old-key-001'
    };

    var newSecretKey = {
        key: crypto.randomBytes(32).toString('hex'),
        keyId: 'new-key-001'
    };

    // Generate token with old key
    var token = sessionTokenModule.generateSessionToken(
        sessionData,
        oldSecretKey);

    // Build secret config with both old and new keys
    var secretConfig = {
        secrets: {},
        gracePeriod: 86400
    };
    secretConfig.secrets[oldSecretKey.keyId] = {
        key: oldSecretKey.key,
        keyId: oldSecretKey.keyId,
        isPrimary: false,
        addedAt: Date.now() - 3600000  // Added 1 hour ago
    };
    secretConfig.secrets[newSecretKey.keyId] = {
        key: newSecretKey.key,
        keyId: newSecretKey.keyId,
        isPrimary: true,
        addedAt: Date.now()
    };

    // Should verify with old key (still within grace period)
    sessionTokenModule.verifySessionToken(
        token,
        secretConfig,
        {},
        function (err, verified) {
            t.ifError(err,
                'should verify token with old key during grace period');
            t.ok(verified, 'should return verified data');
            t.equal(verified.uuid, sessionData.uuid,
                'verified UUID should match');
            t.done();
        });
};

exports.testExpiredSecretRejection = function (t) {
    var now = Math.floor(Date.now() / 1000);
    var sessionData = {
        uuid: 'test-user-uuid-expired-secret',
        roleArn: 'arn:aws:iam::123456789012:role/ExpiredSecretTest',
        sessionName: 'expired-secret-session',
        expires: now + 3600
    };

    var expiredSecretKey = {
        key: crypto.randomBytes(32).toString('hex'),
        keyId: 'expired-key-001'
    };

    var currentSecretKey = {
        key: crypto.randomBytes(32).toString('hex'),
        keyId: 'current-key-001'
    };

    var token = sessionTokenModule.generateSessionToken(
        sessionData,
        expiredSecretKey);

    // Build secret config with only current secret (expired secret not
    // included). In production, expired secrets outside grace period
    // are removed from the map
    var secretConfig = {
        secrets: {},
        gracePeriod: 86400  // 24 hours
    };
    secretConfig.secrets[currentSecretKey.keyId] = {
        key: currentSecretKey.key,
        keyId: currentSecretKey.keyId,
        isPrimary: true,
        addedAt: Date.now()
    };

    // Should fail because the signing key is no longer in the valid
    // secrets map
    sessionTokenModule.verifySessionToken(
        token,
        secretConfig,
        {},
        function (err, verified) {
            t.ok(err,
                'should return error for token signed with expired ' +
                'secret');
            t.ok(!verified, 'should not return verified data');
            t.done();
        });
};

/* --- Test token decoding edge cases --- */

exports.testDecodeTokenTooLarge = function (t) {
    // Create an oversized token payload (Node v0.10.48 compatible)
    var largeBuffer = new Buffer(100000);
    largeBuffer.fill('x');
    var largePayload = largeBuffer.toString('base64');
    var largeToken = 'header.' + largePayload + '.signature';

    t.throws(function () {
        sessionTokenModule.decodeSessionToken(largeToken);
    }, /Session token too large/, 'should reject oversized token');

    t.done();
};

exports.testDecodeTokenInvalidFormat = function (t) {
    t.throws(function () {
        sessionTokenModule.decodeSessionToken('invalid-token-format');
    }, /Invalid JWT format/, 'should reject invalid token format');

    t.done();
};