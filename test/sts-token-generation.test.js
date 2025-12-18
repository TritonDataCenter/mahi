/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2025 Edgecast Cloud LLC.
 */

/**
 * test/sts-token-generation.test.js: Unit tests for STS token generation
 *
 * Tests session token structure, JWT encoding, expiration calculation,
 * duration validation, access key generation, secret key generation,
 * and error conditions.
 */

var nodeunit = require('nodeunit');
var jwt = require('jsonwebtoken');
var crypto = require('crypto');
var accesskey = require('ufds/lib/accesskey');

// Import STS functions for testing
var sts = require('../lib/server/sts.js');
var sessionTokenModule = require('../lib/server/session-token.js');

// Access internal STS functions
var generateUUID = sts.internal.generateUUID;
var generateSessionTokenAccessKeyId = sts.internal.generateSessionTokenAccessKeyId;
var generateAssumeRoleAccessKeyId = sts.internal.generateAssumeRoleAccessKeyId;

/* --- Test session token structure and format --- */

exports.testSessionTokenJWTStructure = function (t) {
    var sessionData = {
        uuid: 'test-user-uuid-123',
        roleArn: 'arn:aws:iam::123456789012:role/TestRole',
        sessionName: 'test-session',
        expires: Math.floor(Date.now() / 1000) + 3600
    };

    var secretKey = {
        key: crypto.randomBytes(32).toString('hex'),
        keyId: 'test-key-001'
    };

    var token = sessionTokenModule.generateSessionToken(
        sessionData,
        secretKey,
        { issuer: 'manta-mahi', audience: 'manta-s3' }
    );

    t.ok(token, 'should generate a token');
    t.equal(typeof token, 'string', 'token should be a string');

    // JWT should have 3 parts separated by dots
    var parts = token.split('.');
    t.equal(parts.length, 3, 'JWT should have header.payload.signature format');

    // Decode and verify structure (without verification)
    var decoded = jwt.decode(token);
    t.ok(decoded, 'should decode JWT structure');
    t.equal(decoded.uuid, sessionData.uuid, 'should contain user UUID');
    t.equal(decoded.roleArn, sessionData.roleArn, 'should contain role ARN');
    t.equal(decoded.sessionName, sessionData.sessionName, 'should contain session name');
    t.equal(decoded.tokenType, 'sts-session', 'should have correct token type');
    t.equal(decoded.tokenVersion, '1.1', 'should have version 1.1');
    t.equal(decoded.keyId, 'test-key-001', 'should contain key ID');
    t.equal(decoded.iss, 'manta-mahi', 'should have correct issuer');
    t.equal(decoded.aud, 'manta-s3', 'should have correct audience');

    t.done();
};

exports.testSessionTokenJWTSignature = function (t) {
    var sessionData = {
        uuid: 'test-user-uuid-456',
        roleArn: 'arn:aws:iam::123456789012:role/SignatureTest',
        sessionName: 'signature-session',
        expires: Math.floor(Date.now() / 1000) + 3600
    };

    var secretKey = {
        key: crypto.randomBytes(32).toString('hex'),
        keyId: 'test-key-002'
    };

    var token = sessionTokenModule.generateSessionToken(
        sessionData,
        secretKey
    );

    // Verify the signature is valid (using callback for jsonwebtoken 1.x)
    jwt.verify(token, secretKey.key, function (err, verified) {
        t.ifError(err, 'JWT signature should verify with correct secret');
        t.ok(verified, 'should have verified payload');
        t.equal(verified.uuid, sessionData.uuid, 'verified payload should match');

        // Verify signature fails with wrong secret
        var wrongSecret = crypto.randomBytes(32).toString('hex');
        jwt.verify(token, wrongSecret, function (verifyErr, result) {
            t.ok(verifyErr, 'should fail verification with wrong secret');
            t.ok(!result, 'should not return payload with wrong secret');
            t.done();
        });
    });
};

/* --- Test JWT encoding and signing --- */

exports.testJWTEncodingAlgorithm = function (t) {
    var sessionData = {
        uuid: 'test-uuid-789',
        roleArn: 'arn:aws:iam::123456789012:role/AlgoTest',
        sessionName: 'algo-session',
        expires: Math.floor(Date.now() / 1000) + 3600
    };

    var secretKey = {
        key: crypto.randomBytes(32).toString('hex'),
        keyId: 'test-key-003'
    };

    var token = sessionTokenModule.generateSessionToken(
        sessionData,
        secretKey
    );

    // Decode header to verify algorithm
    var header = JSON.parse(
        Buffer.from(token.split('.')[0], 'base64').toString('utf8')
    );

    t.equal(header.alg, 'HS256', 'should use HMAC-SHA256 algorithm');
    t.equal(header.typ, 'JWT', 'should have JWT type');

    t.done();
};

exports.testJWTPayloadEncoding = function (t) {
    var sessionData = {
        uuid: 'test-uuid-abc',
        roleArn: 'arn:aws:iam::123456789012:role/PayloadTest',
        sessionName: 'payload-session',
        expires: Math.floor(Date.now() / 1000) + 7200
    };

    var secretKey = {
        key: crypto.randomBytes(32).toString('hex'),
        keyId: 'test-key-004'
    };

    var token = sessionTokenModule.generateSessionToken(
        sessionData,
        secretKey,
        { issuer: 'test-issuer', audience: 'test-audience' }
    );

    // Manually decode payload
    var payloadB64 = token.split('.')[1];
    payloadB64 += '==='.slice(0, (4 - payloadB64.length % 4) % 4);
    payloadB64 = payloadB64.replace(/-/g, '+').replace(/_/g, '/');
    var payload = JSON.parse(Buffer.from(payloadB64, 'base64').toString('utf8'));

    t.equal(payload.uuid, sessionData.uuid, 'payload should contain UUID');
    t.equal(payload.roleArn, sessionData.roleArn, 'payload should contain role ARN');
    t.equal(payload.sessionName, sessionData.sessionName, 'payload should contain session name');
    t.equal(payload.exp, sessionData.expires, 'payload should contain expiration');
    t.ok(payload.iat, 'payload should contain issued-at timestamp');
    t.ok(payload.nbf, 'payload should contain not-before timestamp');
    t.equal(payload.iss, 'test-issuer', 'payload should contain issuer');
    t.equal(payload.aud, 'test-audience', 'payload should contain audience');

    t.done();
};

/* --- Test token expiration calculation --- */

exports.testTokenExpirationCalculation = function (t) {
    var now = Math.floor(Date.now() / 1000);
    var durationSeconds = 3600;
    var expectedExpiration = now + durationSeconds;

    var sessionData = {
        uuid: 'test-uuid-def',
        roleArn: 'arn:aws:iam::123456789012:role/ExpirationTest',
        sessionName: 'expiration-session',
        expires: expectedExpiration
    };

    var secretKey = {
        key: crypto.randomBytes(32).toString('hex'),
        keyId: 'test-key-005'
    };

    var token = sessionTokenModule.generateSessionToken(
        sessionData,
        secretKey
    );

    var decoded = jwt.decode(token);
    t.equal(decoded.exp, expectedExpiration, 'expiration should match calculated value');

    // Verify iat (issued at) is approximately now
    t.ok(Math.abs(decoded.iat - now) <= 1, 'issued-at should be approximately now');

    // Verify nbf (not before) is approximately now
    t.ok(Math.abs(decoded.nbf - now) <= 1, 'not-before should be approximately now');

    t.done();
};

exports.testTokenExpirationBoundaries = function (t) {
    var now = Math.floor(Date.now() / 1000);
    var secretKey = {
        key: crypto.randomBytes(32).toString('hex'),
        keyId: 'test-key-006'
    };

    // Test minimum duration (900 seconds / 15 minutes)
    var minSessionData = {
        uuid: 'test-uuid-min',
        roleArn: 'arn:aws:iam::123456789012:role/MinTest',
        sessionName: 'min-session',
        expires: now + 900
    };

    var minToken = sessionTokenModule.generateSessionToken(
        minSessionData,
        secretKey
    );
    t.ok(minToken, 'should generate token with minimum duration');

    // Test maximum duration (43200 seconds / 12 hours)
    var maxSessionData = {
        uuid: 'test-uuid-max',
        roleArn: 'arn:aws:iam::123456789012:role/MaxTest',
        sessionName: 'max-session',
        expires: now + 43200
    };

    var maxToken = sessionTokenModule.generateSessionToken(
        maxSessionData,
        secretKey
    );
    t.ok(maxToken, 'should generate token with maximum duration');

    t.done();
};

/* --- Test duration validation (min/max bounds) --- */

exports.testDurationValidationMinimum = function (t) {
    var now = Math.floor(Date.now() / 1000);
    var secretKey = {
        key: crypto.randomBytes(32).toString('hex'),
        keyId: 'test-key-007'
    };

    // Test short duration (token generation doesn't enforce AWS 900s minimum)
    // The 900 second minimum is enforced at the STS API level, not token level
    var sessionData = {
        uuid: 'test-uuid-short',
        roleArn: 'arn:aws:iam::123456789012:role/ShortTest',
        sessionName: 'short-session',
        expires: now + 60  // 1 minute duration
    };

    // Should generate successfully - token module doesn't enforce minimum
    var token = sessionTokenModule.generateSessionToken(sessionData, secretKey);
    t.ok(token, 'should generate token with short duration');

    var decoded = jwt.decode(token);
    t.equal(decoded.exp, sessionData.expires, 'should have correct expiration');

    t.done();
};

exports.testDurationValidationMaximum = function (t) {
    var now = Math.floor(Date.now() / 1000);
    var secretKey = {
        key: crypto.randomBytes(32).toString('hex'),
        keyId: 'test-key-008'
    };

    // Test duration above maximum (more than 43200 seconds)
    var sessionData = {
        uuid: 'test-uuid-long',
        roleArn: 'arn:aws:iam::123456789012:role/LongTest',
        sessionName: 'long-session',
        expires: now + 43201  // 1 second more than maximum
    };

    t.throws(function () {
        sessionTokenModule.generateSessionToken(sessionData, secretKey);
    }, /Session duration exceeds maximum allowed/, 'should reject duration above maximum');

    t.done();
};

exports.testDurationValidationPastExpiration = function (t) {
    var now = Math.floor(Date.now() / 1000);
    var secretKey = {
        key: crypto.randomBytes(32).toString('hex'),
        keyId: 'test-key-009'
    };

    // Test expiration in the past
    var sessionData = {
        uuid: 'test-uuid-past',
        roleArn: 'arn:aws:iam::123456789012:role/PastTest',
        sessionName: 'past-session',
        expires: now - 3600  // 1 hour ago
    };

    t.throws(function () {
        sessionTokenModule.generateSessionToken(sessionData, secretKey);
    }, /Session expiration must be in the future/, 'should reject expiration in the past');

    t.done();
};

/* --- Test access key generation for session --- */

exports.testSessionTokenAccessKeyIdGeneration = function (t) {
    var accessKeyId = generateSessionTokenAccessKeyId();

    t.ok(accessKeyId, 'should generate access key ID');
    t.equal(typeof accessKeyId, 'string', 'access key ID should be a string');
    t.ok(accessKeyId.startsWith('MSTS'), 'GetSessionToken access key should start with MSTS');
    t.equal(accessKeyId.length, 20, 'access key ID should be 20 characters (MSTS + 16 hex)');

    // Verify hex characters after prefix
    var hexPart = accessKeyId.substring(4);
    t.ok(/^[A-F0-9]{16}$/.test(hexPart), 'should contain 16 uppercase hex characters');

    t.done();
};

exports.testAssumeRoleAccessKeyIdGeneration = function (t) {
    var accessKeyId = generateAssumeRoleAccessKeyId();

    t.ok(accessKeyId, 'should generate access key ID');
    t.equal(typeof accessKeyId, 'string', 'access key ID should be a string');
    t.ok(accessKeyId.startsWith('MSAR'), 'AssumeRole access key should start with MSAR');
    t.equal(accessKeyId.length, 20, 'access key ID should be 20 characters (MSAR + 16 hex)');

    // Verify hex characters after prefix
    var hexPart = accessKeyId.substring(4);
    t.ok(/^[A-F0-9]{16}$/.test(hexPart), 'should contain 16 uppercase hex characters');

    t.done();
};

exports.testAccessKeyIdUniqueness = function (t) {
    var ids = new Set();
    var iterations = 1000;

    // Generate many access key IDs
    for (var i = 0; i < iterations; i++) {
        var sessionId = generateSessionTokenAccessKeyId();
        var roleId = generateAssumeRoleAccessKeyId();

        t.ok(!ids.has(sessionId), 'SessionToken access key ID should be unique');
        t.ok(!ids.has(roleId), 'AssumeRole access key ID should be unique');

        ids.add(sessionId);
        ids.add(roleId);
    }

    t.equal(ids.size, iterations * 2, 'all generated IDs should be unique');
    t.done();
};

/* --- Test secret key generation for session --- */

exports.testSecretKeyGeneration = function (t) {
    // Use accesskey.generate to create secret key (as used in STS implementation)
    accesskey.generate(accesskey.DEFAULT_PREFIX, accesskey.DEFAULT_BYTE_LENGTH,
        function (err, secretKey) {
            t.ifError(err, 'should not error generating secret key');
            t.ok(secretKey, 'should generate secret key');
            t.equal(typeof secretKey, 'string', 'secret key should be a string');

            // Secret key should be base64-encoded and have appropriate length
            t.ok(secretKey.length > 40, 'secret key should have sufficient length');

            t.done();
        });
};

exports.testSecretKeyRandomness = function (t) {
    var keys = [];
    var iterations = 100;
    var remaining = iterations;

    for (var i = 0; i < iterations; i++) {
        accesskey.generate(accesskey.DEFAULT_PREFIX, accesskey.DEFAULT_BYTE_LENGTH,
            function (err, secretKey) {
                t.ifError(err, 'should not error generating secret key');
                keys.push(secretKey);
                remaining--;

                if (remaining === 0) {
                    // Verify all keys are unique
                    var uniqueKeys = new Set(keys);
                    t.equal(uniqueKeys.size, iterations, 'all secret keys should be unique');
                    t.done();
                }
            });
    }
};

/* --- Test session token string format --- */

exports.testSessionTokenStringFormat = function (t) {
    var sessionData = {
        uuid: 'test-uuid-format',
        roleArn: 'arn:aws:iam::123456789012:role/FormatTest',
        sessionName: 'format-session',
        expires: Math.floor(Date.now() / 1000) + 3600
    };

    var secretKey = {
        key: crypto.randomBytes(32).toString('hex'),
        keyId: 'test-key-010'
    };

    var token = sessionTokenModule.generateSessionToken(
        sessionData,
        secretKey
    );

    // JWT format: base64url.base64url.base64url
    var jwtPattern = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;
    t.ok(jwtPattern.test(token), 'token should match JWT format pattern');

    // Verify base64url encoding (no +, /, or = characters)
    t.equal(token.indexOf('+'), -1, 'should not contain + character (base64url)');
    t.equal(token.indexOf('/'), -1, 'should not contain / character (base64url)');
    t.equal(token.indexOf('='), -1, 'should not contain = character (base64url)');

    t.done();
};

exports.testSessionTokenLength = function (t) {
    var sessionData = {
        uuid: 'test-uuid-length',
        roleArn: 'arn:aws:iam::123456789012:role/LengthTest',
        sessionName: 'length-session',
        expires: Math.floor(Date.now() / 1000) + 3600
    };

    var secretKey = {
        key: crypto.randomBytes(32).toString('hex'),
        keyId: 'test-key-011'
    };

    var token = sessionTokenModule.generateSessionToken(
        sessionData,
        secretKey
    );

    // JWT tokens should have reasonable length
    t.ok(token.length > 100, 'token should be substantial length');
    t.ok(token.length < 2048, 'token should not be excessively long');

    t.done();
};

/* --- Test UUID generation --- */

exports.testUUIDGeneration = function (t) {
    var uuid = generateUUID();

    t.ok(uuid, 'should generate UUID');
    t.equal(typeof uuid, 'string', 'UUID should be a string');

    // UUID v4 format: xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx
    var uuidPattern = /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
    t.ok(uuidPattern.test(uuid), 'should match UUID v4 format');

    t.done();
};

exports.testUUIDUniqueness = function (t) {
    var uuids = new Set();
    var iterations = 10000;

    for (var i = 0; i < iterations; i++) {
        var uuid = generateUUID();
        t.ok(!uuids.has(uuid), 'UUID should be unique');
        uuids.add(uuid);
    }

    t.equal(uuids.size, iterations, 'all generated UUIDs should be unique');
    t.done();
};

exports.testUUIDCryptographicRandomness = function (t) {
    var uuid = generateUUID();
    var parts = uuid.split('-');

    // Verify version bits (4xxx means version 4)
    t.equal(parts[2][0], '4', 'should have version 4 identifier');

    // Verify variant bits (yxxx where y is 8, 9, a, or b)
    var variantChar = parts[3][0];
    t.ok(['8', '9', 'a', 'b'].indexOf(variantChar) !== -1,
        'should have correct variant bits');

    t.done();
};

/* --- Test error conditions (invalid input) --- */

exports.testErrorMissingSessionData = function (t) {
    var secretKey = {
        key: crypto.randomBytes(32).toString('hex'),
        keyId: 'test-key-012'
    };

    t.throws(function () {
        sessionTokenModule.generateSessionToken(null, secretKey);
    }, 'should throw error for missing session data');

    t.done();
};

exports.testErrorMissingUUID = function (t) {
    var sessionData = {
        roleArn: 'arn:aws:iam::123456789012:role/ErrorTest',
        sessionName: 'error-session',
        expires: Math.floor(Date.now() / 1000) + 3600
    };

    var secretKey = {
        key: crypto.randomBytes(32).toString('hex'),
        keyId: 'test-key-013'
    };

    t.throws(function () {
        sessionTokenModule.generateSessionToken(sessionData, secretKey);
    }, /uuid/, 'should throw error for missing UUID');

    t.done();
};

exports.testErrorMissingRoleArn = function (t) {
    var sessionData = {
        uuid: 'test-uuid-error',
        sessionName: 'error-session',
        expires: Math.floor(Date.now() / 1000) + 3600
    };

    var secretKey = {
        key: crypto.randomBytes(32).toString('hex'),
        keyId: 'test-key-014'
    };

    t.throws(function () {
        sessionTokenModule.generateSessionToken(sessionData, secretKey);
    }, /roleArn/, 'should throw error for missing role ARN');

    t.done();
};

exports.testErrorMissingSessionName = function (t) {
    var sessionData = {
        uuid: 'test-uuid-error',
        roleArn: 'arn:aws:iam::123456789012:role/ErrorTest',
        expires: Math.floor(Date.now() / 1000) + 3600
    };

    var secretKey = {
        key: crypto.randomBytes(32).toString('hex'),
        keyId: 'test-key-015'
    };

    t.throws(function () {
        sessionTokenModule.generateSessionToken(sessionData, secretKey);
    }, /sessionName/, 'should throw error for missing session name');

    t.done();
};

exports.testErrorMissingExpiration = function (t) {
    var sessionData = {
        uuid: 'test-uuid-error',
        roleArn: 'arn:aws:iam::123456789012:role/ErrorTest',
        sessionName: 'error-session'
    };

    var secretKey = {
        key: crypto.randomBytes(32).toString('hex'),
        keyId: 'test-key-016'
    };

    t.throws(function () {
        sessionTokenModule.generateSessionToken(sessionData, secretKey);
    }, /expires/, 'should throw error for missing expiration');

    t.done();
};

exports.testErrorMissingSecretKey = function (t) {
    var sessionData = {
        uuid: 'test-uuid-error',
        roleArn: 'arn:aws:iam::123456789012:role/ErrorTest',
        sessionName: 'error-session',
        expires: Math.floor(Date.now() / 1000) + 3600
    };

    t.throws(function () {
        sessionTokenModule.generateSessionToken(sessionData, null);
    }, 'should throw error for missing secret key');

    t.done();
};

exports.testErrorMissingKeyId = function (t) {
    var sessionData = {
        uuid: 'test-uuid-error',
        roleArn: 'arn:aws:iam::123456789012:role/ErrorTest',
        sessionName: 'error-session',
        expires: Math.floor(Date.now() / 1000) + 3600
    };

    var secretKey = {
        key: crypto.randomBytes(32).toString('hex')
        // Missing keyId
    };

    t.throws(function () {
        sessionTokenModule.generateSessionToken(sessionData, secretKey);
    }, /keyId/, 'should throw error for missing key ID');

    t.done();
};

exports.testErrorInvalidDataTypes = function (t) {
    var secretKey = {
        key: crypto.randomBytes(32).toString('hex'),
        keyId: 'test-key-017'
    };

    // Test invalid UUID type
    var invalidUuidData = {
        uuid: 12345,  // should be string
        roleArn: 'arn:aws:iam::123456789012:role/ErrorTest',
        sessionName: 'error-session',
        expires: Math.floor(Date.now() / 1000) + 3600
    };

    t.throws(function () {
        sessionTokenModule.generateSessionToken(invalidUuidData, secretKey);
    }, 'should throw error for invalid UUID type');

    // Test invalid expiration type
    var invalidExpiresData = {
        uuid: 'test-uuid-error',
        roleArn: 'arn:aws:iam::123456789012:role/ErrorTest',
        sessionName: 'error-session',
        expires: 'not-a-number'  // should be number
    };

    t.throws(function () {
        sessionTokenModule.generateSessionToken(invalidExpiresData, secretKey);
    }, 'should throw error for invalid expiration type');

    t.done();
};

exports.testErrorZeroExpiration = function (t) {
    var secretKey = {
        key: crypto.randomBytes(32).toString('hex'),
        keyId: 'test-key-018'
    };

    var sessionData = {
        uuid: 'test-uuid-error',
        roleArn: 'arn:aws:iam::123456789012:role/ErrorTest',
        sessionName: 'error-session',
        expires: 0
    };

    t.throws(function () {
        sessionTokenModule.generateSessionToken(sessionData, secretKey);
    }, /Session expiration must be in the future/, 'should throw error for zero expiration');

    t.done();
};

exports.testErrorNegativeExpiration = function (t) {
    var secretKey = {
        key: crypto.randomBytes(32).toString('hex'),
        keyId: 'test-key-019'
    };

    var sessionData = {
        uuid: 'test-uuid-error',
        roleArn: 'arn:aws:iam::123456789012:role/ErrorTest',
        sessionName: 'error-session',
        expires: -3600
    };

    t.throws(function () {
        sessionTokenModule.generateSessionToken(sessionData, secretKey);
    }, /Session expiration must be in the future/, 'should throw error for negative expiration');

    t.done();
};
