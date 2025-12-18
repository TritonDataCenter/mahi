/*
 * This Source Code Form is subject to the terms of the Mozilla
 * Public License, v. 2.0. If a copy of the MPL was not
 * distributed with this file, You can obtain one at
 * http://mozilla.org/MPL/2.0/.
 *
 * Copyright 2025 Edgecast Cloud LLC.
 */

/*
 * test/session-token-jwt.test.js: Unit tests for session token
 * JWT operations
 */

var nodeunit = require('nodeunit');
var sessionTokenModule = require('../lib/server/session-token');

/* --- Test JWT payload extraction --- */

exports.testDecodeValidToken = function (t) {
    var secretKey = {
        key: 'test-secret-key-12345',
        keyId: 'test-key-001'
    };

    var now = Math.floor(Date.now() / 1000);
    var sessionData = {
        uuid: 'test-user-123',
        roleArn: 'arn:aws:iam::123456789012:role/TestRole',
        sessionName: 'test-session-001',
        expires: now + 3600
    };

    var token = sessionTokenModule.generateSessionToken(
        sessionData,
        secretKey);

    var decoded = sessionTokenModule.decodeSessionToken(token);

    t.ok(decoded, 'should return decoded payload');
    t.equal(decoded.uuid, sessionData.uuid,
        'should extract uuid');
    t.equal(decoded.roleArn, sessionData.roleArn,
        'should extract roleArn');
    t.equal(decoded.sessionName, sessionData.sessionName,
        'should extract sessionName');
    t.equal(decoded.exp, sessionData.expires,
        'should extract expiration');
    t.equal(typeof (decoded.iat), 'number',
        'should have issued-at timestamp');
    t.equal(decoded.tokenVersion, '1.1',
        'should have token version');
    t.done();
};

exports.testDecodePayloadStructure = function (t) {
    var secretKey = {
        key: 'test-secret-key-67890',
        keyId: 'test-key-002'
    };

    var now = Math.floor(Date.now() / 1000);
    var sessionData = {
        uuid: 'test-user-456',
        roleArn: 'arn:aws:iam::987654321098:role/AdminRole',
        sessionName: 'admin-session-001',
        expires: now + 3600
    };

    var token = sessionTokenModule.generateSessionToken(
        sessionData,
        secretKey);

    var decoded = sessionTokenModule.decodeSessionToken(token);

    // Check JWT standard claims
    t.ok(decoded.iss, 'should have issuer claim');
    t.ok(decoded.aud, 'should have audience claim');
    t.ok(decoded.iat, 'should have issued-at claim');
    t.ok(decoded.exp, 'should have expiration claim');
    t.ok(decoded.nbf, 'should have not-before claim');

    // Check custom session claims
    t.ok(decoded.uuid, 'should have uuid claim');
    t.ok(decoded.roleArn, 'should have roleArn claim');
    t.ok(decoded.sessionName, 'should have sessionName claim');
    t.ok(decoded.tokenVersion, 'should have tokenVersion claim');
    t.ok(decoded.keyId, 'should have keyId claim');

    t.done();
};

/* --- Test session token extraction from headers --- */

exports.testExtractTokenFromXAmzSecurityToken = function (t) {
    var headers = {
        'x-amz-security-token': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9',
        'host': 'localhost',
        'x-amz-date': '20251217T120000Z'
    };

    var token = sessionTokenModule.extractSessionToken(headers);

    t.equal(token, 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9',
        'should extract token from x-amz-security-token');
    t.done();
};

exports.testExtractTokenFromAuthorizationHeader = function (t) {
    var headers = {
        'authorization': 'AWS4-HMAC-SHA256 Credential=AKIATEST/..., ' +
            'SessionToken=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload',
        'host': 'localhost'
    };

    var token = sessionTokenModule.extractSessionToken(headers);

    t.equal(token,
        'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload',
        'should extract token from Authorization header');
    t.done();
};

exports.testExtractTokenPriority = function (t) {
    var headers = {
        'x-amz-security-token': 'token-from-header',
        'authorization': 'AWS4-HMAC-SHA256 SessionToken=token-from-auth',
        'host': 'localhost'
    };

    var token = sessionTokenModule.extractSessionToken(headers);

    t.equal(token, 'token-from-header',
        'should prioritize x-amz-security-token over Authorization');
    t.done();
};

exports.testExtractTokenMissing = function (t) {
    var headers = {
        'host': 'localhost',
        'x-amz-date': '20251217T120000Z'
    };

    var token = sessionTokenModule.extractSessionToken(headers);

    t.equal(token, null,
        'should return null when no token present');
    t.done();
};

/* --- Test JWT format validation --- */

exports.testDecodeRejectsInvalidFormat = function (t) {
    var invalidTokens = [
        'not-a-jwt',
        'only.two.parts.here.extra',
        'single-part',
        'two.parts'
    ];

    invalidTokens.forEach(function (invalidToken) {
        t.throws(function () {
            sessionTokenModule.decodeSessionToken(invalidToken);
        }, 'should reject token with invalid format: ' + invalidToken);
    });

    t.done();
};

exports.testDecodeRejectsInvalidBase64 = function (t) {
    // Create token with invalid base64 in payload
    var invalidToken = 'eyJhbGciOiJIUzI1NiJ9.!!!invalid-base64!!!.' +
        'signature';

    t.throws(function () {
        sessionTokenModule.decodeSessionToken(invalidToken);
    }, 'should reject token with invalid base64 payload');

    t.done();
};

exports.testDecodeRejectsInvalidJSON = function (t) {
    // Create token with non-JSON payload
    var invalidPayload = Buffer.from('not valid json {{{').toString('base64')
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    var invalidToken = 'eyJhbGciOiJIUzI1NiJ9.' + invalidPayload +
        '.signature';

    t.throws(function () {
        sessionTokenModule.decodeSessionToken(invalidToken);
    }, 'should reject token with invalid JSON payload');

    t.done();
};

exports.testDecodeRejectsTooLargeToken = function (t) {
    // Create a payload larger than 64KB
    var largeData = new Array(65537).join('x');
    var largePayload = Buffer.from(JSON.stringify({data: largeData}))
        .toString('base64')
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    var largeToken = 'eyJhbGciOiJIUzI1NiJ9.' + largePayload + '.signature';

    t.throws(function () {
        sessionTokenModule.decodeSessionToken(largeToken);
    }, 'should reject token larger than 64KB');

    t.done();
};

/* --- Test session metadata retrieval --- */

exports.testRetrieveSessionMetadata = function (t) {
    var secretKey = {
        key: 'metadata-test-key',
        keyId: 'test-key-003'
    };

    var now = Math.floor(Date.now() / 1000);
    var sessionData = {
        uuid: 'metadata-test-user',
        roleArn: 'arn:aws:iam::111111111111:role/MetadataRole',
        sessionName: 'metadata-session',
        expires: now + 3600
    };

    var token = sessionTokenModule.generateSessionToken(
        sessionData,
        secretKey);

    var decoded = sessionTokenModule.decodeSessionToken(token);

    // Verify all metadata fields are retrievable
    t.equal(decoded.uuid, 'metadata-test-user',
        'should retrieve uuid');
    t.equal(decoded.roleArn,
        'arn:aws:iam::111111111111:role/MetadataRole',
        'should retrieve roleArn');
    t.equal(decoded.sessionName, 'metadata-session',
        'should retrieve sessionName');
    t.equal(decoded.keyId, 'test-key-003',
        'should retrieve keyId');
    t.equal(decoded.tokenVersion, '1.1',
        'should retrieve tokenVersion');
    t.ok(decoded.iat <= now + 1000,
        'should have reasonable issued-at time');
    t.equal(decoded.exp, sessionData.expires,
        'should retrieve expiration');

    t.done();
};

exports.testRetrieveIssuerAndAudience = function (t) {
    var secretKey = {
        key: 'issuer-test-key',
        keyId: 'test-key-004'
    };

    var now = Math.floor(Date.now() / 1000);
    var sessionData = {
        uuid: 'issuer-test-user',
        roleArn: 'arn:aws:iam::222222222222:role/IssuerRole',
        sessionName: 'issuer-session',
        expires: now + 3600
    };

    var token = sessionTokenModule.generateSessionToken(
        sessionData,
        secretKey);

    var decoded = sessionTokenModule.decodeSessionToken(token);

    t.equal(decoded.iss, 'manta-mahi',
        'should have default issuer');
    t.equal(decoded.aud, 'manta-s3',
        'should have default audience');

    t.done();
};

/* --- Test edge cases --- */

exports.testDecodeEmptyToken = function (t) {
    t.throws(function () {
        sessionTokenModule.decodeSessionToken('');
    }, 'should reject empty token');

    t.done();
};

exports.testDecodeNullToken = function (t) {
    t.throws(function () {
        sessionTokenModule.decodeSessionToken(null);
    }, 'should reject null token');

    t.done();
};

exports.testExtractFromEmptyHeaders = function (t) {
    var token = sessionTokenModule.extractSessionToken({});

    t.equal(token, null,
        'should return null for empty headers');
    t.done();
};

exports.testDecodeWithPaddedBase64 = function (t) {
    var secretKey = {
        key: 'padding-test-key',
        keyId: 'test-key-005'
    };

    var now = Math.floor(Date.now() / 1000);
    var sessionData = {
        uuid: 'ab',
        roleArn: 'arn:aws:iam::333333333333:role/R',
        sessionName: 's',
        expires: now + 3600
    };

    var token = sessionTokenModule.generateSessionToken(
        sessionData,
        secretKey);

    var decoded = sessionTokenModule.decodeSessionToken(token);

    t.equal(decoded.uuid, 'ab',
        'should handle short values with padding');

    t.done();
};

exports.testDecodeWithSpecialCharacters = function (t) {
    var secretKey = {
        key: 'special-char-key',
        keyId: 'test-key-006'
    };

    var now = Math.floor(Date.now() / 1000);
    var sessionData = {
        uuid: 'user-with-special-chars-!@#',
        roleArn: 'arn:aws:iam::444444444444:role/Role-With-Dashes',
        sessionName: 'session_with_underscores',
        expires: now + 3600
    };

    var token = sessionTokenModule.generateSessionToken(
        sessionData,
        secretKey);

    var decoded = sessionTokenModule.decodeSessionToken(token);

    t.equal(decoded.uuid, 'user-with-special-chars-!@#',
        'should handle special characters in uuid');
    t.equal(decoded.roleArn,
        'arn:aws:iam::444444444444:role/Role-With-Dashes',
        'should handle dashes in roleArn');
    t.equal(decoded.sessionName, 'session_with_underscores',
        'should handle underscores in sessionName');

    t.done();
};

/* --- Test token version handling --- */

exports.testDecodeTokenVersion = function (t) {
    var secretKey = {
        key: 'version-test-key',
        keyId: 'test-key-007'
    };

    var now = Math.floor(Date.now() / 1000);
    var sessionData = {
        uuid: 'version-test-user',
        roleArn: 'arn:aws:iam::555555555555:role/VersionRole',
        sessionName: 'version-session',
        expires: now + 3600
    };

    var token = sessionTokenModule.generateSessionToken(
        sessionData,
        secretKey);

    var decoded = sessionTokenModule.decodeSessionToken(token);

    t.equal(decoded.tokenVersion, '1.1',
        'should decode current token version');

    t.done();
};
