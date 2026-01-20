/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright 2026 Edgecast Cloud LLC.
 */

/*
 * test/session-token-rotation.test.js: Unit tests for JWT secret rotation
 *
 * Tests the session token verification with multiple secrets during
 * rotation scenarios, grace period handling, and secret expiration.
 */

var nodeunit = require('nodeunit');
var sessionTokenModule = require('../lib/server/session-token');

// Constants for testing
var TEST_UUID = 'test-user-uuid-rotation';
var TEST_ROLE_ARN = 'arn:aws:iam::123456789012:role/TestRole';
var TEST_SESSION_NAME = 'rotation-test-session';
var GRACE_PERIOD = 3600; // 1 hour for testing

/*
 * Helper to create session data
 */
function createSessionData(expiresIn) {
    expiresIn = expiresIn || 3600;
    var now = Math.floor(Date.now() / 1000);
    return {
        uuid: TEST_UUID,
        roleArn: TEST_ROLE_ARN,
        sessionName: TEST_SESSION_NAME,
        expires: now + expiresIn
    };
}

/*
 * Helper to create secret configuration with multiple secrets
 */
function createSecretConfig(secrets, gracePeriod) {
    var config = {
        secrets: {},
        gracePeriod: gracePeriod || GRACE_PERIOD
    };

    secrets.forEach(function (secret) {
        config.secrets[secret.keyId] = {
            key: secret.key,
            keyId: secret.keyId,
            isPrimary: secret.isPrimary || false,
            addedAt: secret.addedAt || Date.now()
        };
    });

    // Set primary secret if specified
    var primarySecret = secrets.filter(function (s) {
        return (s.isPrimary);
    })[0];

    if (primarySecret) {
        config.primarySecret = config.secrets[primarySecret.keyId];
    }

    return (config);
}

/* --- Test token verification with current (primary) secret --- */

exports.testVerifyWithPrimarySecret = function (t) {
    var primarySecret = {
        key: 'primary-secret-key-001',
        keyId: 'primary-key-001',
        isPrimary: true
    };

    var sessionData = createSessionData();
    var secretConfig = createSecretConfig([primarySecret]);

    // Generate token with primary secret
    var token = sessionTokenModule.generateSessionToken(
        sessionData,
        secretConfig.primarySecret);

    // Verify with primary secret should succeed
    sessionTokenModule.verifySessionToken(token, secretConfig, {},
        function (err, result) {
        t.ok(!err, 'should verify with primary secret');
        t.ok(result, 'should return result');
        if (result) {
            t.equal(result.uuid, TEST_UUID, 'should have correct UUID');
            t.equal(result.roleArn, TEST_ROLE_ARN,
                'should have correct roleArn');
        }
        t.done();
    });
};

exports.testVerifyWithMultiplePrimarySecrets = function (t) {
    // Scenario: Multiple primary secrets (shouldn't happen, but test it)
    var secret1 = {
        key: 'primary-secret-001',
        keyId: 'primary-001',
        isPrimary: true
    };

    var secret2 = {
        key: 'primary-secret-002',
        keyId: 'primary-002',
        isPrimary: true
    };

    var sessionData = createSessionData();
    var secretConfig = createSecretConfig([secret1, secret2]);

    // Generate token with first primary secret
    var token = sessionTokenModule.generateSessionToken(
        sessionData,
        secretConfig.secrets[secret1.keyId]);

    // Should verify successfully (will try both)
    sessionTokenModule.verifySessionToken(token, secretConfig, {},
        function (err, result) {
        t.ok(!err, 'should verify with one of the primary secrets');
        t.ok(result, 'should return result');
        t.done();
    });
};

/* --- Test token verification with old secret during grace period --- */

exports.testVerifyWithOldSecretDuringGracePeriod = function (t) {
    var now = Date.now();

    var oldSecret = {
        key: 'old-secret-key-001',
        keyId: 'old-key-001',
        isPrimary: false,
        addedAt: now - 1800000 // 30 minutes ago
    };

    var newSecret = {
        key: 'new-secret-key-001',
        keyId: 'new-key-001',
        isPrimary: true,
        addedAt: now
    };

    var sessionData = createSessionData();
    var secretConfig = createSecretConfig([oldSecret, newSecret]);

    // Generate token with old secret
    var token = sessionTokenModule.generateSessionToken(
        sessionData,
        secretConfig.secrets[oldSecret.keyId]);

    // Verify should succeed (old secret still within grace period)
    sessionTokenModule.verifySessionToken(token, secretConfig, {},
        function (err, result) {
        t.ok(!err, 'should verify with old secret during grace period');
        t.ok(result, 'should return result');
        t.done();
    });
};

exports.testVerifyWithOldSecretNearGracePeriodEnd = function (t) {
    var now = Date.now();
    var gracePeriod = 3600; // 1 hour

    var oldSecret = {
        key: 'old-secret-expiring',
        keyId: 'old-key-expiring',
        isPrimary: false,
        addedAt: now - (gracePeriod * 1000 - 60000) // 59 minutes ago
    };

    var newSecret = {
        key: 'new-secret-current',
        keyId: 'new-key-current',
        isPrimary: true,
        addedAt: now
    };

    var sessionData = createSessionData();
    var secretConfig = createSecretConfig([oldSecret, newSecret],
        gracePeriod);

    // Generate token with old secret
    var token = sessionTokenModule.generateSessionToken(
        sessionData,
        secretConfig.secrets[oldSecret.keyId]);

    // Should still verify (1 minute before grace period expires)
    sessionTokenModule.verifySessionToken(token, secretConfig, {},
        function (err, result) {
        t.ok(!err, 'should verify just before grace period expires');
        t.ok(result, 'should return result');
        t.done();
    });
};

/* --- Test grace period boundary conditions --- */

exports.testSecretBeyondGracePeriodStillInConfig = function (t) {
    var now = Date.now();
    var gracePeriod = 3600; // 1 hour

    var expiredSecret = {
        key: 'expired-secret-key',
        keyId: 'expired-key-001',
        isPrimary: false,
        addedAt: now - (gracePeriod * 1000 + 1000) // 1 hour 1 second ago
    };

    var newSecret = {
        key: 'new-secret-only',
        keyId: 'new-key-only',
        isPrimary: true,
        addedAt: now
    };

    var sessionData = createSessionData();
    var secretConfig = createSecretConfig([expiredSecret, newSecret],
        gracePeriod);

    // Generate token with expired secret
    var token = sessionTokenModule.generateSessionToken(
        sessionData,
        secretConfig.secrets[expiredSecret.keyId]);

    // Should still verify (secret still in config, keyId matches)
    // Grace period only applies to fallback verification
    sessionTokenModule.verifySessionToken(token, secretConfig, {},
        function (err, result) {
        t.ok(!err, 'should verify with keyId match even beyond grace period');
        t.ok(result, 'should return result');
        t.done();
    });
};

exports.testGracePeriodAppliesOnlyToFallback = function (t) {
    var now = Date.now();

    var oldSecret = {
        key: 'old-secret-immediate',
        keyId: 'old-key-immediate',
        isPrimary: false,
        addedAt: now - 1000 // 1 second ago
    };

    var newSecret = {
        key: 'new-secret-immediate',
        keyId: 'new-key-immediate',
        isPrimary: true,
        addedAt: now
    };

    var sessionData = createSessionData();
    var secretConfig = createSecretConfig([oldSecret, newSecret], 0);

    // Generate token with old secret
    var token = sessionTokenModule.generateSessionToken(
        sessionData,
        secretConfig.secrets[oldSecret.keyId]);

    // Should still verify (keyId matches, grace period irrelevant
    // for keyId match)
    sessionTokenModule.verifySessionToken(token, secretConfig, {},
        function (err, result) {
        t.ok(!err, 'should verify with keyId match regardless of grace period');
        t.ok(result, 'should return result');
        t.done();
    });
};

/* --- Test rotation scenarios --- */

exports.testRotationScenario = function (t) {
    var now = Date.now();

    // Step 1: Old secret is primary
    var oldSecret = {
        key: 'secret-before-rotation',
        keyId: 'key-before-rotation',
        isPrimary: false,
        addedAt: now - 1800000 // 30 minutes ago
    };

    // Step 2: New secret becomes primary
    var newSecret = {
        key: 'secret-after-rotation',
        keyId: 'key-after-rotation',
        isPrimary: true,
        addedAt: now
    };

    var sessionData = createSessionData();

    // Generate token with old secret (before rotation)
    var oldToken = sessionTokenModule.generateSessionToken(
        sessionData,
        oldSecret);

    // Generate token with new secret (after rotation)
    var newToken = sessionTokenModule.generateSessionToken(
        sessionData,
        newSecret);

    // Create config with both secrets (rotation in progress)
    var secretConfig = createSecretConfig([oldSecret, newSecret]);

    // Both tokens should verify during grace period
    sessionTokenModule.verifySessionToken(oldToken, secretConfig, {},
        function (err1, result1) {
        t.ok(!err1, 'old token should verify during grace period');
        t.ok(result1, 'should return result for old token');

        sessionTokenModule.verifySessionToken(newToken, secretConfig, {},
            function (err2, result2) {
            t.ok(!err2, 'new token should verify');
            t.ok(result2, 'should return result for new token');
            t.done();
        });
    });
};

exports.testRotationWithThreeGenerations = function (t) {
    var now = Date.now();

    // Ancient secret (expired)
    var ancientSecret = {
        key: 'ancient-secret',
        keyId: 'ancient-key',
        isPrimary: false,
        addedAt: now - 7200000 // 2 hours ago
    };

    // Old secret (within grace period)
    var oldSecret = {
        key: 'old-secret',
        keyId: 'old-key',
        isPrimary: false,
        addedAt: now - 1800000 // 30 minutes ago
    };

    // Current secret (primary)
    var currentSecret = {
        key: 'current-secret',
        keyId: 'current-key',
        isPrimary: true,
        addedAt: now
    };

    var sessionData = createSessionData();
    var secretConfig = createSecretConfig(
        [ancientSecret, oldSecret, currentSecret]);

    // Token with ancient secret should succeed
    // (still in config with keyId match)
    var ancientToken = sessionTokenModule.generateSessionToken(
        sessionData,
        ancientSecret);

    sessionTokenModule.verifySessionToken(ancientToken, secretConfig, {},
        function (err1, result1) {
        t.ok(!err1, 'ancient token should succeed (keyId in config)');
        t.ok(result1, 'should return result for ancient token');

        // Token with old secret should succeed
        var oldToken = sessionTokenModule.generateSessionToken(
            sessionData,
            oldSecret);

        sessionTokenModule.verifySessionToken(oldToken, secretConfig, {},
            function (err2, result2) {
            t.ok(!err2, 'old token should succeed');
            t.ok(result2, 'should return result for old token');

            // Token with current secret should succeed
            var currentToken = sessionTokenModule.generateSessionToken(
                sessionData,
                currentSecret);

            sessionTokenModule.verifySessionToken(currentToken,
                secretConfig, {}, function (err3, result3) {
                t.ok(!err3, 'current token should succeed');
                t.ok(result3,
                    'should return result for current token');
                t.done();
            });
        });
    });
};

/* --- Test multiple secret version handling --- */

exports.testMultipleValidSecrets = function (t) {
    var now = Date.now();

    var secrets = [
        {
            key: 'secret-001',
            keyId: 'key-001',
            isPrimary: false,
            addedAt: now - 1800000 // 30 min ago
        },
        {
            key: 'secret-002',
            keyId: 'key-002',
            isPrimary: false,
            addedAt: now - 900000 // 15 min ago
        },
        {
            key: 'secret-003',
            keyId: 'key-003',
            isPrimary: true,
            addedAt: now
        }
    ];

    var sessionData = createSessionData();
    var secretConfig = createSecretConfig(secrets);

    // Generate tokens with each secret
    var tokens = secrets.map(function (secret) {
        return sessionTokenModule.generateSessionToken(
            sessionData,
            secret);
    });

    // All tokens should verify
    var verified = 0;
    tokens.forEach(function (token, index) {
        sessionTokenModule.verifySessionToken(token, secretConfig, {},
            function (err, result) {
            t.ok(!err, 'token ' + index + ' should verify');
            t.ok(result, 'should return result for token ' + index);
            verified++;
            if (verified === tokens.length) {
                t.done();
            }
        });
    });
};

exports.testFallbackToAllSecretsWhenKeyIdMismatch = function (t) {
    var now = Date.now();

    var secret1 = {
        key: 'secret-fallback-001',
        keyId: 'key-fallback-001',
        isPrimary: false,
        addedAt: now - 1800000
    };

    var secret2 = {
        key: 'secret-fallback-002',
        keyId: 'key-fallback-002',
        isPrimary: true,
        addedAt: now
    };

    var sessionData = createSessionData();

    // Generate token with secret1
    var token = sessionTokenModule.generateSessionToken(
        sessionData,
        secret1);

    // Create config with secret2 only (secret1 removed)
    // This simulates a scenario where the key ID in the token
    // doesn't match any secret, but the token is still valid
    var secretConfig = createSecretConfig([secret2]);

    // Should fail (secret1 not available, different key used)
    sessionTokenModule.verifySessionToken(token, secretConfig, {},
        function (err, result) {
        t.ok(err, 'should fail when signing key not available');
        t.ok(!result, 'should not return result');
        t.done();
    });
};

/* --- Test error conditions --- */

exports.testRemovedSecretCannotVerify = function (t) {
    var sessionData = createSessionData();

    // Create a secret and token
    var removedSecret = {
        key: 'removed-secret',
        keyId: 'removed-key',
        isPrimary: false,
        addedAt: Date.now() - 1000
    };

    var token = sessionTokenModule.generateSessionToken(
        sessionData,
        removedSecret);

    // Create config WITHOUT the secret (it's been removed)
    var newSecret = {
        key: 'new-secret-only',
        keyId: 'new-key-only',
        isPrimary: true,
        addedAt: Date.now()
    };

    var secretConfig = createSecretConfig([newSecret]);

    // Should fail (secret removed from config)
    sessionTokenModule.verifySessionToken(token, secretConfig, {},
        function (err, result) {
        t.ok(err, 'should fail when signing secret removed from config');
        t.ok(!result, 'should not return result');
        t.done();
    });
};

exports.testEmptySecretsConfig = function (t) {
    var sessionData = createSessionData();
    var token = sessionTokenModule.generateSessionToken(
        sessionData,
        {key: 'some-key', keyId: 'some-id'});

    // Empty secrets config
    var secretConfig = {
        secrets: {},
        gracePeriod: GRACE_PERIOD
    };

    // Should fail (no secrets configured)
    sessionTokenModule.verifySessionToken(token, secretConfig, {},
        function (err, result) {
        t.ok(err, 'should fail with empty secrets config');
        t.ok(!result, 'should not return result');
        t.done();
    });
};

/* --- Test primary secret always valid --- */

exports.testPrimarySecretAlwaysValid = function (t) {
    var now = Date.now();

    // Primary secret added long ago, but should still be valid
    var primarySecret = {
        key: 'primary-ancient',
        keyId: 'primary-ancient-key',
        isPrimary: true,
        addedAt: now - 86400000 // 24 hours ago (beyond grace period)
    };

    var sessionData = createSessionData();
    var secretConfig = createSecretConfig([primarySecret], 3600);

    // Generate token with primary secret
    var token = sessionTokenModule.generateSessionToken(
        sessionData,
        secretConfig.secrets[primarySecret.keyId]);

    // Should verify (primary secrets ignore grace period)
    sessionTokenModule.verifySessionToken(token, secretConfig, {},
        function (err, result) {
        t.ok(!err, 'primary secret should always be valid');
        t.ok(result, 'should return result');
        t.done();
    });
};
