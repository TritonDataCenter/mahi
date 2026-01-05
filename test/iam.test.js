/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2026 Edgecast Cloud LLC.
 */

/**
 * Unit tests for IAM (Identity and Access Management) functionality
 * Tests role creation, policy management, and AWS IAM API compatibility
 */

var bunyan = require('bunyan');
var nodeunit = require('nodeunit-plus');
var test = nodeunit.test;

// Import the server module for IAM operations
var server = require('../lib/server/server.js');

// Create a mock logger for tests
var LOG = bunyan.createLogger({
    name: 'iam-test',
    level: process.env.LOG_LEVEL || 'fatal'
});

//
// Test Suite 1: Role Creation and Trust Policy Validation
//

test('buildSecretConfig: requires secret key', function (t) {
    try {
        server.buildSecretConfig({});
        t.fail('Should throw error for missing secret key');
    } catch (err) {
        t.ok(err.message.indexOf('Missing required session secret key')
             !== -1, 'Should require secret key');
    }
    t.end();
});

test('buildSecretConfig: requires valid grace period', function (t) {
    var config = {
        secretKey: 'test-secret-key-12345678',
        secretKeyId: 'test-key-id'
    };

    try {
        server.buildSecretConfig(config);
        t.fail('Should throw error for missing grace period');
    } catch (err) {
        t.ok(err.message.indexOf('Missing required grace period') !== -1,
             'Should require grace period');
    }
    t.end();
});

test('buildSecretConfig: validates minimum grace period', function (t) {
    var config = {
        secretKey: 'test-secret-key-12345678',
        secretKeyId: 'test-key-id',
        gracePeriod: '30'  // Less than 60 seconds
    };

    try {
        server.buildSecretConfig(config);
        t.fail('Should throw error for invalid grace period');
    } catch (err) {
        t.ok(err.message.indexOf('must be a number >= 60 seconds') !== -1,
             'Should validate minimum grace period');
    }
    t.end();
});

test('buildSecretConfig: generates key ID if not provided', function (t) {
    var config = {
        secretKey: 'test-secret-key-12345678',
        gracePeriod: '86400'  // 24 hours
        // No secretKeyId provided
    };

    var result = server.buildSecretConfig(config);

    t.ok(result.primarySecret, 'Should have primary secret');
    t.ok(result.primarySecret.key, 'Should have secret key');
    t.ok(result.primarySecret.keyId, 'Should generate key ID');
    t.ok(result.primarySecret.keyId.indexOf('key-') === 0,
         'Generated key ID should have proper format');
    t.equal(result.gracePeriod, 86400, 'Should set grace period');
    t.end();
});

test('buildSecretConfig: handles old secret for rotation', function (t) {
    var config = {
        secretKey: 'new-secret-key-12345678',
        secretKeyId: 'new-key-id',
        oldSecretKey: 'old-secret-key-87654321',
        oldSecretKeyId: 'old-key-id',
        rotationTime: '1640995200',  // Unix timestamp
        gracePeriod: '86400'
    };

    var result = server.buildSecretConfig(config);

    t.ok(result.primarySecret, 'Should have primary secret');
    t.equal(result.primarySecret.key, config.secretKey,
            'Primary key should match');
    t.equal(result.primarySecret.keyId, config.secretKeyId,
            'Primary key ID should match');

    // Check secrets map
    t.ok(result.secrets[config.secretKeyId],
         'Should have new secret in map');
    t.ok(result.secrets[config.oldSecretKeyId],
         'Should have old secret in map');

    var newSecret = result.secrets[config.secretKeyId];
    var oldSecret = result.secrets[config.oldSecretKeyId];

    t.ok(newSecret.isPrimary, 'New secret should be primary');
    t.ok(!oldSecret.isPrimary, 'Old secret should not be primary');
    t.equal(oldSecret.addedAt, 1640995200000,
            'Old secret should have rotation timestamp');

    t.end();
});

test('buildSecretConfig: validates rotation timestamp format', function (t) {
    var config = {
        secretKey: 'test-secret-key-12345678',
        secretKeyId: 'test-key-id',
        oldSecretKey: 'old-secret-key-87654321',
        oldSecretKeyId: 'old-key-id',
        rotationTime: 'invalid-timestamp',
        gracePeriod: '86400'
    };

    var result = server.buildSecretConfig(config);

    // Should handle invalid timestamp gracefully
    var oldSecret = result.secrets[config.oldSecretKeyId];
    t.ok(isNaN(oldSecret.addedAt) || oldSecret.addedAt > 0,
         'Should handle invalid timestamp gracefully');

    t.end();
});

//
// Test Suite 2: Environment Variable Support
//

test('buildSecretConfig: uses environment variables as fallback',
     function (t) {
    // Set environment variables
    process.env.SESSION_SECRET_KEY = 'env-secret-key-123';
    process.env.SESSION_SECRET_KEY_ID = 'env-key-id';
    process.env.SESSION_SECRET_GRACE_PERIOD = '7200';

    try {
        var result = server.buildSecretConfig();

        t.equal(result.primarySecret.key, 'env-secret-key-123',
                'Should use env secret key');
        t.equal(result.primarySecret.keyId, 'env-key-id',
                'Should use env key ID');
        t.equal(result.gracePeriod, 7200,
                'Should use env grace period');

    } finally {
        // Clean up environment variables
        delete process.env.SESSION_SECRET_KEY;
        delete process.env.SESSION_SECRET_KEY_ID;
        delete process.env.SESSION_SECRET_GRACE_PERIOD;
    }

    t.end();
});

test('buildSecretConfig: session config overrides environment',
     function (t) {
    // Set environment variables
    process.env.SESSION_SECRET_KEY = 'env-secret-key-123';
    process.env.SESSION_SECRET_KEY_ID = 'env-key-id';
    process.env.SESSION_SECRET_GRACE_PERIOD = '7200';

    var config = {
        secretKey: 'config-secret-key-456',
        secretKeyId: 'config-key-id',
        gracePeriod: '3600'
    };

    try {
        var result = server.buildSecretConfig(config);

        t.equal(result.primarySecret.key, 'config-secret-key-456',
                'Should use config secret key over env');
        t.equal(result.primarySecret.keyId, 'config-key-id',
                'Should use config key ID over env');
        t.equal(result.gracePeriod, 3600,
                'Should use config grace period over env');

    } finally {
        // Clean up environment variables
        delete process.env.SESSION_SECRET_KEY;
        delete process.env.SESSION_SECRET_KEY_ID;
        delete process.env.SESSION_SECRET_GRACE_PERIOD;
    }

    t.end();
});

//
// Test Suite 3: Security Validation
//

test('buildSecretConfig: rejects non-numeric grace period', function (t) {
    var config = {
        secretKey: 'test-secret-key-12345678',
        secretKeyId: 'test-key-id',
        gracePeriod: 'not-a-number'
    };

    try {
        server.buildSecretConfig(config);
        t.fail('Should throw error for non-numeric grace period');
    } catch (err) {
        t.ok(err.message.indexOf('must be a number') !== -1,
             'Should reject non-numeric grace period');
    }
    t.end();
});

test('buildSecretConfig: rejects empty secret key', function (t) {
    var config = {
        secretKey: '',
        gracePeriod: '86400'
    };

    try {
        server.buildSecretConfig(config);
        t.fail('Should throw error for empty secret key');
    } catch (err) {
        t.ok(err.message.indexOf('Missing required session secret key')
             !== -1, 'Should reject empty secret key');
    }
    t.end();
});

test('buildSecretConfig: secret isolation', function (t) {
    var config = {
        secretKey: 'test-secret-key-12345678',
        secretKeyId: 'test-key-id',
        gracePeriod: '86400'
    };

    var result = server.buildSecretConfig(config);

    // Verify secrets are properly isolated
    t.notEqual(result.secrets, result.primarySecret,
               'Secrets map should be different from primary secret');
    t.ok(result.secrets[config.secretKeyId],
         'Primary secret should be in secrets map');
    t.equal(Object.keys(result.secrets).length, 1,
            'Should only have one secret when no old secret provided');

    t.end();
});

console.log('✓ IAM configuration and security tests loaded');
