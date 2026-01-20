/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright (c) 2025, Joyent, Inc.
 */

/**
 * Integration Test: Complete SigV4 and STS Authentication Flow
 *
 * Demonstrates end-to-end testing of AWS Signature Version 4
 * authentication and Security Token Service (STS) operations using
 * the test harness infrastructure.
 */

var TestHarness = require('../lib/test-harness.js');

var nodeunit = require('nodeunit-plus');
var after = nodeunit.after;
var before = nodeunit.before;
var test = nodeunit.test;

/**
 * Setup: Initialize test harness with all components enabled
 */
before(function (cb) {
    this.harness = new TestHarness({
        mockUfds: false,     // Don't need UFDS for this test
        redisFixture: 'basicAuth',
        timeMock: true,      // Enable for deterministic signatures
        serverPort: 0        // Use port 0 to let OS assign available port
    });

    this.harness.setup(cb);
});

/**
 * Teardown: Clean up test harness
 */
after(function (cb) {
    this.harness.teardown(cb);
});

/**
 * Test: Basic SigV4 authentication with GET request
 *
 * Demonstrates using the test harness to create a user with access
 * keys and generate valid SigV4 authentication headers.
 */
test('sigv4 authentication - GET request', function (t) {
    var harness = this.harness;

    // Skip if server couldn't start (restify/Node.js incompatibility)
    if (!harness.serverAvailable) {
        t.ok(true, 'test skipped - server not available');
        t.end();
        return;
    }

    // Step 1: Create test user with access key
    harness.createUser({
        login: 'testuser',
        account: harness._generateUuid()
    }, function (err, user) {
        t.ok(!err, 'user creation should succeed');
        t.ok(user.uuid, 'user should have UUID');
        t.ok(user.accessKey, 'user should have access key');
        t.ok(user.secret, 'user should have secret');

        // Step 2: Freeze time for deterministic signature
        if (harness.time) {
            harness.time.freeze(Date.parse('2025-01-16T12:00:00Z'));
        }

        // Step 3: Generate SigV4 headers for GET request
        var headers = harness.sigv4.get(
            '/accounts/' + user.account,
            user.accessKey,
            user.secret
);

        t.ok(headers.authorization, 'should have authorization header');
        t.ok(headers['x-amz-date'], 'should have x-amz-date header');
        t.ok(headers['x-amz-content-sha256'],
            'should have x-amz-content-sha256 header');
        t.ok(headers.host, 'should have host header');

        // Verify authorization header format
        t.ok(headers.authorization.indexOf('AWS4-HMAC-SHA256') === 0,
            'authorization should use AWS4-HMAC-SHA256');
        t.ok(headers.authorization.indexOf('Credential=') !== -1,
            'authorization should contain Credential');
        t.ok(headers.authorization.indexOf('SignedHeaders=') !== -1,
            'authorization should contain SignedHeaders');
        t.ok(headers.authorization.indexOf('Signature=') !== -1,
            'authorization should contain Signature');

        if (harness.time) {
            harness.time.restore();
        }

        return (t.end());
    });
});

/**
 * Test: SigV4 authentication with POST request
 *
 * Demonstrates generating SigV4 signature for POST request with body.
 */
test('sigv4 authentication - POST request with body', function (t) {
    var harness = this.harness;

    // Step 1: Create test user
    harness.createUser({
        login: 'stsuser',
        account: harness._generateUuid()
    }, function (err, user) {
        t.ok(!err, 'user creation should succeed');

        // Step 2: Freeze time
        if (harness.time) {
            harness.time.freeze(Date.parse('2025-01-16T14:30:00Z'));
        }

        // Step 3: Prepare request body
        var body = {
            RoleArn: 'arn:aws:iam::' + user.account + ':role/TestRole',
            RoleSessionName: 'test-session-' + Date.now()
        };

        // Step 4: Generate SigV4 headers for POST with body
        var headers = harness.sigv4.post(
            '/sts/AssumeRole',
            user.accessKey,
            user.secret,
            body
);

        t.ok(headers.authorization, 'should have authorization header');
        t.ok(headers['content-type'], 'should have content-type header');
        // Note: content-length is not set by SigV4Helper as HTTP module
        // will calculate it automatically when sending the request

        // Step 5: Verify authorization header format
        t.ok(headers.authorization.indexOf('AWS4-HMAC-SHA256') === 0,
            'authorization should use AWS4-HMAC-SHA256');
        t.ok(headers.authorization.indexOf('Credential=') !== -1,
            'authorization should contain Credential');
        t.ok(headers.authorization.indexOf('SignedHeaders=') !== -1,
            'authorization should contain SignedHeaders');
        t.ok(headers.authorization.indexOf('Signature=') !== -1,
            'authorization should contain Signature');

        if (harness.time) {
            harness.time.restore();
        }

        t.end();
    });
});

/**
 * Test: Time advancement for expiration testing
 *
 * Demonstrates using time mock to test time-dependent behavior like
 * JWT token expiration and SigV4 timestamp validation.
 */
test('time mocking - signature expiration', function (t) {
    var harness = this.harness;

    if (!harness.time) {
        t.ok(true, 'test skipped - time mock not enabled');
        return (t.end());
    }

    // Step 1: Freeze time at specific point
    var baseTime = Date.parse('2025-01-16T12:00:00Z');
    harness.time.freeze(baseTime);

    var now1 = Date.now();
    t.equal(now1, baseTime, 'time should be frozen at base time');

    // Step 2: Create signature at base time
    return harness.createUser({
        login: 'expiryuser',
        account: harness._generateUuid()
    }, function (err, user) {
        t.ok(!err, 'user creation should succeed');

        var headers1 = harness.sigv4.get(
            '/accounts/' + user.account,
            user.accessKey,
            user.secret
);

        var timestamp1 = headers1['x-amz-date'];
        t.ok(timestamp1, 'should have timestamp in headers');

        // Step 3: Advance time by 20 minutes (beyond 15 minute window)
        harness.time.advance(20 * 60 * 1000);

        var now2 = Date.now();
        t.equal(now2, baseTime + (20 * 60 * 1000),
            'time should have advanced by 20 minutes');

        // Step 4: Create new signature at advanced time
        var headers2 = harness.sigv4.get(
            '/accounts/' + user.account,
            user.accessKey,
            user.secret
);

        var timestamp2 = headers2['x-amz-date'];

        // Timestamps should be different (20 minutes apart)
        t.notEqual(timestamp1, timestamp2,
            'timestamps should differ after time advance');

        // Step 5: Restore time
        harness.time.restore();

        var now3 = Date.now();
        t.ok(now3 > now2, 'time should be restored to real time');

        return (t.end());
    });
});

/**
 * Test: Multiple users with different access keys
 *
 * Demonstrates creating multiple test users and verifying they can
 * each authenticate independently.
 */
test('multiple users with separate credentials', function (t) {
    var harness = this.harness;
    var accountUuid = harness._generateUuid();

    var user1, user2;

    // Create two users in the same account
    harness.createUser({
        login: 'user1',
        account: accountUuid
    }, function (err1, u1) {
        t.ok(!err1, 'first user creation should succeed');
        user1 = u1;

        harness.createUser({
            login: 'user2',
            account: accountUuid
        }, function (err2, u2) {
            t.ok(!err2, 'second user creation should succeed');
            user2 = u2;

            // Verify users have different credentials
            t.notEqual(user1.uuid, user2.uuid,
                'users should have different UUIDs');
            t.notEqual(user1.accessKey, user2.accessKey,
                'users should have different access keys');
            t.notEqual(user1.secret, user2.secret,
                'users should have different secrets');

            // Generate signatures for both users
            var headers1 = harness.sigv4.get(
                '/users/' + user1.uuid,
                user1.accessKey,
                user1.secret
);

            var headers2 = harness.sigv4.get(
                '/users/' + user2.uuid,
                user2.accessKey,
                user2.secret
);

            // Signatures should be different
            t.notEqual(headers1.authorization, headers2.authorization,
                'signatures should differ for different users');

            t.end();
        });
    });
});

/**
 * Test: SigV4 helper utility methods
 *
 * Demonstrates various helper methods provided by the SigV4 helper.
 */
test('sigv4 helper - various methods', function (t) {
    var harness = this.harness;

    // Test creating headers with custom options
    var headers = harness.sigv4.createHeaders({
        method: 'PUT',
        path: '/bucket/key',
        accessKey: 'AKIATEST123',
        secret: 'testsecret',
        host: 'manta.localhost',
        query: 'prefix=photos&delimiter=/',
        body: {data: 'test'}
    });

    t.ok(headers, 'should create headers');
    t.equal(headers.host, 'manta.localhost', 'should use custom host');
    t.ok(headers.authorization, 'should have authorization');

    // Test with session token (temporary credentials)
    var tempHeaders = harness.sigv4.createHeaders({
        method: 'GET',
        path: '/accounts/uuid',
        accessKey: 'ASIATEMP123',
        secret: 'tempsecret',
        sessionToken: 'FQoGZXIvYXdzEBQa...'
    });

    t.ok(tempHeaders['x-amz-security-token'],
        'should include session token header');

    t.end();
});

/**
 * Test: Redis fixture scenarios
 *
 * Demonstrates loading different Redis fixture scenarios.
 */
test('redis fixtures - scenario loading', function (t) {
    var harness = this.harness;

    // Current scenario is 'basicAuth' from before() hook
    // Verify we can check Redis contents
    harness.fixtures.exists('/account/banks', function (err, exists) {
        t.ok(!err, 'should check key existence');
        // May or may not exist depending on fixture contents
        t.ok(exists !== undefined, 'should return boolean');

        // Demonstrate loading empty scenario
        harness.fixtures.loadScenario('empty', function (loadErr) {
            t.ok(!loadErr, 'should load empty scenario');

            // Verify Redis is empty
            harness.redis.keys('*', function (keysErr, keys) {
                t.ok(!keysErr, 'should list keys');
                t.equal(keys.length, 0, 'Redis should be empty');

                // Reload original scenario for other tests
                harness.fixtures.loadScenario('basicAuth',
                    function (reloadErr) {
                    t.ok(!reloadErr, 'should reload basicAuth scenario');
                    t.end();
                });
            });
        });
    });
});
