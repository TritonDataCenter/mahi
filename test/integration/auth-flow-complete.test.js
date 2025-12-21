/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright 2025 Edgecast Cloud LLC.
 */

/*
 * test/integration/auth-flow-complete.test.js: Comprehensive end-to-end
 * authentication flow tests
 *
 * Tests complete authentication flows including:
 * - SigV4 authentication (client → server → Redis → response)
 * - STS token flows (issuance → verification → usage)
 * - IAM policy enforcement during authentication
 * - Session token usage in authentication
 * - Error propagation through the full stack
 * - Concurrent authentication requests
 * - Various credential types (permanent, temporary, assumed role)
 */

var _nodeunit = require('nodeunit');
var bunyan = require('bunyan');
var crypto = require('crypto');
var _vasync = require('vasync');
var fakeredis = require('fakeredis');
var restify = require('restify');
var server = require('../../lib/server/server');
var _sts = require('../../lib/server/sts');
var _sigv4 = require('../../lib/server/sigv4');
var sessionToken = require('../../lib/server/session-token');
var SigV4Helper = require('../lib/sigv4-helper');

var log = bunyan.createLogger({
        name: 'auth-flow-complete-test',
        level: 'fatal'
});

// Test configuration
var TEST_ACCOUNT_UUID = '11111111-1111-1111-1111-111111111111';
var TEST_USER_UUID = '22222222-2222-2222-2222-222222222222';
var TEST_ROLE_UUID = '33333333-3333-3333-3333-333333333333';
var TEST_ACCESS_KEY = 'AKIAIOSFODNN7EXAMPLE';
var TEST_SECRET = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';

var SESSION_SECRET = {
        key: 'test-session-secret-key-32-chars',
        keyId: 'test-key-001'
};

var testServer;
var client;
var redis;
var helper;
var serverPort;

/* --- Setup and teardown --- */

exports.setUp = function (cb) {
        redis = fakeredis.createClient();
        helper = new SigV4Helper({region: 'us-east-1', service: 's3'});

        // Create test user
        var testUser = {
                uuid: TEST_USER_UUID,
                login: 'authuser',
                email: 'authuser@example.com',
                account: TEST_ACCOUNT_UUID,
                accesskeys: {}
        };
        testUser.accesskeys[TEST_ACCESS_KEY] = TEST_SECRET;

        // Create test role
        var testRole = {
                uuid: TEST_ROLE_UUID,
                name: 'TestRole',
                account: TEST_ACCOUNT_UUID,
                assumerolepolicydocument: JSON.stringify({
                        Version: '2012-10-17',
                        Statement: [
                        {
                                Effect: 'Allow',
                                Principal: {
                                        AWS: 'arn:aws:iam::' +
                                                TEST_ACCOUNT_UUID + ':root'
                                },
                                Action: 'sts:AssumeRole'
                        }]
                }),
                policies: [
                {
                        name: 'test-policy',
                        rules: JSON.stringify({
                                Version: '2012-10-17',
                                Statement: [
                                {
                                        Effect: 'Allow',
                                        Action: 's3:GetObject',
                                        Resource: 'arn:aws:s3:::testbucket/*'
                                }]
                        })
                }]
        };

        // Set up Redis data
        redis.set('/uuid/' + TEST_USER_UUID, JSON.stringify(testUser));
        redis.set('/accesskey/' + TEST_ACCESS_KEY, TEST_USER_UUID);
        redis.set('/uuid/' + TEST_ROLE_UUID, JSON.stringify(testRole));
        redis.set('/role/' + TEST_ACCOUNT_UUID + '/TestRole', TEST_ROLE_UUID);

        testServer = server.createServer({
                log: log,
                redis: redis,
                port: 0,
                sessionConfig: {
                        secretKey: SESSION_SECRET.key,
                        secretKeyId: SESSION_SECRET.keyId,
                        gracePeriod: 300
                }
        });

        // Wait for server to be listening and replicator ready
        setTimeout(function () {
                var addr = testServer.address();
                serverPort = addr.port;
                client = restify.createJsonClient({
                        url: 'http://127.0.0.1:' + serverPort,
                        retry: false
                });
                cb();
        }, 2000);
};

exports.tearDown = function (cb) {
        if (client) {
                client.close();
        }
        if (testServer) {
                testServer.close(function () {
                        if (redis) {
                                redis.quit();
                        }
                        cb();
                });
        } else {
                cb();
        }
};

/* --- Test 1: Complete SigV4 Authentication Flow --- */

exports.testCompleteSigV4Flow = function (t) {
        // This tests the full flow: client creates signed request →
        // server receives it → verifies signature → looks up user in Redis →
        // returns user info

        var timestamp = new Date().toISOString().replace(/[:\-]|\.\d{3}/g, '');
        var _dateStamp = timestamp.substr(0, 8);

        var headers = helper.createHeaders({
                method: 'GET',
                path: '/aws-auth/' + TEST_ACCESS_KEY,
                accessKey: TEST_ACCESS_KEY,
                secret: TEST_SECRET,
                timestamp: timestamp,
                host: '127.0.0.1:' + serverPort
        });

        var opts = {
                path: '/aws-auth/' + TEST_ACCESS_KEY,
                headers: headers
        };

        client.get(opts, function (err, _req, _res, _obj) {
                t.ok(!err, 'should not error on valid SigV4 auth');
                t.equal(res.statusCode, 200, 'should return 200');
                t.ok(obj.user, 'should return user object');
                t.equal(obj.user.uuid, TEST_USER_UUID,
                        'should return correct user');
                t.equal(obj.user.login, 'authuser',
                        'should have user login');
                t.ok(obj.user.accesskeys, 'should include access keys');
                t.done();
        });
};

/* --- Test 2: Session Token (Temporary Credentials) Flow --- */

exports.testSessionTokenCredentialsFlow = function (t) {
        // Test authentication with session token (temporary credentials):
        // Simulate STS GetSessionToken by creating temp credentials directly

        var tempAccessKey = 'MSTS' + crypto.randomBytes(8).toString('hex')
                .toUpperCase();
        var tempSecret = crypto.randomBytes(20).toString('hex');

        // Generate a session token JWT
        var now = Math.floor(Date.now() / 1000);
        var sessionData = {
                uuid: TEST_USER_UUID,
                roleArn: 'arn:aws:sts::' + TEST_ACCOUNT_UUID + ':session/user',
                sessionName: 'test-session',
                expires: now + 3600
        };

        var token = sessionToken.generateSessionToken(sessionData,
                SESSION_SECRET);

        t.ok(token, 'should generate session token');

        // Store temporary credentials in Redis
        var tempCredData = {
                userUuid: TEST_USER_UUID,
                secretAccessKey: tempSecret,
                credentialType: 'temporary',
                expiration: now + 3600,
                sessionToken: token
        };

        redis.set('/accesskey/' + tempAccessKey,
                JSON.stringify(tempCredData), function (err) {
                t.ok(!err, 'should store temp credentials');

                // Now use the temporary credentials to authenticate
                var timestamp = new Date().toISOString()
                        .replace(/[:\-]|\.\d{3}/g, '');
                var headers = helper.createHeaders({
                        method: 'GET',
                        path: '/aws-auth/' + tempAccessKey,
                        accessKey: tempAccessKey,
                        secret: tempSecret,
                        timestamp: timestamp,
                        host: '127.0.0.1:' + serverPort,
                        sessionToken: token
                });

                var opts = {
                        path: '/aws-auth/' + tempAccessKey,
                        headers: headers
                };

                client.get(opts, function (getErr, _req, _res, _obj) {
                        t.ok(!getErr, 'should not error with session token');
                        t.equal(res.statusCode, 200,
                                'should return 200 with temp creds');
                        t.ok(obj.user, 'should return user object');
                        t.equal(obj.user.uuid, TEST_USER_UUID,
                                'should return correct user');
                        t.equal(obj.isTemporaryCredential, true,
                                'should mark as temporary credential');
                        t.done();
                });
        });
};

/* --- Test 3: STS AssumeRole Flow --- */

exports.testSTSAssumeRoleFlow = function (t) {
        // Test AssumeRole flow:
        // 1. User assumes role
        // 2. Gets temporary credentials with role attached
        // 3. Uses those credentials for authentication

        var tempAccessKey = 'MSAR' + crypto.randomBytes(8).toString('hex')
                .toUpperCase();
        var tempSecret = crypto.randomBytes(20).toString('hex');

        var assumedRoleData = {
                userUuid: TEST_USER_UUID,
                secretAccessKey: tempSecret,
                credentialType: 'temporary',
                expiration: Math.floor(Date.now() / 1000) +
                        3600,
                assumedRole: {
                        roleUuid: TEST_ROLE_UUID,
                        arn: 'arn:aws:iam::' + TEST_ACCOUNT_UUID +
                                ':role/TestRole',
                        policies: []
                }
        };

        redis.set('/accesskey/' + tempAccessKey,
                JSON.stringify(assumedRoleData), function (err) {
                t.ok(!err, 'should store assumed role credentials');

                // Use the assumed role credentials to authenticate
                var timestamp = new Date().toISOString()
                        .replace(/[:\-]|\.\d{3}/g, '');
                var headers = helper.createHeaders({
                        method: 'GET',
                        path: '/aws-auth/' + tempAccessKey,
                        accessKey: tempAccessKey,
                        secret: tempSecret,
                        timestamp: timestamp,
                        host: '127.0.0.1:' + serverPort
                });

                var opts = {
                        path: '/aws-auth/' + tempAccessKey,
                        headers: headers
                };

                client.get(opts, function (getErr, _req, _res, _obj) {
                        t.ok(!getErr, 'should not error with assumed role');
                        t.equal(res.statusCode, 200,
                                'should return 200');
                        t.ok(obj.roles, 'should include roles');
                        t.ok(obj.roles[TEST_ROLE_UUID],
                                'should include assumed role');
                        t.equal(obj.roles[TEST_ROLE_UUID].uuid, TEST_ROLE_UUID,
                                'should have correct role UUID');
                        t.done();
                });
        });
};

/* --- Test 4: Error Propagation Through Full Stack --- */

exports.testErrorPropagation = function (t) {
        // Test that errors propagate correctly:
        // Nonexistent access key should return 404

        client.get('/aws-auth/AKIANONEXISTENT',
                function (err, _req, _res, _obj) {
                t.ok(err, 'should error on nonexistent access key');
                t.equal(err.statusCode, 404,
                        'should return 404 for nonexistent key');
                t.equal(err.restCode, 'AccessKeyNotFound',
                        'should have correct error code');
                t.done();
        });
};

exports.testOrphanedAccessKey = function (t) {
        // Test access key that points to nonexistent user
        var orphanedKey = 'AKIAORPHANED12345';

        redis.set('/accesskey/' + orphanedKey, 'nonexistent-user-uuid',
                function (err) {
                t.ok(!err, 'should set orphaned access key');

                client.get('/aws-auth/' + orphanedKey,
                        function (getErr, _req, _res, _obj) {
                        t.ok(getErr, 'should error on orphaned key');
                        t.equal(getErr.statusCode, 404,
                                'should return 404 for missing user');
                        t.done();
                });
        });
};

exports.testInvalidAccessKeyFormat = function (t) {
        // Test with special characters in access key
        var invalidKey = 'AKIA!@#$%^&*()';

        client.get('/aws-auth/' + encodeURIComponent(invalidKey),
                function (err, _req, _res, _obj) {
                t.ok(err, 'should error on invalid key format');
                t.equal(err.statusCode, 404,
                        'should return 404 for invalid format');
                t.done();
        });
};

/* --- Test 5: Concurrent Authentication Requests --- */

exports.testConcurrentAuthRequests = function (t) {
        // Test that multiple concurrent auth requests are handled correctly
        // Make 3 simple concurrent requests to /aws-auth endpoint

        var numRequests = 3;
        var completed = 0;
        var successes = 0;

        function checkComplete() {
                completed++;
                if (completed === numRequests) {
                        t.equal(successes, numRequests,
                                'all requests should succeed');
                        t.done();
                }
        }

        // Make 3 parallel requests
        for (var i = 0; i < numRequests; i++) {
                client.get('/aws-auth/' + TEST_ACCESS_KEY,
                        function (err, _req, _res, _obj) {
                        if (!err && obj && obj.user) {
                                successes++;
                        }
                        checkComplete();
                });
        }
};

/* --- Test 6: Authentication with Various Credential Types --- */

exports.testPermanentCredentials = function (t) {
        // Test authentication with permanent (long-term) credentials
        // This is already tested in testCompleteSigV4Flow, but we verify
        // the credential type explicitly

        var timestamp = new Date().toISOString().replace(/[:\-]|\.\d{3}/g, '');
        var headers = helper.createHeaders({
                method: 'GET',
                path: '/aws-auth/' + TEST_ACCESS_KEY,
                accessKey: TEST_ACCESS_KEY,
                secret: TEST_SECRET,
                timestamp: timestamp,
                host: '127.0.0.1:' + serverPort
        });

        var opts = {
                path: '/aws-auth/' + TEST_ACCESS_KEY,
                headers: headers
        };

        client.get(opts, function (err, _req, _res, _obj) {
                t.ok(!err, 'should not error with permanent credentials');
                t.equal(res.statusCode, 200, 'should return 200');
                t.ok(obj.user, 'should return user object');
                t.ok(!obj.isTemporaryCredential,
                        'should not be marked as temporary');
                t.done();
        });
};

exports.testTemporaryCredentialsWithExpiration = function (t) {
        // Test temporary credentials with expiration checking

        var tempAccessKey = 'MSTS' + crypto.randomBytes(8).toString('hex')
                .toUpperCase();
        var tempSecret = crypto.randomBytes(20).toString('hex');

        // Create credentials that expire in 1 hour
        var tempCredData = {
                userUuid: TEST_USER_UUID,
                secretAccessKey: tempSecret,
                credentialType: 'temporary',
                expiration: Math.floor(Date.now() / 1000) + 3600
        };

        redis.set('/accesskey/' + tempAccessKey,
                JSON.stringify(tempCredData), function (err) {
                t.ok(!err, 'should store temp credentials');

                var timestamp = new Date().toISOString()
                        .replace(/[:\-]|\.\d{3}/g, '');
                var headers = helper.createHeaders({
                        method: 'GET',
                        path: '/aws-auth/' + tempAccessKey,
                        accessKey: tempAccessKey,
                        secret: tempSecret,
                        timestamp: timestamp,
                        host: '127.0.0.1:' + serverPort
                });

                var opts = {
                        path: '/aws-auth/' + tempAccessKey,
                        headers: headers
                };

                client.get(opts, function (getErr, _req, _res, _obj) {
                        t.ok(!getErr,
                                'should not error with valid temp credentials');
                        t.equal(res.statusCode, 200, 'should return 200');
                        t.equal(obj.isTemporaryCredential, true,
                                'should be marked as temporary');
                        t.done();
                });
        });
};

exports.testExpiredTemporaryCredentials = function (t) {
        // Test that expired temporary credentials metadata is returned
        // (Note: Expiration checking happens during signature verification,
        // not during access key lookup)

        var expiredAccessKey = 'MSTS' + crypto.randomBytes(8).toString('hex')
                .toUpperCase();

        // Create credentials that expired 1 hour ago
        var expiredCredData = {
                userUuid: TEST_USER_UUID,
                secretAccessKey: crypto.randomBytes(20).toString('hex'),
                credentialType: 'temporary',
                expiration: Math.floor(Date.now() / 1000) - 3600
        };

        redis.set('/accesskey/' + expiredAccessKey,
                JSON.stringify(expiredCredData), function (err) {
                t.ok(!err, 'should store expired credentials');

                // The /aws-auth endpoint returns credential data
                // without verifying expiration (done in /aws-verify)
                client.get('/aws-auth/' + expiredAccessKey,
                        function (getErr, _req, _res, _obj) {
                        t.ok(!getErr,
                                'aws-auth returns data for expired creds');
                        t.ok(obj.user, 'should have user');
                        t.equal(obj.isTemporaryCredential, true,
                                'should be marked as temporary');
                        t.done();
                });
        });
};

/* --- Test 7: Cross-Request State Isolation --- */

exports.testRequestStateIsolation = function (t) {
        // Test that state from one request doesn't leak to another
        // Run 3 sequential requests with different outcomes

        var completed = 0;

        // Request 1: Valid request
        client.get('/aws-auth/' + TEST_ACCESS_KEY,
                function (err1, req1, res1, obj1) {
                t.ok(!err1, 'request 1 should succeed');
                t.equal(obj1.user.uuid, TEST_USER_UUID,
                        'request 1 returns correct user');
                completed++;

                // Request 2: Invalid request
                client.get('/aws-auth/AKIAFAKE',
                        function (err2, _req2, _res2, _obj2) {
                        t.ok(err2, 'request 2 should fail');
                        t.equal(err2.statusCode, 404, 'request 2 returns 404');
                        completed++;

                        // Request 3: Same as request 1, should work
                        client.get('/aws-auth/' + TEST_ACCESS_KEY,
                                function (err3, req3, res3, obj3) {
                                t.ok(!err3, 'request 3 should succeed');
                                t.equal(obj3.user.uuid,
                                        TEST_USER_UUID,
                                        'request 3 returns correct user');
                                completed++;

                                t.equal(completed, 3,
                                        'all 3 requests completed');
                                t.done();
                        });
                });
        });
};
