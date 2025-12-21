/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright 2025 Edgecast Cloud LLC.
 */

/*
 * test/endpoint-aws-auth.test.js: Unit tests for /aws-auth/:accesskeyid
 * endpoint
 */

var nodeunit = require('nodeunit');
var restify = require('restify');
var bunyan = require('bunyan');
var fakeredis = require('fakeredis');
var server = require('../lib/server/server');

var log = bunyan.createLogger({
        name: 'endpoint-aws-auth-test',
        level: 'fatal'
});

var testServer;
var client;
var redis;

/* --- Setup and teardown --- */

exports.setUp = function (cb) {
        redis = fakeredis.createClient();

        testServer = server.createServer({
                log: log,
                redis: redis,
                port: 0
        });

        // Wait for server to be listening and replicator to be ready
        setTimeout(function () {
                var addr = testServer.address();
                client = restify.createJsonClient({
                        url: 'http://127.0.0.1:' + addr.port,
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

/* --- Test valid access key lookup --- */

exports.testGetUserByValidAccessKey = function (t) {
        var testUserUuid = 'test-user-uuid-001';
        var testAccessKeyId = 'AKIATEST12345678';

        // Setup Redis data
        redis.set('/accesskey/' + testAccessKeyId, testUserUuid,
                function (err1) {
                t.ok(!err1, 'should set access key mapping');

                var userData = {
                        uuid: testUserUuid,
                        login: 'testuser',
                        email: 'test@example.com',
                        account: 'test-account-uuid',
                        accesskeys: {}
                };
                userData.accesskeys[testAccessKeyId] = 'secret123';

                redis.set('/uuid/' + testUserUuid, JSON.stringify(userData),
                        function (err2) {
                        t.ok(!err2, 'should set user data');

                        client.get('/aws-auth/' + testAccessKeyId,
                                function (err, req, res, obj) {
                                t.ok(!err, 'should not error');
                                t.equal(res.statusCode, 200,
                                'should return 200');
                                t.ok(obj, 'should return response object');
                                t.ok(obj.user, 'should have user object');
                                t.equal(obj.user.uuid, testUserUuid,
                                        'should return correct user UUID');
                                t.equal(obj.user.login, 'testuser',
                                        'should return user login');
                                t.equal(obj.user.email, 'test@example.com',
                                        'should return user email');
                                t.ok(obj.user.accesskeys,
                                'should include access keys');
                                t.done();
                        });
                });
        });
};

/* --- Test user information retrieval --- */

exports.testUserInformationFields = function (t) {
        var testUserUuid = 'test-user-uuid-002';
        var testAccessKeyId = 'AKIATEST87654321';

        redis.set('/accesskey/' + testAccessKeyId, testUserUuid,
                function (err1) {
                t.ok(!err1, 'should set access key mapping');

                var userData = {
                        uuid: testUserUuid,
                        login: 'alice',
                        email: 'alice@example.com',
                        account: 'alice-account-uuid',
                        cn: 'Alice Smith',
                        accesskeys: {}
                };
                userData.accesskeys[testAccessKeyId] = 'alicesecret';

                redis.set('/uuid/' + testUserUuid, JSON.stringify(userData),
                        function (err2) {
                        t.ok(!err2, 'should set user data');

                        client.get('/aws-auth/' + testAccessKeyId,
                                function (err, req, res, obj) {
                                t.ok(!err, 'should not error');
                                t.ok(obj.user, 'should have user object');
                                t.ok(obj.user.uuid, 'should have uuid field');
                                t.ok(obj.user.login, 'should have login field');
                                t.ok(obj.user.email, 'should have email field');
                                t.ok(obj.user.account,
                                'should have account field');
                                t.equal(obj.user.cn, 'Alice Smith',
                                        'should have cn field');
                                t.done();
                        });
                });
        });
};

/* --- Test nonexistent access key (404) --- */

exports.testNonexistentAccessKey = function (t) {
        var nonexistentKey = 'AKIANONEXISTENT123';

        client.get('/aws-auth/' + nonexistentKey,
                function (err, req, res, obj) {
                t.ok(err, 'should error');
                t.equal(err.statusCode, 404,
                        'should return 404 for nonexistent key');
                t.equal(err.restCode, 'AccessKeyNotFound',
                        'should return AccessKeyNotFound error');
                t.done();
        });
};

exports.testAccessKeyWithoutUserData = function (t) {
        var testAccessKeyId = 'AKIAORPHANED12345';
        var orphanedUserUuid = 'orphaned-user-uuid';

        redis.set('/accesskey/' + testAccessKeyId, orphanedUserUuid,
                function (err1) {
                t.ok(!err1, 'should set access key mapping');

                client.get('/aws-auth/' + testAccessKeyId,
                        function (err, req, res, obj) {
                        t.ok(err, 'should error when user data missing');
                        t.equal(err.statusCode, 404,
                                'should return 404 when user not found');
                        t.done();
                });
        });
};

/* --- Test response format validation --- */

exports.testResponseFormat = function (t) {
        var testUserUuid = 'test-user-uuid-003';
        var testAccessKeyId = 'AKIAFORMAT123456';

        redis.set('/accesskey/' + testAccessKeyId, testUserUuid,
                function (err1) {
                t.ok(!err1, 'should set access key mapping');

                var userData = {
                        uuid: testUserUuid,
                        login: 'formattest',
                        email: 'format@example.com',
                        account: 'format-account-uuid',
                        accesskeys: {}
                };
                userData.accesskeys[testAccessKeyId] = 'formatsecret';

                redis.set('/uuid/' + testUserUuid, JSON.stringify(userData),
                        function (err2) {
                        t.ok(!err2, 'should set user data');

                        client.get('/aws-auth/' + testAccessKeyId,
                                function (err, req, res, obj) {
                                t.ok(!err, 'should not error');
                                t.equal(typeof (obj), 'object',
                                        'should return object');
                                t.ok(obj.user, 'should have user object');
                                t.equal(typeof (obj.user.uuid), 'string',
                                        'uuid should be string');
                                t.equal(typeof (obj.user.login), 'string',
                                        'login should be string');
                                t.equal(typeof (obj.user.accesskeys), 'object',
                                        'accesskeys should be object');
                                t.done();
                        });
                });
        });
};

/* --- Test temporary credentials (MSTS prefix) --- */

exports.testTemporaryCredentialMSTS = function (t) {
        var testUserUuid = 'test-user-uuid-004';
        var testAccessKeyId = 'MSTS1234567890ABCDEF';

        var tempCredData = {
                userUuid: testUserUuid,
                secretAccessKey: 'tempsecret123',
                credentialType: 'temporary',
                expiration: Math.floor(Date.now() / 1000) + 3600
        };

        redis.set('/accesskey/' + testAccessKeyId,
                JSON.stringify(tempCredData), function (err1) {
                t.ok(!err1, 'should set temp credential mapping');

                var userData = {
                        uuid: testUserUuid,
                        login: 'tempuser',
                        email: 'temp@example.com',
                        account: 'temp-account-uuid',
                        accesskeys: {}
                };

                redis.set('/uuid/' + testUserUuid, JSON.stringify(userData),
                        function (err2) {
                        t.ok(!err2, 'should set user data');

                        client.get('/aws-auth/' + testAccessKeyId,
                                function (err, req, res, obj) {
                                t.ok(!err, 'should not error');
                                t.equal(res.statusCode, 200,
                                'should return 200');
                                t.ok(obj.user, 'should have user object');
                                t.equal(obj.user.uuid, testUserUuid,
                                        'should return correct user');
                                t.equal(obj.isTemporaryCredential, true,
                                        'should mark as temporary credential');
                                t.ok(obj.user.accesskeys[testAccessKeyId],
                                        'should inject temp credential');
                                t.done();
                        });
                });
        });
};

/* --- Test assumed role credentials (MSAR prefix) --- */

exports.testAssumedRoleCredentialMSAR = function (t) {
        var testUserUuid = 'test-user-uuid-005';
        var testAccessKeyId = 'MSAR1234567890ABCDEF';
        var roleUuid = 'assumed-role-uuid-001';

        var tempCredData = {
                userUuid: testUserUuid,
                secretAccessKey: 'assumerolesecret',
                credentialType: 'temporary',
                expiration: Math.floor(Date.now() / 1000) + 3600,
                assumedRole: {
                        roleUuid: roleUuid,
                        arn: 'arn:aws:iam::123456789012:role/TestRole',
                        policies: []
                }
        };

        redis.set('/accesskey/' + testAccessKeyId,
                JSON.stringify(tempCredData), function (err1) {
                t.ok(!err1, 'should set assumed role credential mapping');

                var userData = {
                        uuid: testUserUuid,
                        login: 'roleuser',
                        email: 'role@example.com',
                        account: 'role-account-uuid',
                        accesskeys: {}
                };

                redis.set('/uuid/' + testUserUuid, JSON.stringify(userData),
                        function (err2) {
                        t.ok(!err2, 'should set user data');

                        client.get('/aws-auth/' + testAccessKeyId,
                                function (err, req, res, obj) {
                                t.ok(!err, 'should not error');
                                t.equal(res.statusCode, 200,
                                'should return 200');
                                t.ok(obj.roles, 'should include roles');
                                t.ok(obj.roles[roleUuid],
                                        'should include assumed role');
                                t.equal(obj.roles[roleUuid].uuid, roleUuid,
                                        'should have correct role UUID');
                                t.done();
                        });
                });
        });
};

/* --- Test error handling --- */

exports.testRedisConnectionError = function (t) {
        var brokenRedis = fakeredis.createClient();
        brokenRedis.get = function (key, cb) {
                cb(new Error('Redis connection failed'));
        };

        var s = server.createServer({
                log: log,
                redis: brokenRedis,
                port: 0
        });

        var addr = s.address();
        var errorClient = restify.createJsonClient({
                url: 'http://127.0.0.1:' + addr.port,
                retry: false
        });

        errorClient.get('/aws-auth/AKIATEST',
                function (getErr, req, res, obj) {
                t.ok(getErr, 'should error on Redis failure');
                t.equal(getErr.statusCode, 503,
                        'should return 503 on service unavailable');

                errorClient.close();
                s.close(function () {
                        brokenRedis.quit();
                        t.done();
                });
        });
};

exports.testInvalidJSONInRedis = function (t) {
        var testAccessKeyId = 'MSTSINVALID12345';

        redis.set('/accesskey/' + testAccessKeyId, '{invalid json}',
                function (err1) {
                t.ok(!err1, 'should set invalid JSON');

                client.get('/aws-auth/' + testAccessKeyId,
                        function (err, req, res, obj) {
                        t.ok(err, 'should error on invalid JSON');
                        t.done();
                });
        });
};

exports.testEmptyAccessKeyId = function (t) {
        client.get('/aws-auth/', function (err, req, res, obj) {
                t.ok(err, 'should error on empty access key ID');
                t.equal(err.statusCode, 404,
                        'should return 404 for empty key');
                t.done();
        });
};

exports.testSpecialCharactersInAccessKeyId = function (t) {
        var specialKey = 'AKIA!@#$%^&*()';

        client.get('/aws-auth/' + encodeURIComponent(specialKey),
                function (err, req, res, obj) {
                t.ok(err, 'should error on special characters');
                t.equal(err.statusCode, 404,
                        'should return 404 for invalid key format');
                t.done();
        });
};
