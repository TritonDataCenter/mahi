/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright 2025 Edgecast Cloud LLC.
 */

/*
 * test/endpoint-aws-verify.test.js: Unit tests for /aws-verify endpoint
 */

var _nodeunit = require('nodeunit');
var restify = require('restify');
var http = require('http');
var bunyan = require('bunyan');
var fakeredis = require('fakeredis');
var server = require('../lib/server/server');
var SigV4Helper = require('./lib/sigv4-helper');
var sessionToken = require('../lib/server/session-token');

var log = bunyan.createLogger({
        name: 'endpoint-aws-verify-test',
        level: 'fatal'
});

var testServer;
var client;
var redis;
var helper;
var serverPort;

/* --- Setup and teardown --- */

exports.setUp = function (cb) {
        redis = fakeredis.createClient();
        helper = new SigV4Helper({region: 'us-east-1', service: 's3'});

        testServer = server.createServer({
                log: log,
                redis: redis,
                port: 0,
                sessionConfig: {
                        secretKey: 'test-session-secret-key-for-jwt-validation',
                        secretKeyId: 'test-key-001',
                        gracePeriod: 300
                }
        });

        // Wait for server to be listening and replicator to be ready
        setTimeout(function () {
                var addr = testServer.address();
                serverPort = addr.port;
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

/*
 * Helper function to make signed POST requests using raw http module
 * to ensure we have full control over headers and body.
 * Body should be a string (already JSON.stringified)
 */
function signedPost(path, bodyStr, headers, callback) {
        var options = {
                hostname: '127.0.0.1',
                port: serverPort,
                path: path,
                method: 'POST',
                headers: headers
        };

        var req = http.request(options, function (res) {
                var responseBody = '';

                res.on('data', function (chunk) {
                        responseBody += chunk;
                });

                res.on('end', function () {
                        var obj;
                        try {
                                obj = JSON.parse(responseBody);
                        } catch (_e) {
                                obj = responseBody;
                        }

                        if (res.statusCode >= 400) {
                                var err = new Error('HTTP ' + res.statusCode);
                                err.statusCode = res.statusCode;
                                err.body = obj;
                                return (callback(err, req, res, obj));
                        }

                        return callback(null, req, res, obj);
                });
        });

        req.on('error', function (err) {
                callback(err);
        });

        req.write(bodyStr);
        req.end();
}

/* --- Test valid signature verification --- */

exports.testValidSignatureVerification = function (t) {
        var testUserUuid = 'test-user-uuid-001';
        var testAccessKeyId = 'AKIATEST12345678';
        var testSecret = 'testsecret123456';

        var userData = {
                uuid: testUserUuid,
                login: 'testuser',
                email: 'test@example.com',
                account: 'test-account-uuid',
                accesskeys: {}
        };
        userData.accesskeys[testAccessKeyId] = testSecret;

        redis.set('/accesskey/' + testAccessKeyId, testUserUuid,
                function (err1) {
                t.ok(!err1, 'should set access key mapping');

                redis.set('/uuid/' + testUserUuid, JSON.stringify(userData),
                        function (err2) {
                        t.ok(!err2, 'should set user data');

                        var body = {};
                        var headers = helper.createHeaders({
                                method: 'POST',
                                path: '/aws-verify',
                                accessKey: testAccessKeyId,
                                secret: testSecret,
                                body: body,
                                host: '127.0.0.1:' + serverPort
                        });

                        var bodyStr = JSON.stringify(body);
                        signedPost('/aws-verify', bodyStr, headers,
                                function (err, _req, _res, _obj) {
                                t.ok(!err, 'should not error');
                                t.equal(res.statusCode, 200,
                                        'should return 200');
                                t.ok(obj, 'should return response object');
                                t.equal(obj.valid, true,
                                        'should verify as valid');
                                t.equal(obj.accessKeyId, testAccessKeyId,
                                        'should return access key ID');
                                t.equal(obj.userUuid, testUserUuid,
                                        'should return user UUID');
                                t.done();
                        });
                });
        });
};

/* --- Test invalid signature --- */

exports.testInvalidSignature = function (t) {
        var testUserUuid = 'test-user-uuid-002';
        var testAccessKeyId = 'AKIAINVALID12345';
        var testSecret = 'testsecret123456';
        var wrongSecret = 'wrongsecret99999';

        var userData = {
                uuid: testUserUuid,
                login: 'testuser',
                account: 'test-account-uuid',
                accesskeys: {}
        };
        userData.accesskeys[testAccessKeyId] = testSecret;

        redis.set('/accesskey/' + testAccessKeyId, testUserUuid,
                function (err1) {
                t.ok(!err1, 'should set access key mapping');

                redis.set('/uuid/' + testUserUuid, JSON.stringify(userData),
                        function (err2) {
                        t.ok(!err2, 'should set user data');

                        var body = {};
                        var headers = helper.createHeaders({
                                method: 'POST',
                                path: '/aws-verify',
                                accessKey: testAccessKeyId,
                                secret: wrongSecret,
                                body: body,
                                host: '127.0.0.1:' + serverPort
                        });

                        var bodyStr = JSON.stringify(body);
                        signedPost('/aws-verify', bodyStr, headers,
                                function (err, _req, _res, _obj) {
                                t.ok(err, 'should error on invalid signature');
                                t.equal(err.statusCode, 403,
                                        'should return 403 Forbidden');
                                t.done();
                        });
                });
        });
};

/* --- Test missing authorization header --- */

exports.testMissingAuthorizationHeader = function (t) {
        signedPost('/aws-verify', '{}', {}, function (err, _req, _res, _obj) {
                t.ok(err, 'should error without authorization');
                t.equal(err.statusCode, 403,
                        'should return 403 for missing authorization');
                t.ok(err.body, 'should have error body');
                t.equal(err.body.code, 'InvalidSignature',
                        'should return InvalidSignature error');
                t.done();
        });
};

/* --- Test nonexistent access key --- */

exports.testNonexistentAccessKey = function (t) {
        var testAccessKeyId = 'AKIANONEXIST9999';
        var testSecret = 'anysecret';

        var body = {};
        var headers = helper.createHeaders({
                method: 'POST',
                path: '/aws-verify',
                accessKey: testAccessKeyId,
                secret: testSecret,
                body: body,
                host: '127.0.0.1:' + serverPort
        });

        var bodyStr = JSON.stringify(body);
        signedPost('/aws-verify', bodyStr, headers,
                function (err, _req, _res, _obj) {
                t.ok(err, 'should error for nonexistent key');
                t.equal(err.statusCode, 403,
                        'should return 403 for invalid access key');
                t.ok(err.body, 'should have error body');
                t.equal(err.body.code, 'InvalidSignature',
                        'should return InvalidSignature error');
                t.done();
        });
};

/* --- Test with query parameters --- */

exports.testWithQueryParameters = function (t) {
        var testUserUuid = 'test-user-uuid-003';
        var testAccessKeyId = 'AKIAQUERY123456';
        var testSecret = 'querysecret1234';

        var userData = {
                uuid: testUserUuid,
                login: 'queryuser',
                account: 'query-account-uuid',
                accesskeys: {}
        };
        userData.accesskeys[testAccessKeyId] = testSecret;

        redis.set('/accesskey/' + testAccessKeyId, testUserUuid,
                function (err1) {
                t.ok(!err1, 'should set access key mapping');

                redis.set('/uuid/' + testUserUuid, JSON.stringify(userData),
                        function (err2) {
                        t.ok(!err2, 'should set user data');

                        var body = {};
                        var headers = helper.createHeaders({
                                method: 'POST',
                                path: '/aws-verify',
                                accessKey: testAccessKeyId,
                                secret: testSecret,
                                body: body,
                                host: '127.0.0.1:' + serverPort,
                                query: 'param1=value1&param2=value2'
                        });

                        var bodyStr = JSON.stringify(body);
                        var path = '/aws-verify?param1=value1&param2=value2';
                        signedPost(path, bodyStr, headers,
                                function (err, _req, _res, _obj) {
                                t.ok(!err,
                                        'should not error with query params');
                                t.equal(obj.valid, true,
                                        'should verify with query parameters');
                                t.done();
                        });
                });
        });
};

/* --- Test POST with body --- */

exports.testPostRequestWithBody = function (t) {
        var testUserUuid = 'test-user-uuid-004';
        var testAccessKeyId = 'AKIAPOST12345678';
        var testSecret = 'postsecret123456';

        var userData = {
                uuid: testUserUuid,
                login: 'postuser',
                account: 'post-account-uuid',
                accesskeys: {}
        };
        userData.accesskeys[testAccessKeyId] = testSecret;

        redis.set('/accesskey/' + testAccessKeyId, testUserUuid,
                function (err1) {
                t.ok(!err1, 'should set access key mapping');

                redis.set('/uuid/' + testUserUuid, JSON.stringify(userData),
                        function (err2) {
                        t.ok(!err2, 'should set user data');

                        var body = {key: 'value', test: 'data'};
                        var headers = helper.createHeaders({
                                method: 'POST',
                                path: '/aws-verify',
                                accessKey: testAccessKeyId,
                                secret: testSecret,
                                body: body,
                                host: '127.0.0.1:' + serverPort
                        });

                        var bodyStr = JSON.stringify(body);
                        signedPost('/aws-verify', bodyStr, headers,
                                function (err, _req, _res, _obj) {
                                t.ok(!err,
                                        'should not error for POST with body');
                                t.equal(obj.valid, true,
                                        'should verify POST with body');
                                t.done();
                        });
                });
        });
};

/* --- Test temporary credentials --- */

exports.testTemporaryCredentials = function (t) {
        var testUserUuid = 'test-user-uuid-005';
        var testAccessKeyId = 'MSTS1234567890ABCDEF';
        var testSecret = 'tempsecret123456';

        var sessionData = {
                uuid: testUserUuid,
                roleArn: 'arn:aws:iam::123456789012:role/TestRole',
                sessionName: 'test-session',
                expires: Math.floor(Date.now() / 1000) + 3600
        };

        var secretKey = {
                key: 'test-session-secret-key-for-jwt-validation',
                keyId: 'test-key-001'
        };

        var jwtToken = sessionToken.generateSessionToken(sessionData,
                secretKey, {});

        var tempCredData = {
                userUuid: testUserUuid,
                secretAccessKey: testSecret,
                credentialType: 'temporary',
                expiration: Date.now() + (3600 * 1000)
        };

        var userData = {
                uuid: testUserUuid,
                login: 'tempuser',
                account: 'temp-account-uuid',
                accesskeys: {}
        };

        redis.set('/accesskey/' + testAccessKeyId,
                JSON.stringify(tempCredData), function (err1) {
                t.ok(!err1, 'should set temp credential mapping');

                redis.set('/uuid/' + testUserUuid, JSON.stringify(userData),
                        function (err2) {
                        t.ok(!err2, 'should set user data');

                        var body = {};
                        var headers = helper.createHeaders({
                                method: 'POST',
                                path: '/aws-verify',
                                accessKey: testAccessKeyId,
                                secret: testSecret,
                                body: body,
                                host: '127.0.0.1:' + serverPort,
                                sessionToken: jwtToken
                        });

                        var bodyStr = JSON.stringify(body);
                        signedPost('/aws-verify', bodyStr, headers,
                                function (err, _req, _res, _obj) {
                                t.ok(!err, 'should not error for temp creds');
                                t.equal(obj.valid, true,
                                        'should verify temporary credentials');
                                t.equal(obj.isTemporaryCredential, true,
                                        'should mark as temporary credential');
                                t.done();
                        });
                });
        });
};

/* --- Test expired timestamp --- */

exports.testExpiredTimestamp = function (t) {
        var testUserUuid = 'test-user-uuid-006';
        var testAccessKeyId = 'AKIAEXPIRED12345';
        var testSecret = 'expiredsecret123';

        var userData = {
                uuid: testUserUuid,
                login: 'expireduser',
                account: 'expired-account-uuid',
                accesskeys: {}
        };
        userData.accesskeys[testAccessKeyId] = testSecret;

        redis.set('/accesskey/' + testAccessKeyId, testUserUuid,
                function (err1) {
                t.ok(!err1, 'should set access key mapping');

                redis.set('/uuid/' + testUserUuid, JSON.stringify(userData),
                        function (err2) {
                        t.ok(!err2, 'should set user data');

                        var oldDate = new Date(Date.now() - (30 * 60 * 1000));
                        var timestamp = oldDate.toISOString()
                                .replace(/[:-]|\.\d{3}/g, '');

                        var body = {};
                        var headers = helper.createHeaders({
                                method: 'POST',
                                path: '/aws-verify',
                                accessKey: testAccessKeyId,
                                secret: testSecret,
                                body: body,
                                host: '127.0.0.1:' + serverPort,
                                timestamp: timestamp
                        });

                        var bodyStr = JSON.stringify(body);
                        signedPost('/aws-verify', bodyStr, headers,
                                function (err, _req, _res, _obj) {
                                t.ok(err, 'should error for expired timestamp');
                                t.equal(err.statusCode, 403,
                                        'should return 403 for expired');
                                t.ok(err.body, 'should have error body');
                                t.equal(err.body.code, 'InvalidSignature',
                                        'should return InvalidSignature error');
                                t.done();
                        });
                });
        });
};
