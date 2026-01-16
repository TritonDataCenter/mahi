/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright 2026 Edgecast Cloud LLC.
 */

/*
 * test/s3-auth-endpoints.test.js: Additional tests for S3 auth endpoints
 * to improve branch coverage per CHG-047.
 *
 * Focus areas:
 * - Temporary credential handling (MSTS/MSAR prefixes)
 * - Error response structure validation
 * - Edge cases in access key lookup
 * - Response field validation
 */

var nodeunit = require('nodeunit');
var restify = require('restify');
var http = require('http');
var bunyan = require('bunyan');
var crypto = require('crypto');
var fakeredis = require('fakeredis');
var server = require('../lib/server/server');
var SigV4Helper = require('./lib/sigv4-helper');

var log = bunyan.createLogger({
    name: 's3-auth-endpoints-test',
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
            secretKey: 'test-session-secret-key-for-endpoints',
            secretKeyId: 'test-key-endpoints-001',
            gracePeriod: 300
        }
    });

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
 * Helper function for raw HTTP requests
 */
function rawRequest(method, path, headers, bodyStr, callback) {
    var options = {
        hostname: '127.0.0.1',
        port: serverPort,
        path: path,
        method: method,
        headers: headers || {}
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

            callback(null, res, obj);
        });
    });

    req.on('error', function (err) {
        callback(err);
    });

    if (bodyStr) {
        req.write(bodyStr);
    }
    req.end();
}

/*
 * ==============================
 * SECTION 1: MSTS Prefix Access Key Tests (GetSessionToken credentials)
 */

exports.testMSTSPrefixAccessKeyLookup = function (t) {
    var testUserUuid = 'msts-test-user-uuid-001';
    var testAccessKeyId = 'MSTS1234567890123456';
    var testSecret = 'msts-secret-123';

    var userData = {
        uuid: testUserUuid,
        login: 'mststestuser',
        email: 'msts@example.com',
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

            client.get('/aws-auth/' + testAccessKeyId,
                function (err, req, res, obj) {
                t.ok(!err, 'should not error for MSTS prefix key');
                t.equal(res.statusCode, 200, 'should return 200');
                t.ok(obj.user, 'should have user object');
                t.equal(obj.user.uuid, testUserUuid,
                    'should return correct user');
                t.done();
            });
        });
    });
};

/*
 * ==============================
 * SECTION 2: MSAR Prefix Access Key Tests (AssumeRole credentials)
 */

exports.testMSARPrefixAccessKeyLookup = function (t) {
    var testUserUuid = 'msar-test-user-uuid-001';
    var testAccessKeyId = 'MSAR1234567890123456';
    var testSecret = 'msar-secret-123';

    var userData = {
        uuid: testUserUuid,
        login: 'msartestuser',
        email: 'msar@example.com',
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

            client.get('/aws-auth/' + testAccessKeyId,
                function (err, req, res, obj) {
                t.ok(!err, 'should not error for MSAR prefix key');
                t.equal(res.statusCode, 200, 'should return 200');
                t.ok(obj.user, 'should have user object');
                t.equal(obj.user.uuid, testUserUuid,
                    'should return correct user');
                t.done();
            });
        });
    });
};

/*
 * ==============================
 * SECTION 3: Access Key Format Edge Cases
 */

exports.testShortAccessKeyId = function (t) {
    // Access key IDs shorter than normal should still work if in Redis
    var testUserUuid = 'short-key-user-uuid';
    var testAccessKeyId = 'SHORTKEY123'; // 11 chars

    var userData = {
        uuid: testUserUuid,
        login: 'shortkeyuser',
        accesskeys: {}
    };
    userData.accesskeys[testAccessKeyId] = 'shortsecret';

    redis.set('/accesskey/' + testAccessKeyId, testUserUuid,
        function (err1) {
        t.ok(!err1, 'should set short access key mapping');

        redis.set('/uuid/' + testUserUuid, JSON.stringify(userData),
            function (err2) {
            t.ok(!err2, 'should set user data');

            client.get('/aws-auth/' + testAccessKeyId,
                function (err, req, res, obj) {
                t.ok(!err, 'should not error for short access key');
                t.equal(res.statusCode, 200, 'should return 200');
                t.done();
            });
        });
    });
};

exports.testVeryLongAccessKeyId = function (t) {
    var testUserUuid = 'long-key-user-uuid';
    // 128 character access key (maximum allowed)
    var testAccessKeyId = new Array(129).join('A');

    var userData = {
        uuid: testUserUuid,
        login: 'longkeyuser',
        accesskeys: {}
    };
    userData.accesskeys[testAccessKeyId] = 'longsecret';

    redis.set('/accesskey/' + testAccessKeyId, testUserUuid,
        function (err1) {
        t.ok(!err1, 'should set long access key mapping');

        redis.set('/uuid/' + testUserUuid, JSON.stringify(userData),
            function (err2) {
            t.ok(!err2, 'should set user data');

            client.get('/aws-auth/' + testAccessKeyId,
                function (err, req, res, obj) {
                t.ok(!err, 'should not error for long access key');
                t.equal(res.statusCode, 200, 'should return 200');
                t.done();
            });
        });
    });
};

/*
 * ==============================
 * SECTION 4: Error Response Structure Tests
 */

exports.testNotFoundErrorStructure = function (t) {
    var nonExistentKey = 'AKIANOTFOUND123456';

    client.get('/aws-auth/' + nonExistentKey,
        function (err, req, res, obj) {
        t.ok(err, 'should return error for non-existent key');
        t.equal(res.statusCode, 404, 'should return 404');
        t.ok(obj, 'should have response body');
        // Check error structure
        if (obj.code) {
            t.ok(typeof (obj.code) === 'string', 'error should have code');
        }
        if (obj.message) {
            t.ok(typeof (obj.message) === 'string',
                'error should have message');
        }
        t.done();
    });
};

exports.testEmptyAccessKeyId = function (t) {
    // Empty access key in path - should return 404 or redirect
    rawRequest('GET', '/aws-auth/', {}, null, function (err, res, obj) {
        t.ok(!err, 'request should complete');
        // Empty parameter might result in 404 or different route matching
        t.ok(res.statusCode === 404 || res.statusCode === 405 ||
             res.statusCode === 400,
            'should return error status for empty access key');
        t.done();
    });
};

/*
 * ==============================
 * SECTION 5: Response Field Validation
 */

exports.testResponseContainsRequiredFields = function (t) {
    var testUserUuid = 'fields-test-user-uuid';
    var testAccessKeyId = 'AKIAFIELDSTEST12';
    var testAccountUuid = 'fields-test-account-uuid';

    var userData = {
        uuid: testUserUuid,
        login: 'fieldsuser',
        email: 'fields@example.com',
        account: testAccountUuid,
        cn: 'Fields Test User',
        accesskeys: {}
    };
    userData.accesskeys[testAccessKeyId] = 'fieldssecret';

    redis.set('/accesskey/' + testAccessKeyId, testUserUuid,
        function (err1) {
        t.ok(!err1, 'should set access key mapping');

        redis.set('/uuid/' + testUserUuid, JSON.stringify(userData),
            function (err2) {
            t.ok(!err2, 'should set user data');

            client.get('/aws-auth/' + testAccessKeyId,
                function (err, req, res, obj) {
                t.ok(!err, 'should not error');
                t.ok(obj, 'should have response');

                // Check user object fields
                t.ok(obj.user, 'response should have user');
                t.ok(obj.user.uuid, 'user should have uuid');
                t.ok(obj.user.login, 'user should have login');
                t.ok(obj.user.accesskeys, 'user should have accesskeys');

                // Verify field values
                t.equal(obj.user.uuid, testUserUuid, 'uuid should match');
                t.equal(obj.user.login, 'fieldsuser', 'login should match');
                t.done();
            });
        });
    });
};

exports.testResponseAccessKeysIncludesRequestedKey = function (t) {
    var testUserUuid = 'keys-test-user-uuid';
    var testAccessKeyId = 'AKIAKEYSTEST1234';
    var testAccessKeyId2 = 'AKIAKEYSTEST5678';

    var userData = {
        uuid: testUserUuid,
        login: 'keystestuser',
        accesskeys: {}
    };
    userData.accesskeys[testAccessKeyId] = 'secret1';
    userData.accesskeys[testAccessKeyId2] = 'secret2';

    redis.set('/accesskey/' + testAccessKeyId, testUserUuid,
        function (err1) {
        t.ok(!err1, 'should set access key mapping');

        redis.set('/uuid/' + testUserUuid, JSON.stringify(userData),
            function (err2) {
            t.ok(!err2, 'should set user data');

            client.get('/aws-auth/' + testAccessKeyId,
                function (err, req, res, obj) {
                t.ok(!err, 'should not error');
                t.ok(obj.user.accesskeys, 'should have accesskeys');

                // Verify the requested key is in the response
                t.ok(obj.user.accesskeys[testAccessKeyId],
                    'response should include requested key');
                t.done();
            });
        });
    });
};

/*
 * ==============================
 * SECTION 6: User Data Edge Cases
 */

exports.testUserWithMinimalData = function (t) {
    var testUserUuid = 'minimal-user-uuid';
    var testAccessKeyId = 'AKIAMINIMAL12345';

    // Minimal user data - just uuid and accesskeys
    var userData = {
        uuid: testUserUuid,
        accesskeys: {}
    };
    userData.accesskeys[testAccessKeyId] = 'minimalsecret';

    redis.set('/accesskey/' + testAccessKeyId, testUserUuid,
        function (err1) {
        t.ok(!err1, 'should set access key mapping');

        redis.set('/uuid/' + testUserUuid, JSON.stringify(userData),
            function (err2) {
            t.ok(!err2, 'should set user data');

            client.get('/aws-auth/' + testAccessKeyId,
                function (err, req, res, obj) {
                t.ok(!err, 'should not error for minimal user');
                t.equal(res.statusCode, 200, 'should return 200');
                t.ok(obj.user, 'should have user object');
                t.equal(obj.user.uuid, testUserUuid, 'uuid should match');
                t.done();
            });
        });
    });
};

exports.testUserWithSpecialCharsInLogin = function (t) {
    var testUserUuid = 'special-login-user-uuid';
    var testAccessKeyId = 'AKIASPECIALLOG12';

    var userData = {
        uuid: testUserUuid,
        login: 'user.name+tag@domain',
        email: 'special@example.com',
        accesskeys: {}
    };
    userData.accesskeys[testAccessKeyId] = 'specialsecret';

    redis.set('/accesskey/' + testAccessKeyId, testUserUuid,
        function (err1) {
        t.ok(!err1, 'should set access key mapping');

        redis.set('/uuid/' + testUserUuid, JSON.stringify(userData),
            function (err2) {
            t.ok(!err2, 'should set user data');

            client.get('/aws-auth/' + testAccessKeyId,
                function (err, req, res, obj) {
                t.ok(!err, 'should not error');
                t.equal(obj.user.login, 'user.name+tag@domain',
                    'should preserve special chars in login');
                t.done();
            });
        });
    });
};

/*
 * ==============================
 * SECTION 7: /aws-verify Endpoint Edge Cases
 */

exports.testAwsVerifyMissingBody = function (t) {
    var headers = {
        'content-type': 'application/json'
    };

    rawRequest('POST', '/aws-verify', headers, '',
        function (err, res, obj) {
        t.ok(!err, 'request should complete');
        // Missing body should result in error
        t.ok(res.statusCode >= 400,
            'should return error status for missing body');
        t.done();
    });
};

exports.testAwsVerifyMissingAuthHeader = function (t) {
    var headers = {
        'content-type': 'application/json',
        'host': 'localhost'
    };

    rawRequest('POST', '/aws-verify', headers, '{}',
        function (err, res, obj) {
        t.ok(!err, 'request should complete');
        // Missing Authorization header should be rejected
        t.ok(res.statusCode >= 400,
            'should return error for missing auth header');
        t.done();
    });
};

exports.testAwsVerifyInvalidAuthFormat = function (t) {
    var headers = {
        'content-type': 'application/json',
        'host': 'localhost',
        'authorization': 'InvalidFormat not-sigv4'
    };

    rawRequest('POST', '/aws-verify', headers, '{}',
        function (err, res, obj) {
        t.ok(!err, 'request should complete');
        t.ok(res.statusCode >= 400,
            'should return error for invalid auth format');
        t.done();
    });
};

/*
 * ==============================
 * SECTION 8: Concurrent Access Tests
 */

exports.testConcurrentAccessKeyLookups = function (t) {
    var testUserUuid = 'concurrent-user-uuid';
    var testAccessKeyId = 'AKIACONCURRENT12';

    var userData = {
        uuid: testUserUuid,
        login: 'concurrentuser',
        accesskeys: {}
    };
    userData.accesskeys[testAccessKeyId] = 'concurrentsecret';

    redis.set('/accesskey/' + testAccessKeyId, testUserUuid,
        function (err1) {
        t.ok(!err1, 'should set access key mapping');

        redis.set('/uuid/' + testUserUuid, JSON.stringify(userData),
            function (err2) {
            t.ok(!err2, 'should set user data');

            var completed = 0;
            var totalRequests = 5;
            var errors = [];

            function checkDone() {
                completed++;
                if (completed === totalRequests) {
                    t.equal(errors.length, 0,
                        'all concurrent requests should succeed');
                    t.done();
                }
            }

            // Make multiple concurrent requests
            for (var i = 0; i < totalRequests; i++) {
                client.get('/aws-auth/' + testAccessKeyId,
                    function (err, req, res, obj) {
                    if (err) {
                        errors.push(err);
                    } else if (res.statusCode !== 200) {
                        errors.push(new Error('Status: ' + res.statusCode));
                    }
                    checkDone();
                });
            }
        });
    });
};

console.log('✓ S3 auth endpoint tests loaded');
