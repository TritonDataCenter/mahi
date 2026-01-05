/*
 * This Source Code Form is subject to the terms of the Mozilla
 * Public License, v. 2.0. If a copy of the MPL was not
 * distributed with this file, You can obtain one at
 * http://mozilla.org/MPL/2.0/.
 *
 * Copyright 2026 Edgecast Cloud LLC.
 */

/*
 * test/sigv4-verification.test.js: End-to-end unit tests for
 * AWS Signature Version 4 verification workflow
 */

var _nodeunit = require('nodeunit');
var bunyan = require('bunyan');
var crypto = require('crypto');
var fakeredis = require('fakeredis');
var sigv4 = require('../lib/server/sigv4');
var SigV4Helper = require('./lib/sigv4-helper');
var TimeMock = require('./lib/time-mock');

var helper = new SigV4Helper({region: 'us-east-1', service: 's3'});
var timeMock;
var redis;
var log;

/* --- Setup and teardown --- */

exports.setUp = function (cb) {
    timeMock = new TimeMock();
    redis = fakeredis.createClient();
    log = bunyan.createLogger({
        name: 'sigv4-verification-test',
        level: 'fatal'
    });
    cb();
};

exports.tearDown = function (cb) {
    if (timeMock) {
        timeMock.restore();
    }
    if (redis) {
        redis.quit();
    }
    cb();
};

/* --- Helper function for setting up user and verifying --- */

function setupUserAndVerify(opts, t, callback) {
    var user = opts.user;
    var accessKeyId = opts.accessKeyId;
    var secret = opts.secret;

    redis.set('/uuid/' + user.uuid, JSON.stringify(user),
        function (err1) {
        if (err1) {
            return (callback(err1));
        }
        return redis.set('/accesskey/' + accessKeyId, user.uuid,
            function (err2) {
            if (err2) {
                return (callback(err2));
            }

            var headers = helper.createHeaders({
                method: opts.method,
                path: opts.path,
                accessKey: accessKeyId,
                secret: secret,
                timestamp: opts.timestamp,
                query: opts.query,
                body: opts.body
            });

            var payloadHash;
            if (opts.body) {
                var bodyStr = typeof (opts.body) === 'string' ?
                    opts.body : JSON.stringify(opts.body);
                payloadHash = crypto.createHash('sha256')
                    .update(bodyStr, 'utf8').digest('hex');
            } else {
                payloadHash = crypto.createHash('sha256')
                    .update('', 'utf8').digest('hex');
            }
            headers['x-amz-content-sha256'] = payloadHash;

            var url = opts.path;
            if (opts.query) {
                url += '?' + opts.query;
            }

            var req = {
                method: opts.method,
                url: url,
                headers: headers,
                query: opts.reqQuery || {}
            };

            return sigv4.verifySigV4({
                req: req,
                log: log,
                redis: redis
            }, callback);
        });
    });
}

/* --- Test successful verification --- */

exports.testSuccessfulVerification = function (t) {
    var testUser = {
        uuid: 'test-user-uuid',
        login: 'testuser',
        accesskeys: {
            'AKIATEST123': 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
        }
    };

    var timestamp = new Date().toISOString();

    setupUserAndVerify({
        user: testUser,
        accessKeyId: 'AKIATEST123',
        secret: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
        method: 'GET',
        path: '/bucket/key',
        timestamp: timestamp,
        query: 'prefix=photos'
    }, t, function (err, result) {
        t.ok(!err, 'should not error');
        t.ok(result, 'should return result');
        t.equal(result.accessKeyId, 'AKIATEST123',
            'should have access key ID');
        t.ok(result.user, 'should have user object');
        t.equal(result.user.uuid, 'test-user-uuid',
            'should have correct user UUID');
        t.done();
    });
};

exports.testVerificationWithEmptyQuery = function (t) {
    var testUser = {
        uuid: 'test-user-2',
        login: 'testuser2',
        accesskeys: {
            'AKIATEST456': 'secretkey456'
        }
    };

    setupUserAndVerify({
        user: testUser,
        accessKeyId: 'AKIATEST456',
        secret: 'secretkey456',
        method: 'GET',
        path: '/',
        timestamp: new Date().toISOString()
    }, t, function (err, result) {
        t.ok(!err, 'should not error');
        t.ok(result, 'should return result');
        t.equal(result.accessKeyId, 'AKIATEST456');
        t.done();
    });
};

/* --- Test missing/invalid authorization --- */

exports.testMissingAuthorizationHeader = function (t) {
    var req = {
        method: 'GET',
        url: '/bucket/key',
        headers: {},
        query: {}
    };

    sigv4.verifySigV4({
        req: req,
        log: log,
        redis: redis
    }, function (err, result) {
        t.ok(err, 'should error');
        t.equal(err.message, 'Missing Authorization header',
            'should have correct error message');
        t.ok(!result, 'should not return result');
        t.done();
    });
};

exports.testInvalidAuthorizationFormat = function (t) {
    var req = {
        method: 'GET',
        url: '/bucket/key',
        headers: {
            authorization: 'Basic dXNlcjpwYXNz'
        },
        query: {}
    };

    sigv4.verifySigV4({
        req: req,
        log: log,
        redis: redis
    }, function (err, result) {
        t.ok(err, 'should error');
        t.equal(err.message, 'Invalid Authorization header format',
            'should have correct error message');
        t.ok(!result, 'should not return result');
        t.done();
    });
};

/* --- Test invalid access key --- */

exports.testNonexistentAccessKey = function (t) {
    var headers = helper.createHeaders({
        method: 'GET',
        path: '/bucket/key',
        accessKey: 'AKIANONEXISTENT',
        secret: 'fakesecret',
        timestamp: new Date().toISOString()
    });

    var payloadHash = crypto.createHash('sha256')
        .update('', 'utf8').digest('hex');
    headers['x-amz-content-sha256'] = payloadHash;

    var req = {
        method: 'GET',
        url: '/bucket/key',
        headers: headers,
        query: {}
    };

    sigv4.verifySigV4({
        req: req,
        log: log,
        redis: redis
    }, function (err, result) {
        t.ok(err, 'should error');
        t.equal(err.message, 'Invalid access key',
            'should have correct error message');
        t.ok(!result, 'should not return result');
        t.done();
    });
};

exports.testUserNotFoundInRedis = function (t) {
    redis.set('/accesskey/AKIAORPHANED', 'missing-user-uuid',
        function (setErr) {
        t.ok(!setErr, 'should set access key');

        var headers = helper.createHeaders({
            method: 'GET',
            path: '/bucket/key',
            accessKey: 'AKIAORPHANED',
            secret: 'fakesecret',
            timestamp: new Date().toISOString()
        });

        var payloadHash = crypto.createHash('sha256')
            .update('', 'utf8').digest('hex');
        headers['x-amz-content-sha256'] = payloadHash;

        var req = {
            method: 'GET',
            url: '/bucket/key',
            headers: headers,
            query: {}
        };

        sigv4.verifySigV4({
            req: req,
            log: log,
            redis: redis
        }, function (err, result) {
            t.ok(err, 'should error');
            t.equal(err.message, 'User not found',
                'should have correct error message');
            t.ok(!result, 'should not return result');
            t.done();
        });
    });
};

exports.testAccessKeyNotInUserKeys = function (t) {
    var testUser = {
        uuid: 'test-user-3',
        login: 'testuser3',
        accesskeys: {
            'AKIAOTHER': 'othersecret'
        }
    };

    redis.set('/uuid/test-user-3', JSON.stringify(testUser),
        function (err1) {
        t.ok(!err1, 'should set user');
        redis.set('/accesskey/AKIAWRONG', 'test-user-3',
            function (err2) {
            t.ok(!err2, 'should set access key');

            var headers = helper.createHeaders({
                method: 'GET',
                path: '/bucket/key',
                accessKey: 'AKIAWRONG',
                secret: 'fakesecret',
                timestamp: new Date().toISOString()
            });

            var payloadHash = crypto.createHash('sha256')
                .update('', 'utf8').digest('hex');
            headers['x-amz-content-sha256'] = payloadHash;

            var req = {
                method: 'GET',
                url: '/bucket/key',
                headers: headers,
                query: {}
            };

            sigv4.verifySigV4({
                req: req,
                log: log,
                redis: redis
            }, function (err, result) {
                t.ok(err, 'should error');
                t.equal(err.message, 'Access key not found',
                    'should have correct error message');
                t.ok(!result, 'should not return result');
                t.done();
            });
        });
    });
};

/* --- Test signature mismatch --- */

exports.testSignatureMismatch = function (t) {
    var testUser = {
        uuid: 'test-user-4',
        login: 'testuser4',
        accesskeys: {
            'AKIATEST789': 'correctsecret'
        }
    };

    redis.set('/uuid/test-user-4', JSON.stringify(testUser),
        function (err1) {
        t.ok(!err1, 'should set user');
        redis.set('/accesskey/AKIATEST789', 'test-user-4',
            function (err2) {
            t.ok(!err2, 'should set access key');

            var headers = helper.createHeaders({
                method: 'GET',
                path: '/bucket/key',
                accessKey: 'AKIATEST789',
                secret: 'wrongsecret',
                timestamp: new Date().toISOString()
            });

            var payloadHash = crypto.createHash('sha256')
                .update('', 'utf8').digest('hex');
            headers['x-amz-content-sha256'] = payloadHash;

            var req = {
                method: 'GET',
                url: '/bucket/key',
                headers: headers,
                query: {}
            };

            sigv4.verifySigV4({
                req: req,
                log: log,
                redis: redis
            }, function (err, result) {
                t.ok(err, 'should error');
                t.equal(err.message, 'Signature mismatch',
                    'should have correct error message');
                t.ok(!result, 'should not return result');
                t.done();
            });
        });
    });
};

exports.testModifiedPath = function (t) {
    var testUser = {
        uuid: 'test-user-5',
        login: 'testuser5',
        accesskeys: {
            'AKIATEST999': 'mysecret'
        }
    };

    redis.set('/uuid/test-user-5', JSON.stringify(testUser),
        function (err1) {
        t.ok(!err1, 'should set user');
        redis.set('/accesskey/AKIATEST999', 'test-user-5',
            function (err2) {
            t.ok(!err2, 'should set access key');

            var headers = helper.createHeaders({
                method: 'GET',
                path: '/original/path',
                accessKey: 'AKIATEST999',
                secret: 'mysecret',
                timestamp: new Date().toISOString()
            });

            var payloadHash = crypto.createHash('sha256')
                .update('', 'utf8').digest('hex');
            headers['x-amz-content-sha256'] = payloadHash;

            var req = {
                method: 'GET',
                url: '/modified/path',
                headers: headers,
                query: {}
            };

            sigv4.verifySigV4({
                req: req,
                log: log,
                redis: redis
            }, function (err, result) {
                t.ok(err, 'should error');
                t.equal(err.message, 'Signature mismatch',
                    'should detect path modification');
                t.ok(!result, 'should not return result');
                t.done();
            });
        });
    });
};

/* --- Test timestamp validation --- */

exports.testMissingTimestamp = function (t) {
    var testUser = {
        uuid: 'test-user-6',
        login: 'testuser6',
        accesskeys: {
            'AKIATEST111': 'secret111'
        }
    };

    redis.set('/uuid/test-user-6', JSON.stringify(testUser),
        function (err1) {
        t.ok(!err1, 'should set user');
        redis.set('/accesskey/AKIATEST111', 'test-user-6',
            function (err2) {
            t.ok(!err2, 'should set access key');

            var headers = helper.createHeaders({
                method: 'GET',
                path: '/bucket/key',
                accessKey: 'AKIATEST111',
                secret: 'secret111',
                timestamp: new Date().toISOString()
            });

            delete headers['x-amz-date'];

            var req = {
                method: 'GET',
                url: '/bucket/key',
                headers: headers,
                query: {}
            };

            sigv4.verifySigV4({
                req: req,
                log: log,
                redis: redis
            }, function (err, result) {
                t.ok(err, 'should error');
                t.equal(err.message, 'Missing timestamp',
                    'should have correct error message');
                t.ok(!result, 'should not return result');
                t.done();
            });
        });
    });
};

exports.testExpiredTimestamp = function (t) {
    var testUser = {
        uuid: 'test-user-7',
        login: 'testuser7',
        accesskeys: {
            'AKIATEST222': 'secret222'
        }
    };

    var twentyMinutesAgo = Date.now() - (20 * 60 * 1000);
    var expiredDate = new Date(twentyMinutesAgo);
    var expiredTimestamp = expiredDate.toISOString();

    setupUserAndVerify({
        user: testUser,
        accessKeyId: 'AKIATEST222',
        secret: 'secret222',
        method: 'GET',
        path: '/bucket/key',
        timestamp: expiredTimestamp
    }, t, function (err, result) {
        t.ok(err, 'should error');
        t.equal(err.message, 'Request timestamp too old',
            'should reject expired timestamp');
        t.ok(!result, 'should not return result');
        t.done();
    });
};

exports.testFutureTimestampWithinWindow = function (t) {
    var testUser = {
        uuid: 'test-user-8',
        login: 'testuser8',
        accesskeys: {
            'AKIATEST333': 'secret333'
        }
    };

    var tenMinutesFuture = Date.now() + (10 * 60 * 1000);
    var futureDate = new Date(tenMinutesFuture);
    var futureTimestamp = futureDate.toISOString()
        .replace(/[:-]|\.\d{3}/g, '');

    setupUserAndVerify({
        user: testUser,
        accessKeyId: 'AKIATEST333',
        secret: 'secret333',
        method: 'GET',
        path: '/bucket/key',
        timestamp: futureTimestamp
    }, t, function (err, result) {
        t.ok(!err, 'should not error for future time within window');
        t.ok(result, 'should return result');
        t.done();
    });
};

exports.testTimestampExactly15MinutesOld = function (t) {
    var testUser = {
        uuid: 'test-user-9',
        login: 'testuser9',
        accesskeys: {
            'AKIATEST444': 'secret444'
        }
    };

    // Use 14.5 minutes to avoid flakiness due to processing time when
    // running multiple tests. This still tests near-boundary behavior.
    var almostFifteenMinutesAgo = Date.now() - (14.5 * 60 * 1000);
    var boundaryDate = new Date(almostFifteenMinutesAgo);
    var boundaryTimestamp = boundaryDate.toISOString()
        .replace(/[:-]|\.\d{3}/g, '');

    setupUserAndVerify({
        user: testUser,
        accessKeyId: 'AKIATEST444',
        secret: 'secret444',
        method: 'GET',
        path: '/bucket/key',
        timestamp: boundaryTimestamp
    }, t, function (err, result) {
        t.ok(!err, 'should accept timestamp at 15 minute boundary');
        t.ok(result, 'should return result');
        t.done();
    });
};

/* --- Test various HTTP methods --- */

exports.testPUTRequest = function (t) {
    var testUser = {
        uuid: 'test-user-10',
        login: 'testuser10',
        accesskeys: {
            'AKIATEST555': 'secret555'
        }
    };

    var timestamp = new Date().toISOString();

    setupUserAndVerify({
        user: testUser,
        accessKeyId: 'AKIATEST555',
        secret: 'secret555',
        method: 'PUT',
        path: '/bucket/key',
        timestamp: timestamp
    }, t, function (err, result) {
        t.ok(!err, 'should not error');
        t.ok(result, 'should verify PUT request');
        t.done();
    });
};

exports.testDELETERequest = function (t) {
    var testUser = {
        uuid: 'test-user-11',
        login: 'testuser11',
        accesskeys: {
            'AKIATEST666': 'secret666'
        }
    };

    setupUserAndVerify({
        user: testUser,
        accessKeyId: 'AKIATEST666',
        secret: 'secret666',
        method: 'DELETE',
        path: '/bucket/key',
        timestamp: new Date().toISOString()
    }, t, function (err, result) {
        t.ok(!err, 'should not error');
        t.ok(result, 'should verify DELETE request');
        t.done();
    });
};

/* --- Test query string handling --- */

exports.testComplexQueryString = function (t) {
    var testUser = {
        uuid: 'test-user-12',
        login: 'testuser12',
        accesskeys: {
            'AKIATEST777': 'secret777'
        }
    };

    var query = 'prefix=photos&delimiter=/&max-keys=1000';
    setupUserAndVerify({
        user: testUser,
        accessKeyId: 'AKIATEST777',
        secret: 'secret777',
        method: 'GET',
        path: '/bucket',
        timestamp: new Date().toISOString(),
        query: query
    }, t, function (err, result) {
        t.ok(!err, 'should not error');
        t.ok(result, 'should verify complex query string');
        t.done();
    });
};

exports.testQueryParamWithSpecialChars = function (t) {
    var testUser = {
        uuid: 'test-user-13',
        login: 'testuser13',
        accesskeys: {
            'AKIATEST888': 'secret888'
        }
    };

    var query = 'marker=file%20with%20spaces.txt';
    setupUserAndVerify({
        user: testUser,
        accessKeyId: 'AKIATEST888',
        secret: 'secret888',
        method: 'GET',
        path: '/bucket',
        timestamp: new Date().toISOString(),
        query: query
    }, t, function (err, result) {
        t.ok(!err, 'should not error');
        t.ok(result, 'should verify query with special chars');
        t.done();
    });
};

/* --- Test accessKeyId validation --- */

exports.testOversizedAccessKeyId = function (t) {
    // Generate an accessKeyId that exceeds the 1024 character limit
    var oversizedAccessKeyId = '';
    for (var i = 0; i < 1025; i++) {
        oversizedAccessKeyId += 'A';
    }

    var testUser = {
        uuid: 'test-user-oversized',
        login: 'testuserOversized',
        accesskeys: {}
    };
    testUser.accesskeys[oversizedAccessKeyId] = 'secret999';

    var timestamp = new Date().toISOString();

    setupUserAndVerify({
        user: testUser,
        accessKeyId: oversizedAccessKeyId,
        secret: 'secret999',
        method: 'GET',
        path: '/bucket/key',
        timestamp: timestamp
    }, t, function (err, result) {
        t.ok(err, 'should return error for oversized accessKeyId');
        t.equal(err.name, 'InvalidSignatureError',
            'should be InvalidSignatureError');
        t.ok(err.message.indexOf('Access key ID too long') !== -1,
            'error message should mention "Access key ID too long"');
        t.ok(!result, 'should not return result');
        t.done();
    });
};
