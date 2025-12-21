/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright 2025 Edgecast Cloud LLC.
 */

/*
 * test/sigv4-e2e.test.js: End-to-end tests for SigV4 authentication
 *
 * Simulates how an S3 server would use mahi to verify client signatures
 * for various S3 operations. Tests the complete SigV4 verification flow
 * by calling verifySigV4 directly with mock request objects.
 */

var nodeunit = require('nodeunit');
var crypto = require('crypto');
var bunyan = require('bunyan');
var fakeredis = require('fakeredis');
var sigv4 = require('../lib/server/sigv4');
var SigV4Helper = require('./lib/sigv4-helper');

var log = bunyan.createLogger({
        name: 'sigv4-e2e-test',
        level: 'fatal'
});

var redis;
var helper;

/* --- Setup and teardown --- */

exports.setUp = function (cb) {
        redis = fakeredis.createClient();
        helper = new SigV4Helper({region: 'us-east-1', service: 's3'});
        cb();
};

exports.tearDown = function (cb) {
        if (redis) {
                redis.quit();
        }
        cb();
};

/*
 * Helper to verify S3 request through verifySigV4 function
 */
function verifyS3Request(opts, callback) {
        var accessKeyId = opts.accessKey;
        var secret = opts.secret;
        var method = opts.method || 'GET';
        var path = opts.path || '/bucket/object';
        var host = opts.host || 'bucket.s3.amazonaws.com';
        var query = opts.query;
        var body = opts.body;

        // Create signed headers for the S3 request
        var headers = helper.createHeaders({
                method: method,
                path: path,
                accessKey: accessKeyId,
                secret: secret,
                body: body,
                host: host,
                query: query,
                timestamp: opts.timestamp
        });

        // Add payload hash header
        var payloadHash;
        if (body) {
                var bodyStr = (typeof (body) === 'string') ?
                        body : JSON.stringify(body);
                payloadHash = crypto.createHash('sha256')
                        .update(bodyStr, 'utf8').digest('hex');
        } else {
                payloadHash = crypto.createHash('sha256')
                        .update('', 'utf8').digest('hex');
        }
        headers['x-amz-content-sha256'] = payloadHash;

        // Build request URL
        var url = path;
        if (query) {
                url += '?' + query;
        }

        // Create mock request object representing the S3 request
        var req = {
                method: method,
                url: url,
                headers: headers,
                query: {},
                log: log
        };

        // Call verifySigV4 directly
        sigv4.verifySigV4({
                req: req,
                log: log,
                redis: redis
        }, function (err, result) {
                if (err) {
                        return (callback(err));
                }
                callback(null, result);
        });
}

/* --- S3 GET Object Operation --- */

exports.testS3GetObjectOperation = function (t) {
        var userUuid = 'user-s3-get';
        var accessKeyId = 'AKIAS3GET123456';
        var secret = 's3getsecret';

        var userData = {
                uuid: userUuid,
                login: 's3user',
                account: 's3-account',
                accesskeys: {}
        };
        userData.accesskeys[accessKeyId] = secret;

        redis.set('/accesskey/' + accessKeyId, userUuid, function (err1) {
                t.ok(!err1);
                redis.set('/uuid/' + userUuid, JSON.stringify(userData),
                        function (err2) {
                        t.ok(!err2);

                        verifyS3Request({
                                method: 'GET',
                                path: '/my-bucket/photos/image.jpg',
                                accessKey: accessKeyId,
                                secret: secret,
                                host: 'my-bucket.s3.amazonaws.com'
                        }, function (err, result) {
                                t.ok(!err, 'should verify GET object');
                                t.ok(result, 'should return result');
                                t.equal(result.accessKeyId, accessKeyId);
                                t.equal(result.user.uuid, userUuid);
                                t.done();
                        });
                });
        });
};

/* --- S3 PUT Object Operation --- */

exports.testS3PutObjectOperation = function (t) {
        var userUuid = 'user-s3-put';
        var accessKeyId = 'AKIAS3PUT123456';
        var secret = 's3putsecret';

        var userData = {
                uuid: userUuid,
                login: 's3putuser',
                account: 's3-account',
                accesskeys: {}
        };
        userData.accesskeys[accessKeyId] = secret;

        redis.set('/accesskey/' + accessKeyId, userUuid, function (err1) {
                t.ok(!err1);
                redis.set('/uuid/' + userUuid, JSON.stringify(userData),
                        function (err2) {
                        t.ok(!err2);

                        verifyS3Request({
                                method: 'PUT',
                                path: '/my-bucket/uploads/newfile.txt',
                                accessKey: accessKeyId,
                                secret: secret,
                                host: 'my-bucket.s3.amazonaws.com'
                        }, function (err, result) {
                                t.ok(!err, 'should verify PUT object');
                                t.ok(result, 'should return result');
                                t.equal(result.accessKeyId, accessKeyId);
                                t.done();
                        });
                });
        });
};

/* --- S3 DELETE Object Operation --- */

exports.testS3DeleteObjectOperation = function (t) {
        var userUuid = 'user-s3-delete';
        var accessKeyId = 'AKIAS3DEL123456';
        var secret = 's3delsecret';

        var userData = {
                uuid: userUuid,
                login: 's3deluser',
                account: 's3-account',
                accesskeys: {}
        };
        userData.accesskeys[accessKeyId] = secret;

        redis.set('/accesskey/' + accessKeyId, userUuid, function (err1) {
                t.ok(!err1);
                redis.set('/uuid/' + userUuid, JSON.stringify(userData),
                        function (err2) {
                        t.ok(!err2);

                        verifyS3Request({
                                method: 'DELETE',
                                path: '/my-bucket/old-file.txt',
                                accessKey: accessKeyId,
                                secret: secret,
                                host: 'my-bucket.s3.amazonaws.com'
                        }, function (err, result) {
                                t.ok(!err, 'should verify DELETE object');
                                t.ok(result, 'should return result');
                                t.equal(result.accessKeyId, accessKeyId);
                                t.done();
                        });
                });
        });
};

/* --- S3 LIST Objects Operation (with query parameters) --- */

exports.testS3ListObjectsOperation = function (t) {
        var userUuid = 'user-s3-list';
        var accessKeyId = 'AKIAS3LIST12345';
        var secret = 's3listsecret';

        var userData = {
                uuid: userUuid,
                login: 's3listuser',
                account: 's3-account',
                accesskeys: {}
        };
        userData.accesskeys[accessKeyId] = secret;

        redis.set('/accesskey/' + accessKeyId, userUuid, function (err1) {
                t.ok(!err1);
                redis.set('/uuid/' + userUuid, JSON.stringify(userData),
                        function (err2) {
                        t.ok(!err2);

                        verifyS3Request({
                                method: 'GET',
                                path: '/my-bucket',
                                query: 'prefix=photos/&delimiter=/' +
                                        '&max-keys=1000',
                                accessKey: accessKeyId,
                                secret: secret,
                                host: 'my-bucket.s3.amazonaws.com'
                        }, function (err, result) {
                                t.ok(!err, 'should verify LIST operation');
                                t.ok(result, 'should return result');
                                t.equal(result.accessKeyId, accessKeyId);
                                t.done();
                        });
                });
        });
};

/* --- Invalid Signature Rejection --- */

exports.testInvalidSignatureRejection = function (t) {
        var userUuid = 'user-invalid-sig';
        var accessKeyId = 'AKIAINVALID1234';
        var correctSecret = 'correctsecret';
        var wrongSecret = 'wrongsecret';

        var userData = {
                uuid: userUuid,
                login: 'invaliduser',
                account: 'test-account',
                accesskeys: {}
        };
        userData.accesskeys[accessKeyId] = correctSecret;

        redis.set('/accesskey/' + accessKeyId, userUuid, function (err1) {
                t.ok(!err1);
                redis.set('/uuid/' + userUuid, JSON.stringify(userData),
                        function (err2) {
                        t.ok(!err2);

                        verifyS3Request({
                                method: 'GET',
                                path: '/bucket/file.txt',
                                accessKey: accessKeyId,
                                secret: wrongSecret,
                                host: 'bucket.s3.amazonaws.com'
                        }, function (err, result) {
                                t.ok(err, 'should reject invalid signature');
                                t.equal(err.name, 'InvalidSignatureError');
                                t.done();
                        });
                });
        });
};

/* --- Nonexistent Access Key --- */

exports.testNonexistentAccessKey = function (t) {
        verifyS3Request({
                method: 'GET',
                path: '/bucket/file.txt',
                accessKey: 'AKIANONEXIST999',
                secret: 'anysecret',
                host: 'bucket.s3.amazonaws.com'
        }, function (err, result) {
                t.ok(err, 'should reject nonexistent key');
                t.equal(err.name, 'InvalidSignatureError');
                t.done();
        });
};

/* --- Expired Request Rejection --- */

exports.testExpiredRequestRejection = function (t) {
        var userUuid = 'user-expired';
        var accessKeyId = 'AKIAEXPIRED1234';
        var secret = 'expiredsecret';

        var userData = {
                uuid: userUuid,
                login: 'expireduser',
                account: 'expired-account',
                accesskeys: {}
        };
        userData.accesskeys[accessKeyId] = secret;

        redis.set('/accesskey/' + accessKeyId, userUuid, function (err1) {
                t.ok(!err1);
                redis.set('/uuid/' + userUuid, JSON.stringify(userData),
                        function (err2) {
                        t.ok(!err2);

                        // Create timestamp 30 minutes in the past
                        var oldDate = new Date(Date.now() - (30 * 60 * 1000));
                        var timestamp = oldDate.toISOString()
                                .replace(/[:-]|\.\d{3}/g, '');

                        verifyS3Request({
                                method: 'GET',
                                path: '/bucket/file.txt',
                                accessKey: accessKeyId,
                                secret: secret,
                                host: 'bucket.s3.amazonaws.com',
                                timestamp: timestamp
                        }, function (err, result) {
                                t.ok(err, 'should reject expired request');
                                t.equal(err.name, 'InvalidSignatureError');
                                t.done();
                        });
                });
        });
};

/* --- Signed Payload Request --- */

exports.testSignedPayloadRequest = function (t) {
        var userUuid = 'user-signed-payload';
        var accessKeyId = 'AKIASIGNED12345';
        var secret = 'signedsecret';

        var userData = {
                uuid: userUuid,
                login: 'signeduser',
                account: 'signed-account',
                accesskeys: {}
        };
        userData.accesskeys[accessKeyId] = secret;

        redis.set('/accesskey/' + accessKeyId, userUuid, function (err1) {
                t.ok(!err1);
                redis.set('/uuid/' + userUuid, JSON.stringify(userData),
                        function (err2) {
                        t.ok(!err2);

                        verifyS3Request({
                                method: 'POST',
                                path: '/bucket',
                                accessKey: accessKeyId,
                                secret: secret,
                                host: 'bucket.s3.amazonaws.com',
                                query: 'uploads'
                        }, function (err, result) {
                                t.ok(!err, 'should verify signed payload');
                                t.ok(result, 'should return result');
                                t.equal(result.accessKeyId, accessKeyId);
                                t.done();
                        });
                });
        });
};
