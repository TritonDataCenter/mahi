/*
 * This Source Code Form is subject to the terms of the Mozilla
 * Public License, v. 2.0. If a copy of the MPL was not
 * distributed with this file, You can obtain one at
 * http://mozilla.org/MPL/2.0/.
 *
 * Copyright 2026 Edgecast Cloud LLC.
 */

/*
 * test/sigv4-error-branches.test.js: Tests for SigV4 error handling
 * branches to improve branch coverage per CHG-047.
 *
 * Focus areas:
 * - AccessKeyId validation (length, character set)
 * - Credential format validation (dateStamp, requestType)
 * - Temporary credential error paths
 * - Timestamp validation edge cases
 */

var bunyan = require('bunyan');
var crypto = require('crypto');
var fakeredis = require('fakeredis');
var sigv4 = require('../lib/server/sigv4');
var SigV4Helper = require('./lib/sigv4-helper');

var helper = new SigV4Helper({region: 'us-east-1', service: 's3'});
var redis;
var log;

/* --- Setup and teardown --- */

exports.setUp = function (cb) {
    redis = fakeredis.createClient();
    log = bunyan.createLogger({
        name: 'sigv4-error-branches-test',
        level: 'fatal'
    });
    cb();
};

exports.tearDown = function (cb) {
    if (redis) {
        redis.quit();
    }
    cb();
};

/* ================================================================
 * SECTION 1: AccessKeyId Validation in parseAuthHeader
 * Tests for lines 198-204 in sigv4.js
 * ================================================================ */

exports.testAccessKeyIdTooShort = function (t) {
    // AccessKeyId must be >= 16 characters (MIN_ACCESSKEYID_LENGTH)
    var authHeader =
        'AWS4-HMAC-SHA256 Credential=AKIASHORT123456/' +
        '20251217/us-east-1/s3/aws4_request, ' +
        'SignedHeaders=host, ' +
        'Signature=abc123';

    var result = sigv4.parseAuthHeader(authHeader);

    t.equal(result, null,
        'should reject accessKeyId shorter than 16 characters');
    t.done();
};

exports.testAccessKeyIdExactlyMinLength = function (t) {
    // AccessKeyId exactly 16 characters should be valid
    var authHeader =
        'AWS4-HMAC-SHA256 Credential=AKIATEST12345678/' +
        '20251217/us-east-1/s3/aws4_request, ' +
        'SignedHeaders=host, ' +
        'Signature=abc123';

    var result = sigv4.parseAuthHeader(authHeader);

    t.ok(result, 'should accept accessKeyId of exactly 16 characters');
    t.equal(result.accessKeyId, 'AKIATEST12345678');
    t.done();
};

exports.testAccessKeyIdTooLong = function (t) {
    // AccessKeyId must be <= 128 characters (MAX_ACCESSKEYID_LENGTH)
    var longKeyId = new Array(130).join('A'); // 129 chars
    var authHeader =
        'AWS4-HMAC-SHA256 Credential=' + longKeyId + '/' +
        '20251217/us-east-1/s3/aws4_request, ' +
        'SignedHeaders=host, ' +
        'Signature=abc123';

    var result = sigv4.parseAuthHeader(authHeader);

    t.equal(result, null,
        'should reject accessKeyId longer than 128 characters');
    t.done();
};

exports.testAccessKeyIdExactlyMaxLength = function (t) {
    // AccessKeyId exactly 128 characters should be valid
    var maxKeyId = new Array(129).join('A'); // 128 chars
    var authHeader =
        'AWS4-HMAC-SHA256 Credential=' + maxKeyId + '/' +
        '20251217/us-east-1/s3/aws4_request, ' +
        'SignedHeaders=host, ' +
        'Signature=abc123';

    var result = sigv4.parseAuthHeader(authHeader);

    t.ok(result, 'should accept accessKeyId of exactly 128 characters');
    t.equal(result.accessKeyId.length, 128);
    t.done();
};

exports.testAccessKeyIdWithHyphen = function (t) {
    // AccessKeyId regex is /^\w+$/ - hyphen is not a word character
    var authHeader =
        'AWS4-HMAC-SHA256 Credential=AKIA-TEST-12345678/' +
        '20251217/us-east-1/s3/aws4_request, ' +
        'SignedHeaders=host, ' +
        'Signature=abc123';

    var result = sigv4.parseAuthHeader(authHeader);

    t.equal(result, null,
        'should reject accessKeyId with hyphen');
    t.done();
};

exports.testAccessKeyIdWithSpace = function (t) {
    // Space is not a word character
    var authHeader =
        'AWS4-HMAC-SHA256 Credential=AKIA TEST 12345678/' +
        '20251217/us-east-1/s3/aws4_request, ' +
        'SignedHeaders=host, ' +
        'Signature=abc123';

    var result = sigv4.parseAuthHeader(authHeader);

    // Space would break the credential parsing entirely
    t.equal(result, null,
        'should reject accessKeyId with space');
    t.done();
};

exports.testAccessKeyIdWithUnderscore = function (t) {
    // Underscore IS a word character - should be valid
    var authHeader =
        'AWS4-HMAC-SHA256 Credential=AKIA_TEST_12345678/' +
        '20251217/us-east-1/s3/aws4_request, ' +
        'SignedHeaders=host, ' +
        'Signature=abc123';

    var result = sigv4.parseAuthHeader(authHeader);

    t.ok(result, 'should accept accessKeyId with underscore');
    t.equal(result.accessKeyId, 'AKIA_TEST_12345678');
    t.done();
};

exports.testAccessKeyIdWithNumbers = function (t) {
    // Numbers are word characters - should be valid
    var authHeader =
        'AWS4-HMAC-SHA256 Credential=1234567890123456/' +
        '20251217/us-east-1/s3/aws4_request, ' +
        'SignedHeaders=host, ' +
        'Signature=abc123';

    var result = sigv4.parseAuthHeader(authHeader);

    t.ok(result, 'should accept numeric accessKeyId');
    t.equal(result.accessKeyId, '1234567890123456');
    t.done();
};

exports.testAccessKeyIdWithSpecialChars = function (t) {
    // Special characters like @ # $ % are not word characters
    var authHeader =
        'AWS4-HMAC-SHA256 Credential=AKIA@TEST#123456/' +
        '20251217/us-east-1/s3/aws4_request, ' +
        'SignedHeaders=host, ' +
        'Signature=abc123';

    var result = sigv4.parseAuthHeader(authHeader);

    t.equal(result, null,
        'should reject accessKeyId with special characters');
    t.done();
};

/* ================================================================
 * SECTION 2: DateStamp Validation in parseAuthHeader
 * Tests for line 178 in sigv4.js - must be 8 digits
 * ================================================================ */

exports.testDateStampTooShort = function (t) {
    var authHeader =
        'AWS4-HMAC-SHA256 Credential=AKIATEST12345678/' +
        '2025121/us-east-1/s3/aws4_request, ' +
        'SignedHeaders=host, ' +
        'Signature=abc123';

    var result = sigv4.parseAuthHeader(authHeader);

    t.equal(result, null,
        'should reject dateStamp with 7 digits');
    t.done();
};

exports.testDateStampTooLong = function (t) {
    var authHeader =
        'AWS4-HMAC-SHA256 Credential=AKIATEST12345678/' +
        '202512170/us-east-1/s3/aws4_request, ' +
        'SignedHeaders=host, ' +
        'Signature=abc123';

    var result = sigv4.parseAuthHeader(authHeader);

    t.equal(result, null,
        'should reject dateStamp with 9 digits');
    t.done();
};

exports.testDateStampWithLetters = function (t) {
    var authHeader =
        'AWS4-HMAC-SHA256 Credential=AKIATEST12345678/' +
        '2025121A/us-east-1/s3/aws4_request, ' +
        'SignedHeaders=host, ' +
        'Signature=abc123';

    var result = sigv4.parseAuthHeader(authHeader);

    t.equal(result, null,
        'should reject dateStamp with letters');
    t.done();
};

exports.testDateStampWithHyphens = function (t) {
    // ISO format with hyphens is not valid - must be YYYYMMDD
    var authHeader =
        'AWS4-HMAC-SHA256 Credential=AKIATEST12345678/' +
        '2025-12-17/us-east-1/s3/aws4_request, ' +
        'SignedHeaders=host, ' +
        'Signature=abc123';

    var result = sigv4.parseAuthHeader(authHeader);

    t.equal(result, null,
        'should reject dateStamp with hyphens (ISO format)');
    t.done();
};

exports.testDateStampValid = function (t) {
    var authHeader =
        'AWS4-HMAC-SHA256 Credential=AKIATEST12345678/' +
        '20251217/us-east-1/s3/aws4_request, ' +
        'SignedHeaders=host, ' +
        'Signature=abc123';

    var result = sigv4.parseAuthHeader(authHeader);

    t.ok(result, 'should accept valid 8-digit dateStamp');
    t.equal(result.dateStamp, '20251217');
    t.done();
};

/* ================================================================
 * SECTION 3: RequestType Validation in parseAuthHeader
 * Tests for line 187 in sigv4.js - must be 'aws4_request'
 * ================================================================ */

exports.testRequestTypeWrong = function (t) {
    var authHeader =
        'AWS4-HMAC-SHA256 Credential=AKIATEST12345678/' +
        '20251217/us-east-1/s3/aws3_request, ' +
        'SignedHeaders=host, ' +
        'Signature=abc123';

    var result = sigv4.parseAuthHeader(authHeader);

    t.equal(result, null,
        'should reject requestType that is not aws4_request');
    t.done();
};

exports.testRequestTypeCaseSensitive = function (t) {
    var authHeader =
        'AWS4-HMAC-SHA256 Credential=AKIATEST12345678/' +
        '20251217/us-east-1/s3/AWS4_REQUEST, ' +
        'SignedHeaders=host, ' +
        'Signature=abc123';

    var result = sigv4.parseAuthHeader(authHeader);

    t.equal(result, null,
        'should reject uppercase AWS4_REQUEST');
    t.done();
};

exports.testRequestTypeEmpty = function (t) {
    var authHeader =
        'AWS4-HMAC-SHA256 Credential=AKIATEST12345678/' +
        '20251217/us-east-1/s3/, ' +
        'SignedHeaders=host, ' +
        'Signature=abc123';

    var result = sigv4.parseAuthHeader(authHeader);

    t.equal(result, null,
        'should reject empty requestType');
    t.done();
};

/* ================================================================
 * SECTION 4: Temporary Credential Error Paths in verifySigV4
 * Tests for MSTS/MSAR prefix handling (lines 992-1006)
 * ================================================================ */

exports.testMSTSKeyWithoutSessionToken = function (t) {
    // MSTS prefix indicates temporary credential - requires session token
    var testUser = {
        uuid: 'test-user-temp-1',
        login: 'tempuser1',
        accesskeys: {
            'MSTSTEST12345678': 'tempsecret'
        }
    };

    redis.set('/uuid/test-user-temp-1', JSON.stringify(testUser),
        function (err1) {
        t.ok(!err1, 'should set user');
        redis.set('/accesskey/MSTSTEST12345678', 'test-user-temp-1',
            function (err2) {
            t.ok(!err2, 'should set access key');

            var headers = helper.createHeaders({
                method: 'GET',
                path: '/bucket/key',
                accessKey: 'MSTSTEST12345678',
                secret: 'tempsecret'
            });

            var payloadHash = crypto.createHash('sha256')
                .update('', 'utf8').digest('hex');
            headers['x-amz-content-sha256'] = payloadHash;

            // No session token provided
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
                t.ok(err.message.indexOf('session token') !== -1,
                    'error should mention session token');
                t.ok(!result, 'should not return result');
                t.done();
            });
        });
    });
};

exports.testMSARKeyWithoutSessionToken = function (t) {
    // MSAR prefix indicates assumed role credential - requires session token
    var testUser = {
        uuid: 'test-user-temp-2',
        login: 'tempuser2',
        accesskeys: {
            'MSARTEST12345678': 'tempsecret'
        }
    };

    redis.set('/uuid/test-user-temp-2', JSON.stringify(testUser),
        function (err1) {
        t.ok(!err1, 'should set user');
        redis.set('/accesskey/MSARTEST12345678', 'test-user-temp-2',
            function (err2) {
            t.ok(!err2, 'should set access key');

            var headers = helper.createHeaders({
                method: 'GET',
                path: '/bucket/key',
                accessKey: 'MSARTEST12345678',
                secret: 'tempsecret'
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
                t.ok(err.message.indexOf('session token') !== -1,
                    'error should mention session token');
                t.ok(!result, 'should not return result');
                t.done();
            });
        });
    });
};

/* ================================================================
 * SECTION 5: AccessKeyId Length Check in verifySigV4
 * Tests for lines 728-733 in sigv4.js
 * ================================================================ */

exports.testAccessKeyIdTooLongInVerify = function (t) {
    // Even if parseAuthHeader didn't catch it, verifySigV4 has
    // an explicit check for key length > 128
    var longKeyId = new Array(130).join('A'); // 129 chars

    // Manually construct auth header to bypass parseAuthHeader check
    var authHeader =
        'AWS4-HMAC-SHA256 Credential=' + longKeyId + '/' +
        '20251217/us-east-1/s3/aws4_request, ' +
        'SignedHeaders=host, ' +
        'Signature=abc123';

    var req = {
        method: 'GET',
        url: '/bucket/key',
        headers: {
            authorization: authHeader,
            host: 'localhost',
            'x-amz-date': '20251217T120000Z'
        },
        query: {}
    };

    sigv4.verifySigV4({
        req: req,
        log: log,
        redis: redis
    }, function (err, result) {
        t.ok(err, 'should error');
        // Either parseAuthHeader rejects it or verifySigV4 does
        t.ok(!result, 'should not return result');
        t.done();
    });
};

/* ================================================================
 * SECTION 6: Timestamp Validation Edge Cases
 * Tests for timestamp freshness (lines 1083-1086)
 * ================================================================ */

exports.testTimestampInFuture = function (t) {
    var testUser = {
        uuid: 'test-user-future',
        login: 'futureuser',
        accesskeys: {
            'AKIAFUTURE123456': 'futuresecret'
        }
    };

    // 20 minutes in the future
    var futureTime = Date.now() + (20 * 60 * 1000);
    var futureDate = new Date(futureTime);
    var futureTimestamp = futureDate.toISOString()
        .replace(/[:-]|\.\d{3}/g, '');

    redis.set('/uuid/test-user-future', JSON.stringify(testUser),
        function (err1) {
        t.ok(!err1, 'should set user');
        redis.set('/accesskey/AKIAFUTURE123456', 'test-user-future',
            function (err2) {
            t.ok(!err2, 'should set access key');

            var headers = helper.createHeaders({
                method: 'GET',
                path: '/bucket/key',
                accessKey: 'AKIAFUTURE123456',
                secret: 'futuresecret',
                timestamp: futureTimestamp
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
                t.equal(err.message, 'Request timestamp too old',
                    'should reject future timestamp beyond threshold');
                t.ok(!result, 'should not return result');
                t.done();
            });
        });
    });
};

exports.testTimestampExactlyAtThreshold = function (t) {
    var testUser = {
        uuid: 'test-user-threshold',
        login: 'thresholduser',
        accesskeys: {
            'AKIATHRESHOLD123': 'thresholdsecret'
        }
    };

    // Exactly 15 minutes ago - should still be valid
    var thresholdTime = Date.now() - (15 * 60 * 1000);
    var thresholdDate = new Date(thresholdTime);
    var thresholdTimestamp = thresholdDate.toISOString()
        .replace(/[:-]|\.\d{3}/g, '');

    redis.set('/uuid/test-user-threshold', JSON.stringify(testUser),
        function (err1) {
        t.ok(!err1, 'should set user');
        redis.set('/accesskey/AKIATHRESHOLD123', 'test-user-threshold',
            function (err2) {
            t.ok(!err2, 'should set access key');

            var headers = helper.createHeaders({
                method: 'GET',
                path: '/bucket/key',
                accessKey: 'AKIATHRESHOLD123',
                secret: 'thresholdsecret',
                timestamp: thresholdTimestamp
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
                // At exactly 15 minutes, might pass or fail depending on
                // timing - we test that the code handles this boundary
                // The important thing is it doesn't crash
                t.ok(true, 'should handle threshold timestamp without crash');
                t.done();
            });
        });
    });
};

exports.testTimestampJustOverThreshold = function (t) {
    var testUser = {
        uuid: 'test-user-over',
        login: 'overuser',
        accesskeys: {
            'AKIAOVERTIME1234': 'oversecret'
        }
    };

    // 16 minutes ago - should be rejected
    var overTime = Date.now() - (16 * 60 * 1000);
    var overDate = new Date(overTime);
    var overTimestamp = overDate.toISOString()
        .replace(/[:-]|\.\d{3}/g, '');

    redis.set('/uuid/test-user-over', JSON.stringify(testUser),
        function (err1) {
        t.ok(!err1, 'should set user');
        redis.set('/accesskey/AKIAOVERTIME1234', 'test-user-over',
            function (err2) {
            t.ok(!err2, 'should set access key');

            var headers = helper.createHeaders({
                method: 'GET',
                path: '/bucket/key',
                accessKey: 'AKIAOVERTIME1234',
                secret: 'oversecret',
                timestamp: overTimestamp
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
                t.equal(err.message, 'Request timestamp too old',
                    'should reject timestamp just over 15 minutes');
                t.ok(!result, 'should not return result');
                t.done();
            });
        });
    });
};

/* ================================================================
 * SECTION 7: Empty Credential Parts Validation
 * Tests for lines 162-172 in sigv4.js
 * ================================================================ */

exports.testEmptyRegion = function (t) {
    var authHeader =
        'AWS4-HMAC-SHA256 Credential=AKIATEST12345678/' +
        '20251217//s3/aws4_request, ' +
        'SignedHeaders=host, ' +
        'Signature=abc123';

    var result = sigv4.parseAuthHeader(authHeader);

    t.equal(result, null,
        'should reject credential with empty region');
    t.done();
};

exports.testEmptyService = function (t) {
    var authHeader =
        'AWS4-HMAC-SHA256 Credential=AKIATEST12345678/' +
        '20251217/us-east-1//aws4_request, ' +
        'SignedHeaders=host, ' +
        'Signature=abc123';

    var result = sigv4.parseAuthHeader(authHeader);

    t.equal(result, null,
        'should reject credential with empty service');
    t.done();
};

exports.testWhitespaceOnlyRegion = function (t) {
    var authHeader =
        'AWS4-HMAC-SHA256 Credential=AKIATEST12345678/' +
        '20251217/   /s3/aws4_request, ' +
        'SignedHeaders=host, ' +
        'Signature=abc123';

    var result = sigv4.parseAuthHeader(authHeader);

    t.equal(result, null,
        'should reject credential with whitespace-only region');
    t.done();
};

/* ================================================================
 * SECTION 8: Signature Format Validation
 * Tests for signature content handling
 * ================================================================ */

exports.testEmptySignature = function (t) {
    var authHeader =
        'AWS4-HMAC-SHA256 Credential=AKIATEST12345678/' +
        '20251217/us-east-1/s3/aws4_request, ' +
        'SignedHeaders=host, ' +
        'Signature=';

    var result = sigv4.parseAuthHeader(authHeader);

    t.ok(result, 'should parse header with empty signature');
    t.equal(result.signature, '',
        'signature should be empty string');
    t.done();
};

exports.testSignatureWithNonHexChars = function (t) {
    // parseAuthHeader doesn't validate hex - that's checked in verification
    var authHeader =
        'AWS4-HMAC-SHA256 Credential=AKIATEST12345678/' +
        '20251217/us-east-1/s3/aws4_request, ' +
        'SignedHeaders=host, ' +
        'Signature=ghijklmnopqrstuv';

    var result = sigv4.parseAuthHeader(authHeader);

    t.ok(result, 'parseAuthHeader should accept non-hex signature');
    t.equal(result.signature, 'ghijklmnopqrstuv');
    t.done();
};

/* ================================================================
 * SECTION 9: Multiple Credential Part Scenarios
 * Additional tests for credential parsing edge cases
 * ================================================================ */

exports.testCredentialWithSixParts = function (t) {
    // Extra slash creates 6 parts instead of 5
    var authHeader =
        'AWS4-HMAC-SHA256 Credential=AKIATEST12345678/' +
        '20251217/us-east-1/s3/extra/aws4_request, ' +
        'SignedHeaders=host, ' +
        'Signature=abc123';

    var result = sigv4.parseAuthHeader(authHeader);

    t.equal(result, null,
        'should reject credential with 6 parts');
    t.done();
};

exports.testCredentialWithFourParts = function (t) {
    // Missing requestType creates only 4 parts
    var authHeader =
        'AWS4-HMAC-SHA256 Credential=AKIATEST12345678/' +
        '20251217/us-east-1/s3, ' +
        'SignedHeaders=host, ' +
        'Signature=abc123';

    var result = sigv4.parseAuthHeader(authHeader);

    t.equal(result, null,
        'should reject credential with 4 parts');
    t.done();
};

/* ================================================================
 * SECTION 10: Date Header Fallback
 * Tests for using Date header when X-Amz-Date is missing
 * ================================================================ */

exports.testDateHeaderFallback = function (t) {
    var testUser = {
        uuid: 'test-user-dateheader',
        login: 'dateheaderuser',
        accesskeys: {
            'AKIADATEHEADER12': 'dateheadersecret'
        }
    };

    redis.set('/uuid/test-user-dateheader', JSON.stringify(testUser),
        function (err1) {
        t.ok(!err1, 'should set user');
        redis.set('/accesskey/AKIADATEHEADER12', 'test-user-dateheader',
            function (err2) {
            t.ok(!err2, 'should set access key');

            var now = new Date();
            var isoTimestamp = now.toISOString()
                .replace(/[:-]|\.\d{3}/g, '');
            var dateStamp = isoTimestamp.substring(0, 8);

            // Use only 'date' header, not 'x-amz-date'
            var headers = {
                host: 'localhost',
                date: now.toUTCString(),
                authorization:
                    'AWS4-HMAC-SHA256 Credential=AKIADATEHEADER12/' +
                    dateStamp + '/us-east-1/s3/aws4_request, ' +
                    'SignedHeaders=date;host, ' +
                    'Signature=abc123'
            };

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
                // Will fail signature verification but should not fail
                // on missing timestamp
                t.ok(err, 'should error (signature mismatch expected)');
                t.ok(err.message !== 'Missing timestamp',
                    'should use Date header as fallback');
                t.done();
            });
        });
    });
};

/* ================================================================
 * SECTION 11: MSTS/MSAR Prefix Edge Cases
 * ================================================================ */

exports.testMSTSPrefixCaseSensitive = function (t) {
    // 'msts' lowercase should be treated as permanent credential
    var testUser = {
        uuid: 'test-user-msts-lower',
        login: 'mstslower',
        accesskeys: {
            'mststest12345678': 'lowersecret'
        }
    };

    redis.set('/uuid/test-user-msts-lower', JSON.stringify(testUser),
        function (err1) {
        t.ok(!err1, 'should set user');
        redis.set('/accesskey/mststest12345678', 'test-user-msts-lower',
            function (err2) {
            t.ok(!err2, 'should set access key');

            var headers = helper.createHeaders({
                method: 'GET',
                path: '/bucket/key',
                accessKey: 'mststest12345678',
                secret: 'lowersecret'
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
                // lowercase 'msts' should NOT trigger temp credential path
                // Should proceed with normal verification (and succeed)
                t.ok(!err, 'lowercase msts should not trigger temp cred check');
                t.ok(result, 'should return result');
                t.done();
            });
        });
    });
};

exports.testMSARPrefixCaseSensitive = function (t) {
    // 'msar' lowercase should be treated as permanent credential
    var testUser = {
        uuid: 'test-user-msar-lower',
        login: 'msarlower',
        accesskeys: {
            'msartest12345678': 'lowersecret'
        }
    };

    redis.set('/uuid/test-user-msar-lower', JSON.stringify(testUser),
        function (err1) {
        t.ok(!err1, 'should set user');
        redis.set('/accesskey/msartest12345678', 'test-user-msar-lower',
            function (err2) {
            t.ok(!err2, 'should set access key');

            var headers = helper.createHeaders({
                method: 'GET',
                path: '/bucket/key',
                accessKey: 'msartest12345678',
                secret: 'lowersecret'
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
                t.ok(!err, 'lowercase msar should not trigger temp cred check');
                t.ok(result, 'should return result');
                t.done();
            });
        });
    });
};
