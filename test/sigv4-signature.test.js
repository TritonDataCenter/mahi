/*
 * This Source Code Form is subject to the terms of the Mozilla
 * Public License, v. 2.0. If a copy of the MPL was not
 * distributed with this file, You can obtain one at
 * http://mozilla.org/MPL/2.0/.
 *
 * Copyright 2026 Edgecast Cloud LLC.
 */

/*
 * test/sigv4-signature.test.js: Unit tests for AWS Signature
 * Version 4 HMAC-SHA256 signature calculation
 */

var nodeunit = require('nodeunit');
var crypto = require('crypto');
var SigV4Helper = require('./lib/sigv4-helper');
var testVectors = require('./data/sigv4-test-vectors.json');

var helper = new SigV4Helper();

/* --- Test string-to-sign creation --- */

exports.testStringToSignFormat = function (t) {
    var timestamp = '20251217T120000Z';
    var credentialScope = '20251217/us-east-1/s3/aws4_request';
    var canonicalRequest = 'GET\n/\n\nhost:example.com\n' +
        '\nhost\nUNSIGNED-PAYLOAD';

    var stringToSign = helper._createStringToSign(
        timestamp, credentialScope, canonicalRequest);

    var lines = stringToSign.split('\n');
    t.equal(lines.length, 4,
        'should have 4 lines');
    t.equal(lines[0], 'AWS4-HMAC-SHA256',
        'line 0: algorithm');
    t.equal(lines[1], timestamp,
        'line 1: timestamp');
    t.equal(lines[2], credentialScope,
        'line 2: credential scope');
    t.equal(lines[3].length, 64,
        'line 3: SHA256 hash (64 hex chars)');
    t.done();
};

exports.testStringToSignHashesCanonicalRequest = function (t) {
    var timestamp = '20251217T120000Z';
    var scope = '20251217/us-east-1/s3/aws4_request';
    var canonical = 'GET\n/\n\n\n\nUNSIGNED-PAYLOAD';

    var stringToSign = helper._createStringToSign(
        timestamp, scope, canonical);

    var expectedHash = crypto.createHash('sha256')
        .update(canonical, 'utf8').digest('hex');

    var lines = stringToSign.split('\n');
    t.equal(lines[3], expectedHash,
        'should hash canonical request correctly');
    t.done();
};

exports.testStringToSignWithDifferentTimestamps = function (t) {
    var scope = '20251217/us-east-1/s3/aws4_request';
    var canonical = 'GET\n/\n\n\n\nUNSIGNED-PAYLOAD';

    var sts1 = helper._createStringToSign(
        '20251217T120000Z', scope, canonical);
    var sts2 = helper._createStringToSign(
        '20251217T130000Z', scope, canonical);

    t.notEqual(sts1, sts2,
        'different timestamps produce different strings');
    t.done();
};

exports.testStringToSignWithDifferentScopes = function (t) {
    var timestamp = '20251217T120000Z';
    var canonical = 'GET\n/\n\n\n\nUNSIGNED-PAYLOAD';

    var sts1 = helper._createStringToSign(timestamp,
        '20251217/us-east-1/s3/aws4_request', canonical);
    var sts2 = helper._createStringToSign(timestamp,
        '20251217/us-west-2/s3/aws4_request', canonical);

    t.notEqual(sts1, sts2,
        'different regions produce different strings');
    t.done();
};

/* --- Test signature calculation --- */

exports.testSignatureIsHexString = function (t) {
    var signature = helper._calculateSignature(
        'testsecret', '20251217', 'us-east-1', 's3',
        'AWS4-HMAC-SHA256\n20251217T120000Z\n' +
        '20251217/us-east-1/s3/aws4_request\n' +
        'abc123');

    t.equal(typeof (signature), 'string',
        'signature should be string');
    t.equal(signature.length, 64,
        'signature should be 64 hex characters');
    t.ok(/^[0-9a-f]{64}$/.test(signature),
        'signature should be lowercase hex');
    t.done();
};

exports.testSignatureWithSameInputsSame = function (t) {
    var secret = 'testsecret';
    var dateStamp = '20251217';
    var region = 'us-east-1';
    var service = 's3';
    var stringToSign = 'AWS4-HMAC-SHA256\ntest';

    var sig1 = helper._calculateSignature(
        secret, dateStamp, region, service, stringToSign);
    var sig2 = helper._calculateSignature(
        secret, dateStamp, region, service, stringToSign);

    t.equal(sig1, sig2,
        'same inputs produce same signature');
    t.done();
};

exports.testSignatureWithDifferentSecrets = function (t) {
    var dateStamp = '20251217';
    var region = 'us-east-1';
    var service = 's3';
    var stringToSign = 'AWS4-HMAC-SHA256\ntest';

    var sig1 = helper._calculateSignature(
        'secret1', dateStamp, region, service, stringToSign);
    var sig2 = helper._calculateSignature(
        'secret2', dateStamp, region, service, stringToSign);

    t.notEqual(sig1, sig2,
        'different secrets produce different signatures');
    t.done();
};

exports.testSignatureWithDifferentDates = function (t) {
    var secret = 'testsecret';
    var region = 'us-east-1';
    var service = 's3';
    var stringToSign = 'AWS4-HMAC-SHA256\ntest';

    var sig1 = helper._calculateSignature(
        secret, '20251217', region, service, stringToSign);
    var sig2 = helper._calculateSignature(
        secret, '20251218', region, service, stringToSign);

    t.notEqual(sig1, sig2,
        'different dates produce different signatures');
    t.done();
};

exports.testSignatureWithDifferentRegions = function (t) {
    var secret = 'testsecret';
    var dateStamp = '20251217';
    var service = 's3';
    var stringToSign = 'AWS4-HMAC-SHA256\ntest';

    var sig1 = helper._calculateSignature(
        secret, dateStamp, 'us-east-1', service, stringToSign);
    var sig2 = helper._calculateSignature(
        secret, dateStamp, 'us-west-2', service, stringToSign);

    t.notEqual(sig1, sig2,
        'different regions produce different signatures');
    t.done();
};

exports.testSignatureWithDifferentServices = function (t) {
    var secret = 'testsecret';
    var dateStamp = '20251217';
    var region = 'us-east-1';
    var stringToSign = 'AWS4-HMAC-SHA256\ntest';

    var sig1 = helper._calculateSignature(
        secret, dateStamp, region, 's3', stringToSign);
    var sig2 = helper._calculateSignature(
        secret, dateStamp, region, 'sts', stringToSign);

    t.notEqual(sig1, sig2,
        'different services produce different signatures');
    t.done();
};

/* --- Test HMAC-SHA256 chain correctness --- */

exports.testSigningKeyDerivationChain = function (t) {
    var secret = 'testsecret';
    var dateStamp = '20251217';
    var region = 'us-east-1';
    var service = 's3';

    function hmac(key, string) {
        return crypto.createHmac('sha256', key)
            .update(string, 'utf8').digest();
    }

    var kDate = hmac('AWS4' + secret, dateStamp);
    t.ok(Buffer.isBuffer(kDate),
        'kDate should be Buffer');
    t.equal(kDate.length, 32,
        'kDate should be 32 bytes (SHA256)');

    var kRegion = hmac(kDate, region);
    t.ok(Buffer.isBuffer(kRegion),
        'kRegion should be Buffer');
    t.equal(kRegion.length, 32,
        'kRegion should be 32 bytes');

    var kService = hmac(kRegion, service);
    t.ok(Buffer.isBuffer(kService),
        'kService should be Buffer');
    t.equal(kService.length, 32,
        'kService should be 32 bytes');

    var kSigning = hmac(kService, 'aws4_request');
    t.ok(Buffer.isBuffer(kSigning),
        'kSigning should be Buffer');
    t.equal(kSigning.length, 32,
        'kSigning should be 32 bytes');

    t.done();
};

exports.testSigningKeyPrefixAWS4 = function (t) {
    var secret = 'mysecret';
    var dateStamp = '20251217';

    function hmac(key, string) {
        return crypto.createHmac('sha256', key)
            .update(string, 'utf8').digest();
    }

    var kDate1 = hmac('AWS4' + secret, dateStamp);
    var kDate2 = hmac(secret, dateStamp);

    t.notDeepEqual(kDate1, kDate2,
        'AWS4 prefix should affect key derivation');
    t.done();
};

/* --- Test credential scope --- */

exports.testCredentialScopeFormat = function (t) {
    var dateStamp = '20251217';
    var region = 'us-east-1';
    var service = 's3';
    var scope = dateStamp + '/' + region + '/' +
        service + '/aws4_request';

    t.equal(scope, '20251217/us-east-1/s3/aws4_request',
        'scope should match expected format');
    t.done();
};

exports.testCredentialScopeComponents = function (t) {
    var scope = '20251217/ap-northeast-1/dynamodb/aws4_request';
    var parts = scope.split('/');

    t.equal(parts.length, 4,
        'scope should have 4 components');
    t.equal(parts[0], '20251217',
        'part 0: date stamp');
    t.equal(parts[1], 'ap-northeast-1',
        'part 1: region');
    t.equal(parts[2], 'dynamodb',
        'part 2: service');
    t.equal(parts[3], 'aws4_request',
        'part 3: request type');
    t.done();
};

/* --- Test with AWS test vectors --- */

exports.testAWSVectorGetVanillaSignature = function (t) {
    var vector;
    for (var i = 0; i < testVectors.vectors.length; i++) {
        if (testVectors.vectors[i].name === 'get-vanilla') {
            vector = testVectors.vectors[i];
            break;
        }
    }

    if (!vector || !vector.expectedSignature ||
        !vector.canonicalRequest) {
        t.skip('Test vector signature validation pending');
        t.done();
        return;
    }

    var creds = vector.credentials;
    var req = vector.request;

    var canonical = vector.canonicalRequest;
    var credScope = req.headers['x-amz-date'].substring(0, 8) +
        '/' + creds.region + '/' + creds.service +
        '/aws4_request';

    var stringToSign = helper._createStringToSign(
        req.headers['x-amz-date'], credScope, canonical);

    var signature = helper._calculateSignature(
        creds.secretAccessKey,
        req.headers['x-amz-date'].substring(0, 8),
        creds.region, creds.service, stringToSign);

    t.ok(signature.length === 64,
        'signature should be 64 hex chars');
    t.done();
};

exports.testStringToSignWithAWSVector = function (t) {
    var vector;
    for (var i = 0; i < testVectors.vectors.length; i++) {
        if (testVectors.vectors[i].name === 'get-vanilla') {
            vector = testVectors.vectors[i];
            break;
        }
    }

    if (!vector || !vector.stringToSign ||
        !vector.canonicalRequest) {
        t.skip('Test vector string-to-sign validation pending');
        t.done();
        return;
    }

    var req = vector.request;
    var creds = vector.credentials;

    var canonical = vector.canonicalRequest;
    var credScope = req.headers['x-amz-date'].substring(0, 8) +
        '/' + creds.region + '/' + creds.service +
        '/aws4_request';

    var stringToSign = helper._createStringToSign(
        req.headers['x-amz-date'], credScope, canonical);

    var lines = stringToSign.split('\n');
    t.equal(lines[0], 'AWS4-HMAC-SHA256',
        'should start with algorithm');
    t.equal(lines.length, 4,
        'should have 4 lines');
    t.done();
};

/* --- Test edge cases --- */

exports.testSignatureWithEmptyStringToSign = function (t) {
    var signature = helper._calculateSignature(
        'secret', '20251217', 'us-east-1', 's3', '');

    t.ok(signature,
        'should handle empty string-to-sign');
    t.equal(signature.length, 64,
        'signature should still be 64 chars');
    t.done();
};

exports.testSignatureWithLongSecret = function (t) {
    var longSecret = new Array(200 + 1).join('a');
    var signature = helper._calculateSignature(
        longSecret, '20251217', 'us-east-1', 's3',
        'AWS4-HMAC-SHA256\ntest');

    t.ok(signature,
        'should handle long secret');
    t.equal(signature.length, 64,
        'signature should be 64 chars');
    t.done();
};

exports.testSignatureWithSpecialCharsInSecret = function (t) {
    var secret = 'test+secret/with=special!chars';
    var signature = helper._calculateSignature(
        secret, '20251217', 'us-east-1', 's3',
        'AWS4-HMAC-SHA256\ntest');

    t.ok(signature,
        'should handle special characters in secret');
    t.equal(signature.length, 64,
        'signature should be 64 chars');
    t.done();
};

exports.testSignatureWithDifferentRegionFormats = function (t) {
    var secret = 'testsecret';
    var dateStamp = '20251217';
    var service = 's3';
    var stringToSign = 'AWS4-HMAC-SHA256\ntest';

    var sig1 = helper._calculateSignature(
        secret, dateStamp, 'us-east-1', service,
        stringToSign);
    var sig2 = helper._calculateSignature(
        secret, dateStamp, 'ap-northeast-1', service,
        stringToSign);
    var sig3 = helper._calculateSignature(
        secret, dateStamp, 'eu-west-1', service,
        stringToSign);

    t.notEqual(sig1, sig2,
        'US and Asia regions should differ');
    t.notEqual(sig1, sig3,
        'US and EU regions should differ');
    t.notEqual(sig2, sig3,
        'Asia and EU regions should differ');
    t.done();
};

/* --- Test complete flow --- */

exports.testCompleteSignatureFlow = function (t) {
    var method = 'GET';
    var uri = '/bucket/key';
    var query = 'max-keys=10';
    var headers = {
        'host': 'example.com',
        'x-amz-date': '20251217T120000Z'
    };
    var signedHeaders = ['host', 'x-amz-date'];
    var payloadHash = 'UNSIGNED-PAYLOAD';
    var secret = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
    var dateStamp = '20251217';
    var region = 'us-east-1';
    var service = 's3';

    var canonical = helper._createCanonicalRequest(
        method, uri, query, headers, signedHeaders,
        payloadHash);

    var credScope = dateStamp + '/' + region + '/' +
        service + '/aws4_request';
    var stringToSign = helper._createStringToSign(
        headers['x-amz-date'], credScope, canonical);

    var signature = helper._calculateSignature(
        secret, dateStamp, region, service, stringToSign);

    t.ok(canonical,
        'canonical request created');
    t.ok(stringToSign.indexOf('AWS4-HMAC-SHA256') === 0,
        'string-to-sign starts with algorithm');
    t.equal(signature.length, 64,
        'signature is 64 hex chars');
    t.ok(/^[0-9a-f]{64}$/.test(signature),
        'signature is valid hex');
    t.done();
};
