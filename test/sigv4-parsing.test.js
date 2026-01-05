/*
 * This Source Code Form is subject to the terms of the Mozilla
 * Public License, v. 2.0. If a copy of the MPL was not
 * distributed with this file, You can obtain one at
 * http://mozilla.org/MPL/2.0/.
 *
 * Copyright 2026 Edgecast Cloud LLC.
 */

/*
 * test/sigv4-parsing.test.js: Unit tests for AWS Signature
 * Version 4 authorization header parsing
 */

var nodeunit = require('nodeunit');
var sigv4 = require('../lib/server/sigv4');

/* --- Test valid authorization header parsing --- */

exports.testValidHeaderParsing = function (t) {
    var authHeader =
        'AWS4-HMAC-SHA256 Credential=f0d8040a65d0c47f958d3bfe46dc6510/' +
        '20130524/us-east-1/s3/aws4_request, ' +
        'SignedHeaders=host;range;x-amz-date, ' +
        'Signature=fe5f80f77d5fa3beca038a248ff027';

    var result = sigv4.parseAuthHeader(authHeader);

    t.ok(result, 'should return parsed result');
    t.equal(result.accessKeyId, 'f0d8040a65d0c47f958d3bfe46dc6510',
        'should extract accessKeyId');
    t.equal(result.dateStamp, '20130524',
        'should extract dateStamp');
    t.equal(result.region, 'us-east-1',
        'should extract region');
    t.equal(result.service, 's3',
        'should extract service');
    t.equal(result.requestType, 'aws4_request',
        'should extract requestType');
    t.ok(Array.isArray(result.signedHeaders),
        'signedHeaders should be array');
    t.deepEqual(result.signedHeaders,
        ['host', 'range', 'x-amz-date'],
        'should extract signedHeaders');
    t.equal(result.signature,
        'fe5f80f77d5fa3beca038a248ff027',
        'should extract signature');
    t.done();
};

exports.testMinimalValidHeader = function (t) {
    var authHeader =
        'AWS4-HMAC-SHA256 Credential=6ea33abf502acd6ee6cbe5534e1fe4e0/' +
        '20251217/us-west-2/s3/aws4_request, ' +
        'SignedHeaders=host, ' +
        'Signature=abc123';

    var result = sigv4.parseAuthHeader(authHeader);

    t.ok(result, 'should parse minimal valid header');
    t.equal(result.accessKeyId, '6ea33abf502acd6ee6cbe5534e1fe4e0');
    t.equal(result.dateStamp, '20251217');
    t.equal(result.region, 'us-west-2');
    t.equal(result.service, 's3');
    t.deepEqual(result.signedHeaders, ['host']);
    t.equal(result.signature, 'abc123');
    t.done();
};

exports.testHeaderWithMultipleSignedHeaders = function (t) {
    var authHeader =
        'AWS4-HMAC-SHA256 Credential=6ea33abf502acd6ee6cbe5534e1fe4e0/' +
        '20251217/us-east-1/s3/aws4_request, ' +
        'SignedHeaders=content-type;host;x-amz-content-sha256;' +
        'x-amz-date;x-amz-security-token, ' +
        'Signature=fedcba987654321';

    var result = sigv4.parseAuthHeader(authHeader);

    t.ok(result);
    t.equal(result.signedHeaders.length, 5,
        'should parse all signed headers');
    t.deepEqual(result.signedHeaders, [
        'content-type',
        'host',
        'x-amz-content-sha256',
        'x-amz-date',
        'x-amz-security-token'
    ]);
    t.done();
};

/* --- Test malformed header rejection --- */

exports.testNullHeader = function (t) {
    var result = sigv4.parseAuthHeader(null);
    t.equal(result, null,
        'should return null for null header');
    t.done();
};

exports.testUndefinedHeader = function (t) {
    var result = sigv4.parseAuthHeader(undefined);
    t.equal(result, null,
        'should return null for undefined header');
    t.done();
};

exports.testEmptyStringHeader = function (t) {
    var result = sigv4.parseAuthHeader('');
    t.equal(result, null,
        'should return null for empty string');
    t.done();
};

exports.testNonSigV4Header = function (t) {
    var result = sigv4.parseAuthHeader('Basic dXNlcjpwYXNz');
    t.equal(result, null,
        'should return null for non-SigV4 auth');
    t.done();
};

exports.testWrongAlgorithm = function (t) {
    var authHeader =
        'AWS4-HMAC-SHA1 Credential=6ea33abf502acd6ee6cbe5534e1fe4e0/' +
        '20251217/us-east-1/s3/aws4_request, ' +
        'SignedHeaders=host, ' +
        'Signature=abc123';

    var result = sigv4.parseAuthHeader(authHeader);
    t.equal(result, null,
        'should reject wrong algorithm');
    t.done();
};

exports.testMissingCredential = function (t) {
    var authHeader =
        'AWS4-HMAC-SHA256 SignedHeaders=host, ' +
        'Signature=abc123';

    var result = sigv4.parseAuthHeader(authHeader);

    t.ok(result, 'should return result object');
    t.equal(result.accessKeyId, undefined,
        'accessKeyId should be undefined');
    t.ok(result.signedHeaders, 'should have signedHeaders');
    t.ok(result.signature, 'should have signature');
    t.done();
};

exports.testMissingSignedHeaders = function (t) {
    var authHeader =
        'AWS4-HMAC-SHA256 Credential=6ea33abf502acd6ee6cbe5534e1fe4e0/' +
        '20251217/us-east-1/s3/aws4_request, ' +
        'Signature=abc123';

    var result = sigv4.parseAuthHeader(authHeader);

    t.ok(result);
    t.equal(result.accessKeyId, '6ea33abf502acd6ee6cbe5534e1fe4e0');
    t.equal(result.signedHeaders, undefined,
        'signedHeaders should be undefined when missing');
    t.equal(result.signature, 'abc123');
    t.done();
};

exports.testMissingSignature = function (t) {
    var authHeader =
        'AWS4-HMAC-SHA256 Credential=6ea33abf502acd6ee6cbe5534e1fe4e0/' +
        '20251217/us-east-1/s3/aws4_request, ' +
        'SignedHeaders=host';

    var result = sigv4.parseAuthHeader(authHeader);

    t.ok(result);
    t.equal(result.accessKeyId, '6ea33abf502acd6ee6cbe5534e1fe4e0');
    t.ok(result.signedHeaders);
    t.equal(result.signature, undefined,
        'signature should be undefined when missing');
    t.done();
};

exports.testMalformedCredential = function (t) {
    var authHeader =
        'AWS4-HMAC-SHA256 Credential=6ea33abf502acd6ee6cbe5534e1fe4e0, ' +
        'SignedHeaders=host, ' +
        'Signature=abc123';

    var result = sigv4.parseAuthHeader(authHeader);

    t.equal(result, null,
        'should reject incomplete credential (missing parts)');
    t.done();
};

exports.testIncompleteDateStamp = function (t) {
    var authHeader =
        'AWS4-HMAC-SHA256 ' +
        'Credential=6ea33abf502acd6ee6cbe5534e1fe4e0/202512, ' +
        'SignedHeaders=host, Signature=abc123';

    var result = sigv4.parseAuthHeader(authHeader);

    t.equal(result, null,
        'should reject incomplete credential (only 2 parts)');
    t.done();
};

/* --- Test edge cases --- */

exports.testExtraWhitespace = function (t) {
    var authHeader =
        'AWS4-HMAC-SHA256  Credential=6ea33abf502acd6ee6cbe5534e1fe4e0/' +
        '20251217/us-east-1/s3/aws4_request,  ' +
        'SignedHeaders=host,  Signature=abc123';

    var result = sigv4.parseAuthHeader(authHeader);

    t.ok(result, 'should return object');
    t.equal(result.accessKeyId, undefined,
        'extra space breaks credential parsing');
    t.ok(result.signedHeaders,
        'should still parse signedHeaders');
    t.ok(result.signature,
        'should still parse signature');
    t.done();
};

exports.testNoWhitespaceAfterComma = function (t) {
    var authHeader =
        'AWS4-HMAC-SHA256 Credential=6ea33abf502acd6ee6cbe5534e1fe4e0/' +
        '20251217/us-east-1/s3/aws4_request,' +
        'SignedHeaders=host,' +
        'Signature=abc123';

    var result = sigv4.parseAuthHeader(authHeader);

    t.ok(result, 'should handle no whitespace after comma');
    t.equal(result.accessKeyId, '6ea33abf502acd6ee6cbe5534e1fe4e0');
    t.done();
};

exports.testEmptySignedHeaders = function (t) {
    var authHeader =
        'AWS4-HMAC-SHA256 Credential=6ea33abf502acd6ee6cbe5534e1fe4e0/' +
        '20251217/us-east-1/s3/aws4_request, ' +
        'SignedHeaders=, ' +
        'Signature=abc123';

    var result = sigv4.parseAuthHeader(authHeader);

    t.ok(result);
    t.ok(Array.isArray(result.signedHeaders),
        'signedHeaders should be array');
    t.equal(result.signedHeaders.length, 1,
        'empty string creates single-element array');
    t.equal(result.signedHeaders[0], '',
        'single element should be empty string');
    t.done();
};

exports.testLongSignature = function (t) {
    var longSig =
        new Array(64 + 1).join('a');
    var authHeader =
        'AWS4-HMAC-SHA256 Credential=6ea33abf502acd6ee6cbe5534e1fe4e0/' +
        '20251217/us-east-1/s3/aws4_request, ' +
        'SignedHeaders=host, ' +
        'Signature=' + longSig;

    var result = sigv4.parseAuthHeader(authHeader);

    t.ok(result);
    t.equal(result.signature.length, 64,
        'should handle long signature');
    t.equal(result.signature, longSig);
    t.done();
};

exports.testSpecialCharsInAccessKeyId = function (t) {
    var authHeader =
        'AWS4-HMAC-SHA256 Credential=AKIA+TEST/KEY/' +
        '20251217/us-east-1/s3/aws4_request, ' +
        'SignedHeaders=host, ' +
        'Signature=abc123';

    var result = sigv4.parseAuthHeader(authHeader);

    t.equal(result, null,
        'should reject credential with slash in accessKeyId (6 parts)');
    t.done();
};

exports.testDifferentService = function (t) {
    var authHeader =
        'AWS4-HMAC-SHA256 Credential=6ea33abf502acd6ee6cbe5534e1fe4e0/' +
        '20251217/ap-northeast-1/dynamodb/aws4_request, ' +
        'SignedHeaders=host, ' +
        'Signature=abc123';

    var result = sigv4.parseAuthHeader(authHeader);

    t.ok(result);
    t.equal(result.region, 'ap-northeast-1');
    t.equal(result.service, 'dynamodb',
        'should support non-s3 services');
    t.done();
};

exports.testCaseSensitivity = function (t) {
    var authHeader =
        'AWS4-HMAC-SHA256 credential=6ea33abf502acd6ee6cbe5534e1fe4e0/' +
        '20251217/us-east-1/s3/aws4_request, ' +
        'signedheaders=host, ' +
        'signature=abc123';

    var result = sigv4.parseAuthHeader(authHeader);

    t.ok(result);
    t.equal(result.accessKeyId, undefined,
        'credential key is case-sensitive');
    t.equal(result.signedHeaders, undefined,
        'signedHeaders key is case-sensitive');
    t.equal(result.signature, undefined,
        'signature key is case-sensitive');
    t.done();
};

/* --- Test credential validation (strict parsing) --- */

exports.testEmptyCredentialPart = function (t) {
    var authHeader =
        'AWS4-HMAC-SHA256 Credential=6ea33abf502acd6ee6cbe5534e1fe4e0//' +
        'us-east-1/s3/aws4_request, ' +
        'SignedHeaders=host, ' +
        'Signature=abc123';

    var result = sigv4.parseAuthHeader(authHeader);

    t.equal(result, null,
        'should reject credential with empty part');
    t.done();
};

exports.testWhitespaceOnlyCredentialPart = function (t) {
    var authHeader =
        'AWS4-HMAC-SHA256 ' +
        'Credential=6ea33abf502acd6ee6cbe5534e1fe4e0/20251217/ /' +
        's3/aws4_request, ' +
        'SignedHeaders=host, ' +
        'Signature=abc123';

    var result = sigv4.parseAuthHeader(authHeader);

    t.equal(result, null,
        'should reject credential with whitespace-only part');
    t.done();
};

exports.testInvalidDateStampFormat = function (t) {
    var authHeader =
        'AWS4-HMAC-SHA256 Credential=6ea33abf502acd6ee6cbe5534e1fe4e0/' +
        '2025-12-17/us-east-1/s3/aws4_request, ' +
        'SignedHeaders=host, ' +
        'Signature=abc123';

    var result = sigv4.parseAuthHeader(authHeader);

    t.equal(result, null,
        'should reject dateStamp with dashes (must be YYYYMMDD)');
    t.done();
};

exports.testDateStampTooShort = function (t) {
    var authHeader =
        'AWS4-HMAC-SHA256 Credential=6ea33abf502acd6ee6cbe5534e1fe4e0/' +
        '2025121/us-east-1/s3/aws4_request, ' +
        'SignedHeaders=host, ' +
        'Signature=abc123';

    var result = sigv4.parseAuthHeader(authHeader);

    t.equal(result, null,
        'should reject dateStamp with only 7 digits');
    t.done();
};

exports.testDateStampTooLong = function (t) {
    var authHeader =
        'AWS4-HMAC-SHA256 Credential=6ea33abf502acd6ee6cbe5534e1fe4e0/' +
        '202512170/us-east-1/s3/aws4_request, ' +
        'SignedHeaders=host, ' +
        'Signature=abc123';

    var result = sigv4.parseAuthHeader(authHeader);

    t.equal(result, null,
        'should reject dateStamp with 9 digits');
    t.done();
};

exports.testNonNumericDateStamp = function (t) {
    var authHeader =
        'AWS4-HMAC-SHA256 Credential=6ea33abf502acd6ee6cbe5534e1fe4e0/' +
        'DATEHERE/us-east-1/s3/aws4_request, ' +
        'SignedHeaders=host, ' +
        'Signature=abc123';

    var result = sigv4.parseAuthHeader(authHeader);

    t.equal(result, null,
        'should reject non-numeric dateStamp');
    t.done();
};

exports.testInvalidRequestType = function (t) {
    var authHeader =
        'AWS4-HMAC-SHA256 Credential=6ea33abf502acd6ee6cbe5534e1fe4e0/' +
        '20251217/us-east-1/s3/aws4, ' +
        'SignedHeaders=host, ' +
        'Signature=abc123';

    var result = sigv4.parseAuthHeader(authHeader);

    t.equal(result, null,
        'should reject requestType != "aws4_request"');
    t.done();
};

exports.testRequestTypeWithExtraText = function (t) {
    var authHeader =
        'AWS4-HMAC-SHA256 Credential=6ea33abf502acd6ee6cbe5534e1fe4e0/' +
        '20251217/us-east-1/s3/aws4_request_extra, ' +
        'SignedHeaders=host, ' +
        'Signature=abc123';

    var result = sigv4.parseAuthHeader(authHeader);

    t.equal(result, null,
        'should reject requestType with extra characters');
    t.done();
};

/* --- Test accessKeyId validation (sdc-ufds schema) --- */

exports.testAccessKeyIdTooShort = function (t) {
    var authHeader =
        'AWS4-HMAC-SHA256 Credential=AKIATEST/' +
        '20251217/us-east-1/s3/aws4_request, ' +
        'SignedHeaders=host, ' +
        'Signature=abc123';

    var result = sigv4.parseAuthHeader(authHeader);

    t.equal(result, null,
        'should reject accessKeyId shorter than 16 characters');
    t.done();
};

exports.testAccessKeyIdTooLong = function (t) {
    // Generate a 129-character accessKeyId
    var longKey = new Array(130).join('A');
    var authHeader =
        'AWS4-HMAC-SHA256 Credential=' + longKey + '/' +
        '20251217/us-east-1/s3/aws4_request, ' +
        'SignedHeaders=host, ' +
        'Signature=abc123';

    var result = sigv4.parseAuthHeader(authHeader);

    t.equal(result, null,
        'should reject accessKeyId longer than 128 characters');
    t.done();
};

exports.testAccessKeyIdInvalidCharacters = function (t) {
    var authHeader =
        'AWS4-HMAC-SHA256 Credential=AKIA+TEST-KEY123/' +
        '20251217/us-east-1/s3/aws4_request, ' +
        'SignedHeaders=host, ' +
        'Signature=abc123';

    var result = sigv4.parseAuthHeader(authHeader);

    t.equal(result, null,
        'should reject accessKeyId with non-word characters (+, -)');
    t.done();
};

exports.testAccessKeyIdWithSlash = function (t) {
    var authHeader =
        'AWS4-HMAC-SHA256 Credential=AKIA/TEST1234567/' +
        '20251217/us-east-1/s3/aws4_request, ' +
        'SignedHeaders=host, ' +
        'Signature=abc123';

    var result = sigv4.parseAuthHeader(authHeader);

    t.equal(result, null,
        'should reject accessKeyId containing slash');
    t.done();
};

exports.testAccessKeyIdWithSpace = function (t) {
    var authHeader =
        'AWS4-HMAC-SHA256 Credential=AKIA TEST1234567/' +
        '20251217/us-east-1/s3/aws4_request, ' +
        'SignedHeaders=host, ' +
        'Signature=abc123';

    var result = sigv4.parseAuthHeader(authHeader);

    t.equal(result, null,
        'should reject accessKeyId containing space');
    t.done();
};

exports.testAccessKeyIdMinLength = function (t) {
    var authHeader =
        'AWS4-HMAC-SHA256 Credential=6ea33abf502acd6ee6cbe5534e1fe4e0/' +
        '20251217/us-east-1/s3/aws4_request, ' +
        'SignedHeaders=host, ' +
        'Signature=abc123';

    var result = sigv4.parseAuthHeader(authHeader);

    t.ok(result, 'should accept accessKeyId with exactly 16 characters');
    t.equal(result.accessKeyId, '6ea33abf502acd6ee6cbe5534e1fe4e0');
    t.done();
};

exports.testAccessKeyIdMaxLength = function (t) {
    // Generate a 128-character accessKeyId
    var maxKey = new Array(129).join('A');
    var authHeader =
        'AWS4-HMAC-SHA256 Credential=' + maxKey + '/' +
        '20251217/us-east-1/s3/aws4_request, ' +
        'SignedHeaders=host, ' +
        'Signature=abc123';

    var result = sigv4.parseAuthHeader(authHeader);

    t.ok(result, 'should accept accessKeyId with exactly 128 characters');
    t.equal(result.accessKeyId, maxKey);
    t.done();
};

exports.testAccessKeyIdWithUnderscore = function (t) {
    var authHeader =
        'AWS4-HMAC-SHA256 Credential=6ea33abf_502acd6e_e6cbe5534e1fe4e0/' +
        '20251217/us-east-1/s3/aws4_request, ' +
        'SignedHeaders=host, ' +
        'Signature=abc123';

    var result = sigv4.parseAuthHeader(authHeader);

    t.ok(result, 'should accept accessKeyId with underscores');
    t.equal(result.accessKeyId, '6ea33abf_502acd6e_e6cbe5534e1fe4e0');
    t.done();
};
