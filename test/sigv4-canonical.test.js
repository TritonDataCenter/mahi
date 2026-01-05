/*
 * This Source Code Form is subject to the terms of the Mozilla
 * Public License, v. 2.0. If a copy of the MPL was not
 * distributed with this file, You can obtain one at
 * http://mozilla.org/MPL/2.0/.
 *
 * Copyright 2026 Edgecast Cloud LLC.
 */

/*
 * test/sigv4-canonical.test.js: Unit tests for AWS Signature
 * Version 4 canonical request creation
 */

var nodeunit = require('nodeunit');
var SigV4Helper = require('./lib/sigv4-helper');
var testVectors = require('./data/sigv4-test-vectors.json');

var helper = new SigV4Helper();

/* --- Test canonical URI creation --- */

exports.testSimpleURI = function (t) {
    var canonical = helper._createCanonicalRequest(
        'GET', '/', '', {},
        [], 'UNSIGNED-PAYLOAD');

    t.ok(canonical.indexOf('\n/\n') !== -1,
        'should have root path');
    t.done();
};

exports.testURIWithSegments = function (t) {
    var canonical = helper._createCanonicalRequest(
        'GET', '/bucket/key', '', {},
        [], 'UNSIGNED-PAYLOAD');

    t.ok(canonical.indexOf('\n/bucket/key\n') !== -1,
        'should preserve path segments');
    t.done();
};

exports.testURIWithSpaces = function (t) {
    var canonical = helper._createCanonicalRequest(
        'GET', '/my bucket/my key', '', {},
        [], 'UNSIGNED-PAYLOAD');

    t.ok(canonical.indexOf('/my%20bucket/my%20key') !== -1,
        'should encode spaces');
    t.done();
};

exports.testURIWithSpecialChars = function (t) {
    var canonical = helper._createCanonicalRequest(
        'GET', '/path/file!name', '', {},
        [], 'UNSIGNED-PAYLOAD');

    t.ok(canonical.indexOf('%21') !== -1,
        'should encode special characters');
    t.done();
};

exports.testURIWithUnreservedChars = function (t) {
    var canonical = helper._createCanonicalRequest(
        'GET', '/path-with_dots.and~tilde123ABC', '',
        {}, [], 'UNSIGNED-PAYLOAD');

    var lines = canonical.split('\n');
    var uri = lines[1];
    t.ok(uri.indexOf('-') !== -1,
        'hyphen should not be encoded');
    t.ok(uri.indexOf('_') !== -1,
        'underscore should not be encoded');
    t.ok(uri.indexOf('.') !== -1,
        'dot should not be encoded');
    t.ok(uri.indexOf('~') !== -1,
        'tilde should not be encoded');
    t.done();
};

/* --- Test canonical query string --- */

exports.testEmptyQueryString = function (t) {
    var canonical = helper._createCanonicalRequest(
        'GET', '/', '', {}, [], 'UNSIGNED-PAYLOAD');

    var lines = canonical.split('\n');
    t.equal(lines[2], '', 'should have empty query line');
    t.done();
};

exports.testSingleQueryParam = function (t) {
    var canonical = helper._createCanonicalRequest(
        'GET', '/', 'key=value', {},
        [], 'UNSIGNED-PAYLOAD');

    t.ok(canonical.indexOf('\nkey=value\n') !== -1,
        'should include query parameter');
    t.done();
};

exports.testQueryParamSorting = function (t) {
    var canonical = helper._createCanonicalRequest(
        'GET', '/', 'zebra=z&apple=a&middle=m', {},
        [], 'UNSIGNED-PAYLOAD');

    var lines = canonical.split('\n');
    var query = lines[2];
    var params = query.split('&');
    t.equal(params[0].split('=')[0], 'apple',
        'should sort alphabetically');
    t.equal(params[1].split('=')[0], 'middle');
    t.equal(params[2].split('=')[0], 'zebra');
    t.done();
};

exports.testQueryParamEncoding = function (t) {
    var canonical = helper._createCanonicalRequest(
        'GET', '/', 'key=value with spaces', {},
        [], 'UNSIGNED-PAYLOAD');

    t.ok(canonical.indexOf('key=value%20with%20spaces') !== -1,
        'should encode query values');
    t.done();
};

exports.testQueryParamWithEmptyValue = function (t) {
    var canonical = helper._createCanonicalRequest(
        'GET', '/', 'key=', {}, [], 'UNSIGNED-PAYLOAD');

    t.ok(canonical.indexOf('key=\n') !== -1,
        'should preserve empty value');
    t.done();
};

exports.testQueryParamWithNoValue = function (t) {
    var canonical = helper._createCanonicalRequest(
        'GET', '/', 'flag', {}, [], 'UNSIGNED-PAYLOAD');

    t.ok(canonical.indexOf('flag=') !== -1,
        'should add = for valueless param');
    t.done();
};

exports.testMultipleQueryParamsWithSameKey = function (t) {
    var canonical = helper._createCanonicalRequest(
        'GET', '/', 'tag=a&tag=b&tag=c', {},
        [], 'UNSIGNED-PAYLOAD');

    var lines = canonical.split('\n');
    var query = lines[2];
    var params = query.split('&');
    var tagParams = params.filter(function (p) {
        return (p.indexOf('tag') === 0);
    });
    t.equal(tagParams.length, 3,
        'should preserve multiple values for same key');
    t.done();
};

/* --- Test canonical headers --- */

exports.testSingleHeader = function (t) {
    var canonical = helper._createCanonicalRequest(
        'GET', '/', '', {host: 'example.com'},
        ['host'], 'UNSIGNED-PAYLOAD');

    t.ok(canonical.indexOf('host:example.com\n') !== -1,
        'should include header');
    t.done();
};

exports.testHeaderLowercasing = function (t) {
    var canonical = helper._createCanonicalRequest(
        'GET', '/', '',
        {Host: 'example.com', 'X-Amz-Date': '20251217T000000Z'},
        ['host', 'x-amz-date'], 'UNSIGNED-PAYLOAD');

    t.ok(canonical.indexOf('host:') !== -1,
        'header name should be lowercase');
    t.ok(canonical.indexOf('x-amz-date:') !== -1,
        'x-amz-date should be lowercase');
    t.done();
};

exports.testHeaderValueTrimming = function (t) {
    var canonical = helper._createCanonicalRequest(
        'GET', '/', '',
        {host: '  example.com  '},
        ['host'], 'UNSIGNED-PAYLOAD');

    t.ok(canonical.indexOf('host:example.com\n') !== -1,
        'should trim header value');
    t.done();
};

exports.testHeaderValueSpaceCollapsing = function (t) {
    var canonical = helper._createCanonicalRequest(
        'GET', '/', '',
        {host: 'example.com   test'},
        ['host'], 'UNSIGNED-PAYLOAD');

    t.ok(canonical.indexOf('host:example.com test\n') !== -1,
        'should collapse multiple spaces to one');
    t.done();
};

exports.testHeaderSorting = function (t) {
    var canonical = helper._createCanonicalRequest(
        'GET', '/', '', {
            'x-amz-date': '20251217T000000Z',
            'host': 'example.com',
            'content-type': 'text/plain'
        },
        ['x-amz-date', 'host', 'content-type'],
        'UNSIGNED-PAYLOAD');

    var lines = canonical.split('\n');
    var headerSection = '';
    for (var i = 3; i < lines.length - 2; i++) {
        headerSection += lines[i] + '\n';
    }

    var contentIndex = headerSection.indexOf('content-type:');
    var hostIndex = headerSection.indexOf('host:');
    var xAmzIndex = headerSection.indexOf('x-amz-date:');

    t.ok(contentIndex < hostIndex,
        'content-type should come before host');
    t.ok(hostIndex < xAmzIndex,
        'host should come before x-amz-date');
    t.done();
};

exports.testMissingHeader = function (t) {
    var canonical = helper._createCanonicalRequest(
        'GET', '/', '', {host: 'example.com'},
        ['host', 'x-missing-header'], 'UNSIGNED-PAYLOAD');

    t.ok(canonical.indexOf('x-missing-header:') !== -1,
        'should include missing header with empty value');
    t.done();
};

/* --- Test signed headers list --- */

exports.testSignedHeadersList = function (t) {
    var canonical = helper._createCanonicalRequest(
        'GET', '/', '', {
            host: 'example.com',
            'x-amz-date': '20251217T000000Z'
        },
        ['host', 'x-amz-date'], 'UNSIGNED-PAYLOAD');

    t.ok(canonical.indexOf('\nhost;x-amz-date\n') !== -1,
        'should have signed headers list');
    t.done();
};

exports.testSignedHeadersSorting = function (t) {
    var canonical = helper._createCanonicalRequest(
        'GET', '/', '', {
            'x-amz-date': '20251217T000000Z',
            'host': 'example.com',
            'content-type': 'text/plain'
        },
        ['x-amz-date', 'content-type', 'host'],
        'UNSIGNED-PAYLOAD');

    t.ok(canonical.indexOf(
        'content-type;host;x-amz-date\n') !== -1,
        'signed headers should be sorted');
    t.done();
};

/* --- Test payload hash --- */

exports.testUnsignedPayload = function (t) {
    var canonical = helper._createCanonicalRequest(
        'GET', '/', '', {host: 'example.com'},
        ['host'], 'UNSIGNED-PAYLOAD');

    var lines = canonical.split('\n');
    t.equal(lines[lines.length - 1], 'UNSIGNED-PAYLOAD',
        'should end with UNSIGNED-PAYLOAD');
    t.done();
};

exports.testSignedPayload = function (t) {
    var payloadHash =
        'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b' +
        '934ca495991b7852b855';
    var canonical = helper._createCanonicalRequest(
        'PUT', '/bucket/key', '', {host: 'example.com'},
        ['host'], payloadHash);

    var lines = canonical.split('\n');
    t.equal(lines[lines.length - 1], payloadHash,
        'should end with payload hash');
    t.done();
};

/* --- Test various HTTP methods --- */

exports.testGETMethod = function (t) {
    var canonical = helper._createCanonicalRequest(
        'GET', '/', '', {}, [], 'UNSIGNED-PAYLOAD');

    var lines = canonical.split('\n');
    t.equal(lines[0], 'GET', 'should have GET method');
    t.done();
};

exports.testPUTMethod = function (t) {
    var canonical = helper._createCanonicalRequest(
        'PUT', '/bucket/key', '', {}, [],
        'UNSIGNED-PAYLOAD');

    var lines = canonical.split('\n');
    t.equal(lines[0], 'PUT', 'should have PUT method');
    t.done();
};

exports.testPOSTMethod = function (t) {
    var canonical = helper._createCanonicalRequest(
        'POST', '/path', '', {}, [], 'UNSIGNED-PAYLOAD');

    var lines = canonical.split('\n');
    t.equal(lines[0], 'POST', 'should have POST method');
    t.done();
};

exports.testDELETEMethod = function (t) {
    var canonical = helper._createCanonicalRequest(
        'DELETE', '/bucket/key', '', {}, [],
        'UNSIGNED-PAYLOAD');

    var lines = canonical.split('\n');
    t.equal(lines[0], 'DELETE', 'should have DELETE method');
    t.done();
};

exports.testHEADMethod = function (t) {
    var canonical = helper._createCanonicalRequest(
        'HEAD', '/bucket/key', '', {}, [],
        'UNSIGNED-PAYLOAD');

    var lines = canonical.split('\n');
    t.equal(lines[0], 'HEAD', 'should have HEAD method');
    t.done();
};

/* --- Test with AWS test vectors --- */

exports.testAWSVectorGetVanilla = function (t) {
    var vector;
    for (var i = 0; i < testVectors.vectors.length; i++) {
        if (testVectors.vectors[i].name === 'get-vanilla') {
            vector = testVectors.vectors[i];
            break;
        }
    }

    if (!vector || !vector.canonicalRequest) {
        t.skip('Test vector not available');
        t.done();
        return;
    }

    var canonical = helper._createCanonicalRequest(
        vector.request.method,
        vector.request.uri,
        vector.request.query,
        vector.request.headers,
        vector.request.signedHeaders.split(';'),
        vector.request.payloadHash);

    t.equal(canonical, vector.canonicalRequest,
        'should match AWS test vector');
    t.done();
};

exports.testAWSVectorGetVanillaQuery = function (t) {
    var vector;
    for (var i = 0; i < testVectors.vectors.length; i++) {
        if (testVectors.vectors[i].name === 'get-vanilla-query') {
            vector = testVectors.vectors[i];
            break;
        }
    }

    if (!vector || !vector.canonicalRequest) {
        t.skip('Test vector not available');
        t.done();
        return;
    }

    var canonical = helper._createCanonicalRequest(
        vector.request.method,
        vector.request.uri,
        vector.request.query,
        vector.request.headers,
        vector.request.signedHeaders.split(';'),
        vector.request.payloadHash);

    t.equal(canonical, vector.canonicalRequest,
        'should match AWS query test vector');
    t.done();
};

exports.testAWSVectorGetHeaderValueTrim = function (t) {
    var vector;
    for (var i = 0; i < testVectors.vectors.length; i++) {
        if (testVectors.vectors[i].name === 'get-header-value-trim') {
            vector = testVectors.vectors[i];
            break;
        }
    }

    if (!vector || !vector.canonicalRequest) {
        t.skip('Test vector not available');
        t.done();
        return;
    }

    var canonical = helper._createCanonicalRequest(
        vector.request.method,
        vector.request.uri,
        vector.request.query,
        vector.request.headers,
        vector.request.signedHeaders.split(';'),
        vector.request.payloadHash);

    t.equal(canonical, vector.canonicalRequest,
        'should match AWS header trim test vector');
    t.done();
};

/* --- Test canonical request format --- */

exports.testCanonicalRequestStructure = function (t) {
    var canonical = helper._createCanonicalRequest(
        'GET', '/path', 'query=1',
        {host: 'example.com', 'x-amz-date': '20251217T000000Z'},
        ['host', 'x-amz-date'], 'payload-hash-here');

    var lines = canonical.split('\n');
    t.equal(lines.length, 8,
        'should have 8 lines (method, uri, query, ' +
        'headers*2, blank, signed headers, hash)');
    t.equal(lines[0], 'GET', 'line 0: method');
    t.equal(lines[1], '/path', 'line 1: URI');
    t.equal(lines[2], 'query=1', 'line 2: query');
    t.ok(lines[3].indexOf('host:') === 0,
        'line 3: first header');
    t.ok(lines[4].indexOf('x-amz-date:') === 0,
        'line 4: second header');
    t.equal(lines[5], '',
        'line 5: blank line separator');
    t.equal(lines[6], 'host;x-amz-date',
        'line 6: signed headers');
    t.equal(lines[7], 'payload-hash-here',
        'line 7: payload hash');
    t.done();
};
