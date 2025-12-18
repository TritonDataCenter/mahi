/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright (c) 2025, Joyent, Inc.
 */

/**
 * AWS Signature Version 4 Test Helper
 *
 * Provides utilities for generating valid AWS SigV4 signatures and
 * authentication headers for testing purposes. Implements the complete
 * SigV4 signing process according to AWS specification.
 */

var assert = require('assert-plus');
var crypto = require('crypto');

/**
 * @brief AWS Signature Version 4 helper for tests
 *
 * Generates valid AWS SigV4 authentication headers and signatures
 * for testing authenticated API endpoints. Follows AWS SigV4
 * specification exactly.
 *
 * @constructor
 * @param {object} [opts] Configuration options
 * @param {string} [opts.region] AWS region (default: 'us-west-1')
 * @param {string} [opts.service] AWS service (default: 's3')
 *
 * @example
 * var SigV4Helper = require('./sigv4-helper');
 * var helper = new SigV4Helper();
 *
 * var headers = helper.createHeaders({
 *     method: 'POST',
 *     path: '/sts/AssumeRole',
 *     accessKey: 'AKIATEST',
 *     secret: 'secretkey',
 *     body: {RoleArn: 'arn:aws:iam::...'}
 * });
 *
 * @since 1.0.0
 */
function SigV4Helper(opts) {
    opts = opts || {};
    assert.optionalString(opts.region, 'opts.region');
    assert.optionalString(opts.service, 'opts.service');

    this.region = opts.region || 'us-west-1';
    this.service = opts.service || 's3';
}

/**
 * @brief Create complete SigV4 authentication headers
 *
 * Generates all required headers for AWS SigV4 authentication
 * including Authorization, X-Amz-Date, Host, and optionally
 * X-Amz-Security-Token for temporary credentials.
 *
 * @param {object} opts Request options
 * @param {string} opts.method HTTP method (GET, POST, PUT, etc.)
 * @param {string} opts.path Request path
 * @param {string} opts.accessKey AWS access key ID
 * @param {string} opts.secret AWS secret access key
 * @param {string} [opts.host] Host header value (default: 'localhost')
 * @param {string} [opts.timestamp] ISO 8601 timestamp (default: now)
 * @param {object} [opts.headers] Additional headers to include
 * @param {object} [opts.body] Request body (will be JSON stringified)
 * @param {string} [opts.query] Query string (without leading ?)
 * @param {string} [opts.sessionToken] Session token for temporary creds
 *
 * @return {object} Headers object ready to pass to HTTP client
 *
 * @example
 * var headers = helper.createHeaders({
 *     method: 'POST',
 *     path: '/sts/AssumeRole',
 *     accessKey: 'AKIATEST',
 *     secret: 'mysecret',
 *     body: {RoleArn: 'arn:aws:iam::account:role/MyRole'}
 * });
 *
 * client.post('/sts/AssumeRole', headers, body, callback);
 *
 * @since 1.0.0
 */
SigV4Helper.prototype.createHeaders = function createHeaders(opts) {
    assert.object(opts, 'opts');
    assert.string(opts.method, 'opts.method');
    assert.string(opts.path, 'opts.path');
    assert.string(opts.accessKey, 'opts.accessKey');
    assert.string(opts.secret, 'opts.secret');
    assert.optionalString(opts.host, 'opts.host');
    assert.optionalString(opts.timestamp, 'opts.timestamp');
    assert.optionalObject(opts.headers, 'opts.headers');
    assert.optionalObject(opts.body, 'opts.body');
    assert.optionalString(opts.query, 'opts.query');
    assert.optionalString(opts.sessionToken, 'opts.sessionToken');

    var host = opts.host || 'localhost';
    var timestamp = opts.timestamp || new Date().toISOString()
        .replace(/[:-]|\.\d{3}/g, '');
    var dateStamp = timestamp.substring(0, 8); // YYYYMMDD

    // Build headers object
    var headers = opts.headers || {};
    headers.host = host;
    headers['x-amz-date'] = timestamp;

    if (opts.sessionToken) {
        headers['x-amz-security-token'] = opts.sessionToken;
    }

    // Handle request body
    var body = '';
    var payloadHash;

    if (opts.body) {
        body = typeof (opts.body) === 'string' ?
            opts.body : JSON.stringify(opts.body);
        payloadHash = crypto.createHash('sha256')
            .update(body, 'utf8').digest('hex');
        headers['content-type'] = 'application/json';
        headers['content-length'] = Buffer.byteLength(body, 'utf8');
    } else {
        payloadHash = crypto.createHash('sha256')
            .update('', 'utf8').digest('hex');
    }

    // Build signed headers list
    var signedHeaders = Object.keys(headers).sort();

    // Create canonical request
    var canonicalRequest = this._createCanonicalRequest(
        opts.method,
        opts.path,
        opts.query || '',
        headers,
        signedHeaders,
        payloadHash);

    // Create string to sign
    var credentialScope = dateStamp + '/' + this.region + '/' +
        this.service + '/aws4_request';
    var stringToSign = this._createStringToSign(
        timestamp,
        credentialScope,
        canonicalRequest);

    // Calculate signature
    var signature = this._calculateSignature(
        opts.secret,
        dateStamp,
        this.region,
        this.service,
        stringToSign);

    // Build authorization header
    var authorization = 'AWS4-HMAC-SHA256 ' +
        'Credential=' + opts.accessKey + '/' + credentialScope + ', ' +
        'SignedHeaders=' + signedHeaders.join(';') + ', ' +
        'Signature=' + signature;

    headers.authorization = authorization;

    return (headers);
};

/**
 * @brief Encode URI path according to RFC 3986
 *
 * Performs percent-encoding of URI path segments following RFC 3986
 * for use in canonical request construction.
 *
 * @param {string} path URI path to encode
 *
 * @return {string} RFC 3986 encoded path
 *
 * @note Encodes each path segment separately
 *
 * @since 1.0.0
 */
SigV4Helper.prototype._encodeRfc3986 = function _encodeRfc3986(path) {
    return (path.split('/').map(function (segment) {
        return (encodeURIComponent(segment)
            .replace(/[!'()*]/g, function (c) {
                return ('%' + c.charCodeAt(0).toString(16).toUpperCase());
            }));
    }).join('/'));
};

/**
 * @brief Create canonical request string
 *
 * Constructs the canonical request string required for AWS SigV4
 * authentication.
 *
 * @param {string} method HTTP method
 * @param {string} uri Request URI path
 * @param {string} queryString Query string parameters
 * @param {object} headers HTTP headers object
 * @param {array} signedHeaders Array of signed header names
 * @param {string} payloadHash SHA256 hash of request payload
 *
 * @return {string} Canonical request string
 *
 * @since 1.0.0
 */
SigV4Helper.prototype._createCanonicalRequest =
    function _createCanonicalRequest(method, uri, queryString, headers,
        signedHeaders, payloadHash) {
    // Format query string
    var canonicalQueryString = '';
    if (queryString) {
        var params = queryString.split('&').map(function (param) {
            var parts = param.split('=');
            var key = encodeURIComponent(parts[0] || '');
            var value = parts.length > 1 ?
                encodeURIComponent(parts[1]) : '';
            return (key + '=' + value);
        }).sort();
        canonicalQueryString = params.join('&');
    }

    var path = uri || '/';
    var canonicalURI = this._encodeRfc3986(path);

    // Sort signed headers and build canonical headers string
    var sortedSignedHeaders = signedHeaders.slice().sort();
    var canonicalHeaders = '';

    sortedSignedHeaders.forEach(function (name) {
        var value = headers[name.toLowerCase()] || '';
        value = value.replace(/\s+/g, ' ').trim();
        canonicalHeaders += name.toLowerCase() + ':' + value + '\n';
    });

    var canonicalRequest = method + '\n' +
                           canonicalURI + '\n' +
                           canonicalQueryString + '\n' +
                           canonicalHeaders + '\n' +
                           sortedSignedHeaders.join(';') + '\n' +
                           payloadHash;

    return (canonicalRequest);
};

/**
 * @brief Create string-to-sign for signature calculation
 *
 * Constructs the string-to-sign component required for AWS SigV4
 * authentication.
 *
 * @param {string} timestamp ISO 8601 timestamp (YYYYMMDDTHHMMSSZ)
 * @param {string} credentialScope Credential scope string
 * @param {string} canonicalRequest Canonical request string
 *
 * @return {string} String-to-sign
 *
 * @since 1.0.0
 */
SigV4Helper.prototype._createStringToSign =
    function _createStringToSign(timestamp, credentialScope,
        canonicalRequest) {
    var hashedCanonicalRequest = crypto.createHash('sha256')
        .update(canonicalRequest, 'utf8').digest('hex');

    return ('AWS4-HMAC-SHA256\n' +
           timestamp + '\n' +
           credentialScope + '\n' +
           hashedCanonicalRequest);
};

/**
 * @brief Calculate AWS SigV4 signature
 *
 * Performs AWS SigV4 signature calculation using HMAC-SHA256
 * with derived signing key.
 *
 * @param {string} secretKey AWS secret access key
 * @param {string} dateStamp Date stamp (YYYYMMDD)
 * @param {string} region AWS region
 * @param {string} service AWS service
 * @param {string} stringToSign String-to-sign
 *
 * @return {string} Hexadecimal signature
 *
 * @since 1.0.0
 */
SigV4Helper.prototype._calculateSignature =
    function _calculateSignature(secretKey, dateStamp, region, service,
        stringToSign) {
    function hmac(key, string) {
        return (crypto.createHmac('sha256', key).update(string, 'utf8')
            .digest());
    }

    var kDate = hmac('AWS4' + secretKey, dateStamp);
    var kRegion = hmac(kDate, region);
    var kService = hmac(kRegion, service);
    var kSigning = hmac(kService, 'aws4_request');
    return (hmac(kSigning, stringToSign).toString('hex'));
};

/**
 * @brief Create signature for GET request
 *
 * Convenience method for creating SigV4 headers for GET requests.
 *
 * @param {string} path Request path
 * @param {string} accessKey AWS access key ID
 * @param {string} secret AWS secret access key
 * @param {object} [opts] Additional options
 *
 * @return {object} Headers object
 *
 * @example
 * var headers = helper.get('/accounts/uuid', 'AKIATEST', 'secret');
 *
 * @since 1.0.0
 */
SigV4Helper.prototype.get = function get(path, accessKey, secret, opts) {
    opts = opts || {};
    opts.method = 'GET';
    opts.path = path;
    opts.accessKey = accessKey;
    opts.secret = secret;
    return (this.createHeaders(opts));
};

/**
 * @brief Create signature for POST request
 *
 * Convenience method for creating SigV4 headers for POST requests.
 *
 * @param {string} path Request path
 * @param {string} accessKey AWS access key ID
 * @param {string} secret AWS secret access key
 * @param {object} body Request body
 * @param {object} [opts] Additional options
 *
 * @return {object} Headers object
 *
 * @example
 * var headers = helper.post('/sts/AssumeRole', 'AKIATEST', 'secret',
 *     {RoleArn: 'arn:aws:iam::...'});
 *
 * @since 1.0.0
 */
SigV4Helper.prototype.post = function post(path, accessKey, secret, body,
    opts) {
    opts = opts || {};
    opts.method = 'POST';
    opts.path = path;
    opts.accessKey = accessKey;
    opts.secret = secret;
    opts.body = body;
    return (this.createHeaders(opts));
};

module.exports = SigV4Helper;
