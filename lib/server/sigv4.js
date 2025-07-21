/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2025 Edgecast Cloud LLC.
 */

var assert = require('assert-plus');
var crypto = require('crypto');
var sprintf = require('util').format;
var errors = require('./errors.js');
var utils = require('./utils.js');

/**
 * AWS SigV4 Authentication Module for Mahi
 */

/**
 * Parse AWS Authorization header
 * Format: AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/
 * us-east-1/s3/aws4_request, SignedHeaders=host;range;x-amz-date,
 * Signature=fe5f80f77d5fa3beca038a248ff027d0445342fe2855ddc963176630326f1024
 */
function parseAuthHeader(authHeader) {
        if (!authHeader || authHeader.indexOf('AWS4-HMAC-SHA256') !== 0) {
                return (null);
        }

    /* BEGIN JSSTYLED */
        var parts = authHeader.substring('AWS4-HMAC-SHA256 '.length)
                .split(/,\s*/);
    /* END JSSTYLED */
        var result = {};

        parts.forEach(function (part) {
                var keyValue = part.split('=');
                if (keyValue.length === 2) {
                        var key = keyValue[0];
                        var value = keyValue[1];

                        if (key === 'Credential') {
                                var credParts = value.split('/');
                                result.accessKeyId = credParts[0];
                                result.dateStamp = credParts[1];
                                result.region = credParts[2];
                                result.service = credParts[3];
                                result.requestType = credParts[4];
                        } else if (key === 'SignedHeaders') {
                                result.signedHeaders = value.split(';');
                        } else if (key === 'Signature') {
                                result.signature = value;
                        }
                }
        });

        return (result);
}

/**
 * Create canonical request string
 */
function encodeRfc3986(path) {
        return path.split('/').map(function (segment) {
                return encodeURIComponent(segment)
                        .replace(/[!'()*]/g, function (c) {
                                return '%' + c.charCodeAt(0).
                                        toString(16).toUpperCase();
                        });
        }).join('/');
}
function createCanonicalRequest(method, uri, queryString, headers,
        signedHeaders, payloadHash) {
        // Fix 1: Properly format query string according to AWS SigV4 spec
        var canonicalQueryString = '';
        if (queryString) {
                var params = queryString.split('&').map(function (param) {
                        var parts = param.split('=');
                        var key = encodeURIComponent(parts[0] || '');
                        // Handle empty values correctly - AWS SigV4 spec
                        // requires
                        // empty values to be encoded as empty string, not
                        // 'undefined'
                        var value = parts.length > 1 ?
                                encodeURIComponent(parts[1]) : '';
                        return (key + '=' + value);
                }).sort();
                canonicalQueryString = params.join('&');
        }
        var path = uri || '/';
        var canonicalURI = encodeRfc3986(path);
        // Fix 2: Sort signed headers
        // consistently (create copy to avoid mutation)
        var sortedSignedHeaders = signedHeaders.slice().sort();

        // Fix 3: Properly normalize header values according to AWS SigV4 spec
        var canonicalHeaders = '';
        sortedSignedHeaders.forEach(function (name) {
                var value = headers[name.toLowerCase()] || '';
                // Collapse multiple spaces into single spaces and trim
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
}

/**
 * Create string to sign
 */
function createStringToSign(timestamp, credentialScope, canonicalRequest) {
        var hashedCanonicalRequest = crypto.createHash('sha256')
                .update(canonicalRequest, 'utf8').digest('hex');

        return 'AWS4-HMAC-SHA256\n' +
                     timestamp + '\n' +
                     credentialScope + '\n' +
                     hashedCanonicalRequest;
}

/**
 * Calculate AWS4 signature
 */
function calculateSignature(secretKey, dateStamp, region, service,
        stringToSign) {
        function hmac(key, string) {
                return crypto.createHmac('sha256', key).update(string, 'utf8')
                        .digest();
        }
        var kDate = hmac('AWS4' + secretKey, dateStamp);
        var kRegion = hmac(kDate, region);
        var kService = hmac(kRegion, service);
        var kSigning = hmac(kService, 'aws4_request');
        return (hmac(kSigning, stringToSign).toString('hex'));
}

/**
 * Verify AWS SigV4 signature
 */
function verifySigV4(opts, cb) {
        assert.object(opts, 'opts');
        assert.object(opts.req, 'opts.req');
        assert.object(opts.log, 'opts.log');
        assert.object(opts.redis, 'opts.redis');
        assert.func(cb, 'callback');

        var req = opts.req;
        var log = opts.log;
        var redis = opts.redis;

        log.debug('sigv4.verify: entered');

        var authHeader = req.headers.authorization;
        if (!authHeader) {
                setImmediate(cb, new errors.InvalidSignatureError(
                        'Missing Authorization header'));
                return;
        }

        var authInfo = parseAuthHeader(authHeader);
        if (!authInfo) {
                setImmediate(cb, new errors.InvalidSignatureError(
                        'Invalid Authorization header format'));
                return;
        }

        // Debug: Log the parsed authorization info
        log.debug({
                authHeader: authHeader,
                parsedAuthInfo: authInfo,
                accessKeyId: authInfo.accessKeyId,
                accessKeyIdLength: authInfo.accessKeyId ?
                        authInfo.accessKeyId.length : 0,
                accessKeyIdHex: (authInfo.accessKeyId &&
                                 typeof (authInfo.accessKeyId) === 'string') ?
                     new Buffer(authInfo.accessKeyId).toString('hex') :
                        null,
                userAgent: req.headers['user-agent']
        }, 'Authorization header debug');

        // Look up user by access key ID
        var accessKeyLookupKey = sprintf('/accesskey/%s',
                authInfo.accessKeyId);
        redis.get(accessKeyLookupKey, function (err, userUuid) {
                if (err) {
                        cb(new errors.RedisError(err));
                        return;
                }

                if (!userUuid) {
                        cb(new errors.InvalidSignatureError(
                                'Invalid access key'));
                        return;
                }

                // Get user's access keys
                var userKey = sprintf('/uuid/%s', userUuid);
                redis.get(userKey, function (err, userRes) {
                        if (err) {
                                cb(new errors.RedisError(err));
                                return;
                        }

                        if (!userRes) {
                                cb(new errors.InvalidSignatureError(
                                        'User not found'));
                                return;
                        }

                        var user = JSON.parse(userRes);
                        if (!user.accesskeys ||
                                !user.accesskeys[authInfo.accessKeyId]) {
                                cb(new errors.InvalidSignatureError(
                                        'Access key not found'));
                                return;
                                        }

                        var secretKey = user.accesskeys[authInfo.accessKeyId];
                        var timestamp = req.headers['x-amz-date'] ||
                                req.headers.date;
                        if (!timestamp) {
                                cb(new errors.InvalidSignatureError(
                                        'Missing timestamp'));
                                return;
                        }

                        var requestTime = new Date(timestamp).getTime();
                        var currentTime = Date.now();
                        var timeDiff = Math.abs(currentTime - requestTime);
                        if (timeDiff > 15 * 60 * 1000) { // 15 minutes
                                cb(new errors.InvalidSignatureError(
                                        'Request timestamp too old'));
                                return;
                        }

                        // Build canonical request using original request data
                        // from query params.
                        // The original method and URL are passed as query
                        // parameters to /aws-verify
                        var originalMethod = req.query.method || req.method;
                        var originalUrl = req.query.url || req.url;
                        // URL decode the originalUrl if it comes from query
                        // params (fixes Cyberduck compatibility without
                        // affecting AWS CLI)

                        var uri = originalUrl.split('?')[0];
                        if (req.query.url) {
                                originalUrl = decodeURIComponent(originalUrl);
                                uri = decodeURIComponent(uri);
                        }

                        var queryString = originalUrl.split('?')[1] || '';
                        var payloadHash = req.headers['x-amz-content-sha256'] ||
                                'UNSIGNED-PAYLOAD';

                        var canonicalRequest = createCanonicalRequest(
                                originalMethod, uri, queryString, req.headers,
                                authInfo.signedHeaders, payloadHash);

                        // Print hexdump of canonicalRequest
                        log.debug('canonicalRequest hexdump:\n'+
                            utils.hexdump(canonicalRequest));

                        // Create string to sign
                        var credentialScope = sprintf('%s/%s/%s/aws4_request',
                                authInfo.dateStamp, authInfo.region,
                                authInfo.service);
                        var stringToSign = createStringToSign(timestamp,
                                credentialScope, canonicalRequest);

                        log.debug('stringToSign hexdump:\n'+
                            utils.hexdump(stringToSign));

                        // Calculate expected signature
                        var expectedSignature = calculateSignature(
                                secretKey, authInfo.dateStamp, authInfo.region,
                                authInfo.service, stringToSign);

                        // Compare signatures
                        if (expectedSignature !== authInfo.signature) {
                                log.debug({
                                        expected: expectedSignature,
                                        received: authInfo.signature,
                                        stringToSign: stringToSign,
                                        canonicalRequest: canonicalRequest
                                }, 'Signature mismatch');
                                cb(new errors.InvalidSignatureError(
                                        'Signature mismatch'));
                                return;
                        }

                        log.debug({accessKeyId: authInfo.accessKeyId,
                                userUuid: userUuid},
                                'SigV4 verification successful');
                        cb(null, {
                                user: user,
                                accessKeyId: authInfo.accessKeyId
                        });
                });
        });
}

module.exports = {
        parseAuthHeader: parseAuthHeader,
        verifySigV4: verifySigV4
};
