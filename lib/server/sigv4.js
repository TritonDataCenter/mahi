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
var sessionTokenModule = require('./session-token');
var utils = require('./utils.js');

/**
 * AWS SigV4 Authentication Module for Mahi
 */

/*
 * AccessKeyId validation regex from sdc-ufds/schema/accesskey.js
 * Matches word characters only (alphanumeric + underscore)
 */
var ACCESSKEYID_RE = /^\w+$/;

/**
 * @brief Parse ISO8601 timestamp (basic or extended format)
 *
 * Converts AWS SigV4 basic format timestamp (20251218T123236Z) to
 * a Date object. Also handles extended format (2025-12-18T12:32:36Z).
 * JavaScript's Date() cannot parse basic ISO8601 format directly.
 *
 * @param {string} timestamp ISO8601 timestamp (basic or extended format)
 *
 * @return {Date} Parsed date object
 *
 * @since 1.0.0
 */
function parseISO8601Basic(timestamp) {
        if (!timestamp) {
                return (new Date(timestamp));
        }

        // If timestamp already contains hyphens, it's in extended format
        // and JavaScript's Date() can parse it directly
        if (timestamp.indexOf('-') !== -1) {
                return (new Date(timestamp));
        }

        // Convert basic format: 20251218T123236Z to 2025-12-18T12:32:36Z
        if (timestamp.length >= 15) {
                var formatted = timestamp.substring(0, 4) + '-' +
                        timestamp.substring(4, 6) + '-' +
                        timestamp.substring(6, 8) + 'T' +
                        timestamp.substring(9, 11) + ':' +
                        timestamp.substring(11, 13) + ':' +
                        timestamp.substring(13, 15) + 'Z';
                return (new Date(formatted));
        }
        return (new Date(timestamp));
}

/**
 * @brief Parse AWS Signature Version 4 Authorization header
 *
 * Extracts and parses credential, signed headers, and signature
 * components from AWS SigV4 authorization header string. Supports
 * standard AWS authorization header format parsing.
 *
 * @param {string} authHeader Raw authorization header value from request
 *
 * @return {Object|null} Parsed authorization components object containing:
 *   - accessKeyId: AWS access key identifier
 *   - dateStamp: Request date stamp (YYYYMMDD format)
 *   - region: AWS region identifier
 *   - service: AWS service identifier
 *   - requestType: Request type (usually 'aws4_request')
 *   - signedHeaders: Array of signed header names
 *   - signature: Hexadecimal signature string
 *   Returns null if header format is invalid
 *
 * @note Expected format: 'AWS4-HMAC-SHA256 Credential=<keyid>/<date>/
 *       <region>/<service>/aws4_request, SignedHeaders=<headers>,
 *       Signature=<signature>'
 * @note Returns null for non-SigV4 authorization headers
 *
 * @example
 * var auth = parseAuthHeader(req.headers.authorization);
 * console.log(auth.accessKeyId); // "AKIAIOSFODNN7EXAMPLE"
 *
 * @since 1.0.0
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
        var validationFailed = false;

        for (var partIdx = 0; partIdx < parts.length; partIdx++) {
                var part = parts[partIdx];
                var keyValue = part.split('=');
                if (keyValue.length === 2) {
                        var key = keyValue[0];
                        var value = keyValue[1];

                        if (key === 'Credential') {
                                var credParts = value.split('/');

                                /*
                                 * Validate credential format per AWS SigV4
                                 * spec: Credential=AccessKeyId/DateStamp/
                                 * Region/Service/RequestType
                                 * All 5 parts required and non-empty.
                                 */
                                if (credParts.length !== 5) {
                                        validationFailed = true;
                                        break;
                                }

                                /*
                                 * Validate all credential parts are non-empty
                                 */
                                for (var i = 0; i < 5; i++) {
                                        if (!credParts[i] ||
                                            credParts[i].trim() === '') {
                                                validationFailed = true;
                                                break;
                                        }
                                }

                                if (validationFailed) {
                                        break;
                                }

                                /*
                                 * Validate dateStamp format (YYYYMMDD)
                                 * AWS SigV4 requires 8-digit date format
                                 */
                                if (!/^\d{8}$/.test(credParts[1])) {
                                        validationFailed = true;
                                        break;
                                }

                                /*
                                 * Validate requestType is "aws4_request"
                                 * AWS SigV4 spec requires this exact value
                                 */
                                if (credParts[4] !== 'aws4_request') {
                                        validationFailed = true;
                                        break;
                                }

                                /*
                                 * Validate accessKeyId per sdc-ufds schema:
                                 * - Only word characters (alphanumeric +
                                 *   underscore)
                                 * - Length between 16 and 128 characters
                                 */
                                if (!ACCESSKEYID_RE.test(credParts[0]) ||
                                    credParts[0].length < 16 ||
                                    credParts[0].length > 128) {
                                        validationFailed = true;
                                        break;
                                }

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
        }

        if (validationFailed) {
                return (null);
        }

        return (result);
}

/**
 * @brief Encode URI path component according to RFC 3986
 *
 * Performs percent-encoding of URI path segments following RFC 3986
 * specification for unreserved characters. Used in canonical request
 * construction for AWS Signature Version 4 authentication.
 *
 * @param {string} path URI path to encode
 *
 * @return {string} RFC 3986 encoded path with proper percent-encoding
 *                  for all characters except unreserved ones
 *
 * @note Encodes each path segment separately (splits on '/')
 * @note Ensures special characters like !, ', (, ), * are encoded
 * @note Required for proper AWS SigV4 canonical request construction
 *
 * @example
 * var encoded = encodeRfc3986('/path/to/file with spaces.txt');
 * // Returns: "/path/to/file%20with%20spaces.txt"
 *
 * @since 1.0.0
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

/**
 * @brief Create AWS SigV4 canonical request string
 *
 * Constructs the canonical request string required for AWS Signature
 * Version 4 authentication. Normalizes HTTP method, URI, query
 * parameters, headers, and payload hash according to AWS specification.
 *
 * @param {string} method HTTP method (GET, POST, PUT, etc.)
 * @param {string} uri Request URI path component
 * @param {string} queryString URL query string parameters
 * @param {Object} headers HTTP headers object (name: value pairs)
 * @param {Array} signedHeaders Array of header names that are signed
 * @param {string} payloadHash SHA256 hash of request payload
 *
 * @return {string} Canonical request string formatted according to AWS
 *                  SigV4 specification with newline-separated components
 *
 * @note Query parameters are sorted alphabetically by key
 * @note Headers are normalized (trimmed, lowercase, sorted)
 * @note Special handling for content-length and content-md5 headers
 * @note Uses RFC 3986 encoding for URI path components
 *
 * @example
 * var canonical = createCanonicalRequest('GET', '/bucket/key',
 *     'prefix=photos&delimiter=/', headers, ['host', 'x-amz-date'],
 *     'UNSIGNED-PAYLOAD');
 *
 * @since 1.0.0
 */
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

        // We send this from manta-buckets-api to match
        // the canonical url signature for sigv4 on clients
        // that create a signature using content-length
        // why we need this here? restify overwrites the real
        // content-length value, the same happens with content-md5
        //
        if ('content-length' in headers) {
            headers['content-length'] = headers['manta-s3-content-length'];
        }
        // Restify also overrides this header, so restoring the value here.
        if ('content-md5' in headers) {
            headers['content-md5'] = headers['manta-s3-content-md5'];
        }
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
 * @brief Create AWS SigV4 string-to-sign for signature calculation
 *
 * Constructs the string-to-sign component required for AWS Signature
 * Version 4 authentication. Combines algorithm identifier, timestamp,
 * credential scope, and hashed canonical request into final format.
 *
 * @param {string} timestamp ISO 8601 timestamp for the request
 * @param {string} credentialScope Scope string in format:
 *                 YYYYMMDD/region/service/aws4_request
 * @param {string} canonicalRequest Previously constructed canonical
 *                 request string
 *
 * @return {string} String-to-sign formatted for AWS SigV4 signature
 *                  calculation with newline-separated components
 *
 * @note Uses SHA256 hash of canonical request in final component
 * @note Format: AWS4-HMAC-SHA256\n<timestamp>\n<scope>\n<hash>
 * @note Required step before HMAC signature calculation
 *
 * @example
 * var stringToSign = createStringToSign('20240101T120000Z',
 *     '20240101/us-west-1/s3/aws4_request', canonicalRequest);
 *
 * @since 1.0.0
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
 * @brief Calculate AWS SigV4 HMAC-SHA256 signature
 *
 * Performs the AWS Signature Version 4 signature calculation using
 * HMAC-SHA256 with derived signing key. Implements the complete key
 * derivation process and final signature generation.
 *
 * @param {string} secretKey AWS secret access key
 * @param {string} dateStamp Date stamp in YYYYMMDD format
 * @param {string} region AWS region identifier
 * @param {string} service AWS service identifier
 * @param {string} stringToSign Previously constructed string-to-sign
 *
 * @return {string} Hexadecimal representation of calculated signature
 *
 * @note Implements AWS key derivation: kDate -> kRegion -> kService ->
 *       kSigning -> signature
 * @note Uses HMAC-SHA256 for all derivation steps
 * @note Final signature is hex-encoded for authorization header
 *
 * @example
 * var signature = calculateSignature(secretKey, '20240101',
 *     'us-west-1', 's3', stringToSign);
 * console.log(signature); // "abc123def456..." (64-char hex string)
 *
 * @since 1.0.0
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
 * @brief Handle temporary credential verification for STS
 *
 * Verifies STS-issued temporary credentials by looking up the
 * access key in UFDS and validating session token, expiration,
 * and principal information.
 *
 * @param authInfo Object containing accessKeyId and other auth data
 * @param sessionToken Session token from X-Amz-Security-Token header
 * @param req HTTP request object with Redis connection
 * @param log Bunyan logger instance for debug/error logging
 * @param ufds UFDS client instance for credential lookup
 * @param cb Callback function (err, result)
 *
 * @returns Via callback: credential verification result with
 *          principal user data and role information
 *
 * @note Validates credential expiration and session token match
 * @note Retrieves original principal user who assumed the role
 * @note Performs signature verification using temporary secret
 *
 * @see AWS STS temporary credential documentation
 * @since 1.0.0
 */
/*jsl:ignore*/
function handleTemporaryCredential(authInfo, sessionToken, req, log, ufds, cb) {
    log.debug({
        accessKeyId: authInfo.accessKeyId,
        hasSessionToken: true
    }, 'sigv4.handleTemporaryCredential: looking up temporary credential');

    // Look up temporary credential in UFDS by access key ID
    var searchBase = 'ou=users, o=smartdc';
    var searchFilter = '(&(objectclass=accesskey)(accesskeyid=' +
        authInfo.accessKeyId + ')(credentialtype=temporary))';

    ufds.search(searchBase, {
        scope: 'sub',
        filter: searchFilter
    }, function (searchErr, searchRes) {
        if (searchErr) {
            log.error({
                err: searchErr,
                accessKeyId: authInfo.accessKeyId
            }, 'sigv4.handleTemporaryCredential: UFDS search failed');
            return cb(new errors.InvalidSignatureError
                      ('Failed to verify temporary credential'));
        }

        if (!searchRes || searchRes.length === 0) {
            log.warn({
                accessKeyId: authInfo.accessKeyId
            }, 'sigv4.handleTemporaryCredential' +
               ': temporary credential not found');
            return cb(new errors.InvalidSignatureError
                      ('Invalid temporary access key'));
        }

        var tempCredential = searchRes[0];
        var credData = tempCredential.object || tempCredential;

        log.debug({
            accessKeyId: authInfo.accessKeyId,
            principalUuid: credData.principaluuid,
            assumedroleFromUFDS: credData.assumedrole,
            assumedroleType: typeof (credData.assumedrole),
            hasAssumedrole: !!credData.assumedrole
        }, 'SECURITY DEBUG: sigv4 retrieved from UFDS: assumedrole=' +
           (credData.assumedrole || 'NULL'));

        // Check if credential has expired
        if (credData.expiration) {
            var expiration = new Date(credData.expiration);
            if (expiration < new Date()) {
                log.warn({
                    accessKeyId: authInfo.accessKeyId,
                    expiration: credData.expiration
                }, 'sigv4.handleTemporaryCredential:' +
                   ' temporary credential expired');
                return cb(new errors.InvalidSignatureError
                          ('Temporary credential expired'));
            }
        }

        // Verify session token matches
        if (credData.sessiontoken !== sessionToken) {
            log.warn({
                accessKeyId: authInfo.accessKeyId
            }, 'sigv4.handleTemporaryCredential: session token mismatch');
            return cb(new errors.InvalidSignatureError
                      ('Invalid session token'));
        }

        // Get the principal user data (the original user who assumed the role)
        var principalUuid = credData.principaluuid;
        var redis = req.redis;
        var userKey = sprintf('/uuid/%s', principalUuid);

        redis.get(userKey, function (err, userRes) {
            if (err || !userRes) {
                log.error({
                    err: err,
                    principalUuid: principalUuid
                }, 'sigv4.handleTemporaryCredential: ' +
                   'failed to get principal user');
                return cb(new errors.InvalidSignatureError
                          ('Invalid principal user'));
            }

            var user = JSON.parse(userRes);

            // Verify signature using the temporary credential's secret key
            var secretKey = credData.accesskeysecret;

            // Perform signature verification (reuse permanent credential logic)
            var timestamp = req.headers['x-amz-date'];
            if (!timestamp) {
                return cb(new errors.InvalidSignatureError
                          ('Missing X-Amz-Date header'));
            }

            // Check timestamp skew (15 minutes threshold)
            var requestTime = parseISO8601Basic(timestamp).getTime();
            var currentTime = Date.now();
            var timeDiff = Math.abs(currentTime - requestTime);

            if (timeDiff > 15 * 60 * 1000) { // 15 minutes
                return cb(new errors.InvalidSignatureError
                          ('Request timestamp too old'));
            }

            // Build canonical request using original request data
            var originalMethod = req.query.method || req.method;
            var originalUrl = req.query.url || req.url;

            var uri = originalUrl.split('?')[0];
            if (req.query.url) {
                originalUrl = decodeURIComponent(originalUrl);
                uri = decodeURIComponent(uri);
            }

            var queryString = originalUrl.split('?')[1] || '';

            // Remove sessionToken from query string for signature verification
            // The sessionToken was added by buckets-api after AWS CLI signed
            // the request
            if (queryString) {
                queryString =
                    /*JSSTYLED*/
                    queryString.replace(/[&?]?sessionToken=[^&]*&?/g, '')
                    .replace(/^&/, '').replace(/&$/, '');
            }

            var payloadHash = req.headers['x-amz-content-sha256'] ||
                'UNSIGNED-PAYLOAD';

            var canonicalRequest = createCanonicalRequest(
                originalMethod, uri, queryString, req.headers,
                authInfo.signedHeaders, payloadHash);

            // Create string to sign
            var credentialScope = sprintf('%s/%s/%s/aws4_request',
                authInfo.dateStamp, authInfo.region, authInfo.service);
            var stringToSign = createStringToSign(timestamp, credentialScope,
                                                  canonicalRequest);

            log.debug({
                originalMethod: originalMethod,
                uri: uri,
                queryString: queryString,
                signedHeaders: authInfo.signedHeaders,
                payloadHash: payloadHash,
                credentialScope: credentialScope,
                canonicalRequest: canonicalRequest,
                stringToSign: stringToSign,
                secretKey: secretKey.substring(0, 10) + '...'
            }, 'sigv4.handleTemporaryCredential:' +
               ' signature calculation details');

            // Calculate expected signature using temporary secret key
            var expectedSignature = calculateSignature(secretKey,
                                                       authInfo.dateStamp,
                                                       authInfo.region,
                                                       authInfo.service,
                                                       stringToSign);

            // Verify signature matches
            if (expectedSignature !== authInfo.signature) {
                log.warn({
                    accessKeyId: authInfo.accessKeyId,
                    expectedSignature: expectedSignature,
                    providedSignature: authInfo.signature
                }, 'sigv4.handleTemporaryCredential:' +
                   ' signature mismatch for temporary credential');
                return cb(new errors.InvalidSignatureError
                          ('Signature mismatch'));
            }

            // Return result with role information
            var result = {
                user: user,
                accessKeyId: authInfo.accessKeyId,
                userUuid: principalUuid,
                valid: true,
                // Additional fields for role-based access
                isTemporaryCredential: true,
                assumedRole: credData.assumedrole,
                principalUuid: principalUuid,
                credentialType: 'temporary'
            };

            log.debug({
                accessKeyId: authInfo.accessKeyId,
                resultAssumedRole: result.assumedRole,
                assumedroleFromCredData: credData.assumedrole
            }, 'SECURITY DEBUG: sigv4 returning assumedRole=' +
               (result.assumedRole || 'NULL'));

            cb(null, result);
            return;
        });
        return;
    });
}
/*jsl:end*/

/**
 * @brief Verify AWS Signature Version 4 authentication
 *
 * Validates AWS SigV4 signatures for both permanent and temporary
 * credentials. Handles complete signature verification workflow
 * including credential lookup, signature calculation, and validation.
 *
 * @param {Object} opts Verification options object containing:
 * @param {Object} opts.req HTTP request object with headers/query
 * @param {Object} opts.log Bunyan logger instance
 * @param {Object} opts.redis Redis client for credential lookup
 * @param {Object} opts.ufds UFDS client for temporary credential lookup
 * @param {function} cb Callback function
 * @param {Error} cb.err Error if verification failed
 * @param {Object} cb.result Verification result containing:
 *   - user: User object from credential store
 *   - accessKeyId: Verified access key identifier
 *   - valid: Boolean verification status
 *   - isTemporaryCredential: Boolean for temp credential type
 *   - assumedRole: Role ARN for temporary credentials
 *
 * @note Supports both permanent access keys and STS temporary credentials
 * @note Validates signature timestamp against 15-minute window
 * @note Handles session token verification for temporary credentials
 * @note Reconstructs canonical request for signature verification
 *
 * @error InvalidSignature Authorization header missing/malformed
 * @error InvalidSignature Access key not found or invalid
 * @error InvalidSignature Signature mismatch or expired
 *
 * @see AWS Signature Version 4 specification
 * @since 1.0.0
 */
/*jsl:ignore*/
function verifySigV4(opts, cb) {
        assert.object(opts, 'opts');
        assert.object(opts.req, 'opts.req');
        assert.object(opts.log, 'opts.log');
        assert.object(opts.redis, 'opts.redis');
        assert.func(cb, 'callback');

        var req = opts.req;
        var log = opts.log;
        var redis = opts.redis;
        var ufds = opts.ufds; // UFDS client for temporary credential lookup

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

        // Validate accessKeyId length before processing
        if (authInfo.accessKeyId &&
            typeof (authInfo.accessKeyId) === 'string' &&
            authInfo.accessKeyId.length > 1024) {
                setImmediate(cb, new errors.InvalidSignatureError(
                        'Access key ID too long'));
                return;
        }

        // Compute hex representation for debug logging
        var accessKeyIdHex = null;
        if (authInfo.accessKeyId &&
            typeof (authInfo.accessKeyId) === 'string') {
                accessKeyIdHex = new Buffer(
                    authInfo.accessKeyId, 'utf8').toString('hex');
        }

        // Debug: Log the parsed authorization info
        log.debug({
                authHeader: authHeader,
                parsedAuthInfo: authInfo,
                accessKeyId: authInfo.accessKeyId,
                accessKeyIdLength: authInfo.accessKeyId ?
                        authInfo.accessKeyId.length : 0,
                accessKeyIdHex: accessKeyIdHex,
                userAgent: req.headers['user-agent']
        }, 'Authorization header debug');

        // Check if this is a temporary credential request
        // Session token can be in multiple places:
        // 1. X-Amz-Security-Token header (AWS CLI standard)
        // 2. req.query.sessionToken (manta-buckets-api format)
        // 3. Embedded in URL parameter
        var sessionToken = req.headers['x-amz-security-token'] ||
            req.query.sessionToken;

        // If not found yet, check if it's embedded in the URL parameter
        if (!sessionToken && req.query.url) {
            /*JSSTYLED*/
            var urlMatch = req.query.url.match(/sessionToken=([^&]+)/);
            if (urlMatch) {
                sessionToken = decodeURIComponent(urlMatch[1]);
            }
        }

        log.debug({
            sessionTokenHeader: !!req.headers['x-amz-security-token'],
            sessionTokenQuery: !!req.query.sessionToken,
            sessionTokenUrl: !!(req.query.url &&
                                req.query.url.indexOf('sessionToken=') > -1),
            finalSessionToken: !!sessionToken,
            accessKeyId: authInfo.accessKeyId
        }, 'Session token detection from multiple sources');

    var isTemporaryCredential = sessionToken &&
        typeof (sessionToken) === 'string' && sessionToken.length > 10;

        log.info({
            hasSessionToken: !!sessionToken,
            isTemporaryCredential: isTemporaryCredential,
            accessKeyId: authInfo.accessKeyId,
            hasUfds: !!ufds,
            queryParams: Object.keys(req.query || {}),
            sessionTokenLength: sessionToken ? sessionToken.length : 0,
            fullQueryObject: req.query,
            urlParam: req.query ? req.query.url : 'no-url-param',
            sessionTokenSource: sessionToken ? (req.query.sessionToken ?
                                                'direct-query' :
                                                'url-embedded') : 'not-found'
        }, 'sigv4.verify: CREDENTIAL TYPE DETECTION');

        if (isTemporaryCredential) {
            log.info({
                accessKeyId: authInfo.accessKeyId,
                sessionToken: sessionToken.substring(0, 20) + '...',
                hasUfds: !!ufds,
                hasRedis: !!redis
            }, 'sigv4.verify: ROUTING TO TEMPORARY CREDENTIAL HANDLER');

            // For temporary credentials, validate the JWT session token first
            var secretConfig = opts.secretConfig;

            if (!secretConfig || !secretConfig.secrets) {
                log.error({
                    accessKeyId: authInfo.accessKeyId
                }, 'sigv4.verify: No session secret config available for ' +
                          'JWT validation');
                return cb(new errors.InvalidSignatureError(
                    'Cannot verify session token'));
            }

            // DEBUG: Log session token metadata (never full token)
            log.debug({
                accessKeyId: authInfo.accessKeyId,
                sessionTokenLength: sessionToken ? sessionToken.length : 0,
                sessionTokenPrefix: sessionToken ?
                    sessionToken.substring(0, 20) + '...' : 'none',
                sessionTokenType: typeof (sessionToken),
                sessionTokenIsString: typeof (sessionToken) === 'string',
                sessionTokenHasDots: sessionToken ?
                    sessionToken.indexOf('.') >= 0 : false,
                sessionTokenParts: sessionToken ?
                    sessionToken.split('.').length : 0
            }, 'sigv4.verify: Session token validation metadata');

            // Verify the JWT session token
            // (async callback approach for old JWT library)
            sessionTokenModule.verifySessionToken(sessionToken,
                                                   secretConfig, {},
                                                   function (jwtErr,
                                                             tokenData) {
                if (jwtErr) {
                    log.error({
                        err: jwtErr,
                        errorMessage: jwtErr.message,
                        errorStack: jwtErr.stack,
                        accessKeyId: authInfo.accessKeyId,
                        sessionTokenPrefix: sessionToken ?
                            sessionToken.substring(0, 50) + '...' : 'none',
                        hasSecretConfig: !!secretConfig,
                        secretConfigKeys: secretConfig ?
                            Object.keys(secretConfig) : null,
                        secretsAvailable: secretConfig &&
                            secretConfig.secrets ?
                            Object.keys(secretConfig.secrets) : null
                    }, 'sigv4.verify: JWT session token verification failed');
                    return cb(new errors.InvalidSignatureError(
                        'Invalid session token'));
                }

                if (!tokenData || !tokenData.uuid) {
                    log.error({
                        accessKeyId: authInfo.accessKeyId,
                        tokenData: tokenData
                    }, 'sigv4.verify: JWT session token validation failed' +
                              ' - no user UUID');
                    return cb(new errors.InvalidSignatureError(
                        'Invalid session token'));
                }

                log.info({
                    accessKeyId: authInfo.accessKeyId,
                    tokenData: tokenData,
                    tokenValid: !!tokenData,
                    userUuid: tokenData ? tokenData.uuid : null
                }, 'sigv4.verify: JWT session token verification SUCCESS');

            // Now lookup the temporary credential in Redis
            var accessKeyLookupKey = sprintf('/accesskey/%s',
                                             authInfo.accessKeyId);
            redis.get(accessKeyLookupKey, function (redisErr, credentialData) {
                if (redisErr) {
                    log.error({
                        err: redisErr,
                        accessKeyId: authInfo.accessKeyId
                    }, 'sigv4.verify: Redis lookup failed for' +
                              ' temporary credential');
                    return (cb(new errors.RedisError(redisErr)));
                }

                if (credentialData) {
                    var tempCredData;
                    try {
                        tempCredData = JSON.parse(credentialData);
                    } catch (parseErr) {
                        log.debug({
                            accessKeyId: authInfo.accessKeyId,
                            credentialDataType: typeof (credentialData),
                            credentialDataLength: credentialData ?
                                credentialData.length : 0,
                            credentialDataSample: credentialData ?
                                credentialData.substring(0, 100) +
                                '...' : 'null'
                        }, 'sigv4.verify: Redis contains non-JSON data,' +
                                  ' probably UUID - trying UFDS');

                        // If Redis contains just a UUID (old format),
                        // fall back to UFDS
                        if (ufds) {
                            return handleTemporaryCredential(authInfo,
                                                             sessionToken,
                                                             req,
                                                             log,
                                                             ufds,
                                                             cb);
                        } else {
                            return cb(new errors.InvalidSignatureError(
                                'Cannot verify temporary credentials'));
                        }
                    }

                    // Check expiration from credential data
                    if (tempCredData.expiration &&
                        new Date(tempCredData.expiration) < new Date()) {
                        log.info({
                            accessKeyId: authInfo.accessKeyId,
                            expiration: tempCredData.expiration
                        }, 'sigv4.verify: Temporary credential expired');
                        return cb(new errors.InvalidSignatureError
                                  ('Credential expired'));
                    }

                    log.debug({
                        accessKeyId: authInfo.accessKeyId,
                        userUuid: tempCredData.userUuid,
                        jwtUserUuid: tokenData.uuid,
                        expiration: tempCredData.expiration,
                        assumedRole: tempCredData.assumedRole ?
                            tempCredData.assumedRole.arn : null
                    }, 'sigv4.verify: Successfully verified temporary' +
                              ' credential from Redis with JWT');

                    // Return the credential info for signature verification
                    return cb(null, {
                        accessKeyId: tempCredData.accessKeyId,
                        secretAccessKey: tempCredData.secretAccessKey,
                        userUuid: tempCredData.userUuid,
                        user: { uuid: tempCredData.userUuid },
                        account: { uuid: tempCredData.userUuid },
                        isTemporary: true,
                        isTemporaryCredential: true,
                        assumedRole: tempCredData.assumedRole,
                        principalUuid: tempCredData.userUuid,
                        expiration: tempCredData.expiration
                    });
                }

                // Not found in Redis - try UFDS if available
                if (ufds) {
                    log.info({
                        accessKeyId: authInfo.accessKeyId
                    }, 'sigv4.verify: Temporary credential' +
                             ' not in Redis, trying UFDS');
                    return handleTemporaryCredential(authInfo,
                                                     sessionToken,
                                                     req,
                                                     log,
                                                     ufds,
                                                     cb);
                }

                log.error({
                    accessKeyId: authInfo.accessKeyId
                }, 'sigv4.verify: Temporary credential' +
                          ' not found in Redis and no UFDS available');
                return cb(new errors.InvalidSignatureError(
                    'Cannot verify temporary credentials'));
            });
            }); // Close JWT verification callback
            return;
        }

        // Detect temporary credentials (MSTS or MSAR) used
        // without session token - this is a security violation
        var isTempKey = authInfo.accessKeyId &&
            (authInfo.accessKeyId.indexOf('MSTS') === 0 ||
             authInfo.accessKeyId.indexOf('MSAR') === 0);
        if (isTempKey) {
            log.error({
                accessKeyId: authInfo.accessKeyId,
                hasSessionToken: !!sessionToken,
                sessionTokenLength: sessionToken ? sessionToken.length : 0
            }, 'SECURITY: Temporary access key used without' +
                      ' session token - BLOCKING');

            cb(new errors.InvalidSignatureError(
                'Temporary credentials' +
                    ' require session token for authentication'));
            return;
        }

        // Handle permanent credentials - look up from Redis
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

                        // According to AWS S3 documentation a 15 minutes
                        // threshold is used as a security mechanism to
                        // prevent replay attacks.
                        // https://docs.aws.amazon.com/AmazonS3/latest/API/\
                        // sig-v4-authenticating-requests.html
                        var requestTime =
                                parseISO8601Basic(timestamp).getTime();
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
                        return;
                });
                return;
        });
}
/*jsl:end*/

module.exports = {
        parseAuthHeader: parseAuthHeader,
        verifySigV4: verifySigV4
};
