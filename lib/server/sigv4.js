/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2026 Edgecast Cloud LLC.
 */

var assert = require('assert-plus');
var crypto = require('crypto');
var sprintf = require('util').format;
var errors = require('./errors.js');
var sessionTokenModule = require('./session-token');
var utils = require('./utils.js');

/**
 * AWS SigV4 Authentication Module for Mahi
 *
 * Y2038 COMPATIBILITY NOTE: JavaScript Date objects use 64-bit IEEE 754
 * floating-point numbers internally and correctly handle dates beyond 2038
 * even on 32-bit platforms. Testing on 32-bit Node.js v0.10.48 (SunOS ia32)
 * confirms that Date arithmetic, parsing, and comparison work correctly with
 * post-Y2038 timestamps.
 *
 * The Y2038 problem in Node.js manifests in system-level operations (file
 * timestamps via fs.utimes/fs.stat, native modules using time_t), not in
 * JavaScript Date operations. For SigV4 authentication, timestamps are parsed
 * from HTTP headers and compared using JavaScript Date arithmetic, which is
 * Y2038-safe on all platforms.
 *
 * The Y2038_THRESHOLD_MS constant and overflow detection code remain as
 * defensive measures for potential edge cases in system-level operations.
 */

/*
 * AccessKeyId validation regex from sdc-ufds/schema/accesskey.js
 * Matches word characters only (alphanumeric + underscore)
 */
var ACCESSKEYID_RE = /^\w+$/;

/*
 * AccessKeyId validation constants from sdc-ufds schema
 * (sdc-ufds/schema/accesskey.js)
 */
var MIN_ACCESSKEYID_LENGTH = 16;
var MAX_ACCESSKEYID_LENGTH = 128;

/*
 * Y2038 timestamp threshold (2038-01-19 03:14:08 UTC)
 * Used to log warnings for post-Y2038 timestamps. JavaScript Date arithmetic
 * works correctly on all platforms (uses 64-bit floats), so this is only for
 * observability, not for skipping validation.
 * Milliseconds since Unix epoch: (2^31 - 1)  * 1000
 */
var Y2038_THRESHOLD_MS = 2147483647000;

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
 * @since 2.1.0
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
 * @since 2.1.0
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
                                var keyId = credParts[0];
                                if (!ACCESSKEYID_RE.test(keyId) ||
                                    keyId.length < MIN_ACCESSKEYID_LENGTH ||
                                    keyId.length > MAX_ACCESSKEYID_LENGTH) {
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
 * @since 2.1.0
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
 * @since 2.1.0
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
 * @since 2.1.0
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
 * @since 2.1.0
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
        return ({
                signature: hmac(kSigning, stringToSign).toString('hex'),
                signingKey: kSigning.toString('hex')
        });
}

/**
 * @brief Verify a SigV4 signature given a secret key
 *
 * Shared helper used by the Redis path, the UFDS
 * permanent-key fallback, and the UFDS temporary-
 * credential fallback.  Validates timestamp freshness,
 * builds the canonical request, and compares the
 * computed signature against the client's signature.
 *
 * @param {Object} authInfo - Parsed Authorization header
 * @param {string} secretKey - The access key secret
 * @param {Object} req - HTTP request (headers, query)
 * @param {Object} log - Bunyan logger
 * @return {Object} { err, signingKey } — err is null
 *   on success, an Error on failure
 */
function verifySigV4Signature(authInfo, secretKey, req, log) {
    var timestamp = req.headers['x-amz-date'] ||
        req.headers.date;
    if (!timestamp) {
        return ({
            err: new errors.InvalidSignatureError(
                'Missing timestamp'),
            signingKey: null
        });
    }

    var requestTime =
        parseISO8601Basic(timestamp).getTime();
    var currentTime = Date.now();
    var timeDiff = Math.abs(currentTime - requestTime);

    if (requestTime > Y2038_THRESHOLD_MS) {
        log.warn({
            requestTimestamp: timestamp,
            requestTimeMs: requestTime,
            systemTimeMs: currentTime,
            timeDiff: timeDiff
        }, 'Y2038: Request timestamp beyond Y2038 ' +
            'threshold.');
    }

    if (timeDiff > 15 * 60 * 1000) {
        return ({
            err: new errors.InvalidSignatureError(
                'Request timestamp too old'),
            signingKey: null
        });
    }

    var originalMethod =
        req.query.method || req.method;
    var originalUrl =
        req.query.url || req.url;
    var uri = originalUrl.split('?')[0];
    if (req.query.url) {
        originalUrl =
            decodeURIComponent(originalUrl);
        uri = decodeURIComponent(uri);
    }

    var queryString =
        originalUrl.split('?')[1] || '';
    var payloadHash =
        req.headers['x-amz-content-sha256'] ||
        'UNSIGNED-PAYLOAD';

    var canonicalRequest = createCanonicalRequest(
        originalMethod, uri, queryString,
        req.headers, authInfo.signedHeaders,
        payloadHash);

    var credentialScope = sprintf(
        '%s/%s/%s/aws4_request',
        authInfo.dateStamp, authInfo.region,
        authInfo.service);
    var stringToSign = createStringToSign(
        timestamp, credentialScope,
        canonicalRequest);

    var sigResult = calculateSignature(
        secretKey, authInfo.dateStamp,
        authInfo.region, authInfo.service,
        stringToSign);

    if (sigResult.signature !== authInfo.signature) {
        log.debug({
            expected: sigResult.signature,
            received: authInfo.signature,
            stringToSign: stringToSign,
            canonicalRequest: canonicalRequest
        }, 'Signature mismatch');
        return ({
            err: new errors.InvalidSignatureError(
                'Signature mismatch'),
            signingKey: null
        });
    }

    return ({
        err: null,
        signingKey: sigResult.signingKey
    });
}


/*
 * Negative cache for permanent key IDs not found in
 * UFDS.  Prevents an attacker from forcing UFDS LDAP
 * queries by sending garbage key IDs.  Entries expire
 * after NEGATIVE_CACHE_TTL_MS.
 *
 * FALSE-NEGATIVE RISK: A key is added to this cache when
 * it is absent from Redis and no UFDS client is passed to
 * verifySigV4 (opts.ufds is null).  When UFDS IS available,
 * the read-through path is used instead and the negative
 * cache is bypassed.  If the key subsequently arrives in
 * Redis (via replication or cache-push), the cache entry
 * will still cause 401s for up to NEGATIVE_CACHE_TTL_MS
 * (30 seconds).
 *
 * This can happen when:
 *   1. A key is created in UFDS but the replicator is lagging.
 *   2. A request arrives before the key reaches Redis.
 *   3. The key later replicates to Redis.
 *   4. For the next ~30 s, the cache rejects the valid key.
 *
 * Mitigation: CloudAPI calls POST /cache-push immediately
 * after key creation so the key is in Redis before the
 * caller's first request.  Do NOT skip the cache-push call
 * for newly created permanent keys.
 */
var NEGATIVE_CACHE_TTL_MS = 30000;
var NEGATIVE_CACHE_MAX_SIZE = 10000;
var NEGATIVE_CACHE_SWEEP_MS = 60000;
var negativeKeyCache = {};
var negativeCacheSize = 0;

/*
 * Periodic sweep: evict expired entries every 60s instead
 * of resetting the entire cache at the size limit.  This
 * avoids the cliff behavior where a full cache is emptied
 * in one shot, causing a burst of UFDS queries.
 */
setInterval(function sweepNegativeCache() {
    var now = Date.now();
    var keys = Object.keys(negativeKeyCache);
    for (var i = 0; i < keys.length; i++) {
        if (now - negativeKeyCache[keys[i]] >
            NEGATIVE_CACHE_TTL_MS) {
            delete negativeKeyCache[keys[i]];
            negativeCacheSize--;
        }
    }
}, NEGATIVE_CACHE_SWEEP_MS).unref();

/**
 * @brief Check if a key ID is in the negative cache
 *
 * @param {string} keyId
 * @return {boolean} true if recently not-found
 */
function isNegativelyCached(keyId) {
    var entry = negativeKeyCache[keyId];
    if (!entry) {
        return (false);
    }
    if (Date.now() - entry > NEGATIVE_CACHE_TTL_MS) {
        /*
         * Expired — treat as not cached.  Do NOT delete
         * here; the periodic sweep handles eviction and
         * counter decrement.  Deleting in both places
         * causes counter drift (double-decrement).
         */
        return (false);
    }
    return (true);
}

/**
 * @brief Add a key ID to the negative cache
 *
 * If the cache exceeds NEGATIVE_CACHE_MAX_SIZE, new
 * entries are not added (the periodic sweep will free
 * space).  This bounds memory without the cliff-reset
 * behavior that previously emptied the entire cache.
 *
 * @param {string} keyId
 */
var _lastCacheFullWarn = 0;
function addToNegativeCache(keyId) {
    if (negativeCacheSize >= NEGATIVE_CACHE_MAX_SIZE) {
        var now = Date.now();
        if (now - _lastCacheFullWarn > 60000) {
            _lastCacheFullWarn = now;
            /* global console */
            console.error(
                'sigv4: negative cache full (%d ' +
                'entries), dropping new entries — ' +
                'possible sustained garbage-key attack',
                negativeCacheSize);
        }
        return;
    }
    negativeKeyCache[keyId] = Date.now();
    negativeCacheSize++;
}


/**
 * @brief UFDS read-through for permanent keys
 *
 * Called when a permanent key is not found in Redis
 * (replication lag).  Searches UFDS directly, verifies
 * the SigV4 signature, and returns the same result
 * shape as the Redis path.
 *
 * @param {Object} authInfo - Parsed auth header
 * @param {Object} req - HTTP request
 * @param {Object} log - Bunyan logger
 * @param {Object} redis - Redis client (unused, for
 *   interface compat)
 * @param {Object} ufds - UFDS client
 * @param {Function} cb - callback(err, result)
 */
function handlePermanentCredentialUfds(
    authInfo, req, log, redis, ufds, cb) {

    /*
     * Validate access key ID format before using it in
     * an LDAP filter.  Access key IDs are hex strings
     * (32 chars for permanent keys).  Reject anything
     * that contains LDAP special characters to prevent
     * filter injection.
     */
    if (!/^[a-zA-Z0-9_-]+$/.test(authInfo.accessKeyId)) {
        cb(new errors.InvalidSignatureError(
            'Invalid access key format'));
        return;
    }

    if (isNegativelyCached(authInfo.accessKeyId)) {
        cb(new errors.InvalidSignatureError(
            'Invalid access key'));
        return;
    }

    var searchBase = 'ou=users, o=smartdc';
    var searchFilter =
        '(&(objectclass=accesskey)(accesskeyid=' +
        authInfo.accessKeyId +
        ')(status=Active))';

    ufds.search(searchBase, {
        scope: 'sub',
        filter: searchFilter
    }, function (searchErr, searchRes) {
        if (searchErr) {
            /*
             * UFDS unreachable — return 503 so the
             * client retries, rather than masking
             * the outage as "key not found."
             */
            log.error({
                err: searchErr,
                accessKeyId: authInfo.accessKeyId
            }, 'sigv4.ufds-fallback: UFDS search' +
                ' failed');
            cb(new errors.ReplicatorNotReadyError());
            return;
        }

        if (!searchRes || searchRes.length === 0) {
            log.warn({
                accessKeyId: authInfo.accessKeyId
            }, 'sigv4.ufds-fallback: key not found' +
                ' in UFDS — genuinely invalid');
            addToNegativeCache(authInfo.accessKeyId);
            cb(new errors.InvalidSignatureError(
                'Invalid access key'));
            return;
        }

        var cred = searchRes[0];
        var credData = cred.object || cred;
        var secretKey = credData.accesskeysecret;
        var ownerUuid = credData._owner;
        var bucketScope = credData.accesskeyscope ||
            null;

        if (Array.isArray(secretKey)) {
            secretKey = secretKey[0];
        }
        if (Array.isArray(ownerUuid)) {
            ownerUuid = ownerUuid[0];
        }
        if (Array.isArray(bucketScope)) {
            bucketScope = bucketScope[0];
        }

        if (!secretKey || !ownerUuid) {
            log.error({
                accessKeyId: authInfo.accessKeyId,
                hasSecret: !!secretKey,
                hasOwner: !!ownerUuid
            }, 'sigv4.ufds-fallback: incomplete' +
                ' UFDS entry');
            cb(new errors.InvalidSignatureError(
                'Incomplete access key data'));
            return;
        }

        var result = verifySigV4Signature(
            authInfo, secretKey, req, log);
        if (result.err) {
            cb(result.err);
            return;
        }

        log.info({
            accessKeyId: authInfo.accessKeyId,
            ownerUuid: ownerUuid
        }, 'sigv4.ufds-fallback: verification' +
            ' successful (read-through)');

        cb(null, buildPermanentResult(
            { uuid: ownerUuid },
            authInfo.accessKeyId,
            result.signingKey,
            bucketScope));
    });
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
 * @since 2.1.0
 */
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
            cb(new errors.InvalidSignatureError
                      ('Failed to verify temporary credential'));
            return;
        }

        if (!searchRes || searchRes.length === 0) {
            log.warn({
                accessKeyId: authInfo.accessKeyId
            }, 'sigv4.handleTemporaryCredential' +
               ': temporary credential not found');
            cb(new errors.InvalidSignatureError
                      ('Invalid temporary access key'));
            return;
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
                cb(new errors.InvalidSignatureError
                          ('Temporary credential expired'));
                return;
            }
        }

        // Verify session token matches
        if (credData.sessiontoken !== sessionToken) {
            log.warn({
                accessKeyId: authInfo.accessKeyId
            }, 'sigv4.handleTemporaryCredential: session token mismatch');
            cb(new errors.InvalidSignatureError
                      ('Invalid session token'));
            return;
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
                cb(new errors.InvalidSignatureError
                          ('Invalid principal user'));
                return;
            }

            var user;
            try {
                user = JSON.parse(userRes);
            } catch (parseErr) {
                log.error({
                    err: parseErr,
                    principalUuid: principalUuid,
                    userRes: userRes ?
                        userRes.substring(0, 100) : 'null'
                }, 'Failed to parse principal user' +
                    ' data from Redis');
                cb(new errors.InvalidSignatureError(
                    'Corrupt principal user data'));
                return;
            }

            // Verify signature using the temporary credential's secret key
            var secretKey = credData.accesskeysecret;

            // Perform signature verification (reuse permanent credential logic)
            var timestamp = req.headers['x-amz-date'];
            if (!timestamp) {
                cb(new errors.InvalidSignatureError
                          ('Missing X-Amz-Date header'));
                return;
            }

            // Check timestamp skew (15 minutes threshold)
            var requestTime = parseISO8601Basic(timestamp).getTime();
            var currentTime = Date.now();
            var timeDiff = Math.abs(currentTime - requestTime);

            // Y2038 detection: Log warning for post-Y2038 timestamps.
            // JavaScript Date arithmetic works correctly on all platforms,
            // so freshness check proceeds normally.
            if (requestTime > Y2038_THRESHOLD_MS) {
                log.warn({
                    requestTimestamp: timestamp,
                    requestTimeMs: requestTime,
                    systemTimeMs: currentTime,
                    timeDiff: timeDiff
                }, 'Y2038: Request timestamp beyond Y2038 threshold. ' +
                   'Timestamp validation proceeds normally.');
            }

            if (timeDiff > 15 * 60 * 1000) { // 15 minutes
                cb(new errors.InvalidSignatureError
                          ('Request timestamp too old'));
                return;
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
            var sigResult = calculateSignature(secretKey,
                                               authInfo.dateStamp,
                                               authInfo.region,
                                               authInfo.service,
                                               stringToSign);

            // Verify signature matches
            if (sigResult.signature !== authInfo.signature) {
                log.warn({
                    accessKeyId: authInfo.accessKeyId,
                    expectedSignature: sigResult.signature,
                    providedSignature: authInfo.signature
                }, 'sigv4.handleTemporaryCredential:' +
                   ' signature mismatch for temporary credential');
                cb(new errors.InvalidSignatureError
                          ('Signature mismatch'));
                return;
            }

            // Return result with role information
            var result = buildTemporaryResult({
                accessKeyId: authInfo.accessKeyId,
                userUuid: principalUuid,
                user: user,
                assumedRole: credData.assumedrole,
                principalUuid: principalUuid,
                signingKey: sigResult.signingKey,
                bucketScope: (credData.accesskeyscope != null)
                    ? credData.accesskeyscope : null
            });

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

/**
 * @brief Build the standard result object for temporary credential
 * verification.
 *
 * Shared by handleTemporaryCredentialRedis and
 * handleTemporaryCredential (UFDS) to prevent divergence in
 * result construction — the same pattern that caused bugs C1
 * and C3 in the permanent credential path.
 *
 * @param {Object} opts
 * @param {string} opts.accessKeyId
 * @param {string} [opts.secretAccessKey]
 * @param {string} opts.userUuid
 * @param {Object} opts.user - User object
 * @param {Object|string} [opts.assumedRole]
 * @param {string} [opts.principalUuid]
 * @param {string} [opts.expiration]
 * @param {Buffer} opts.signingKey
 * @param {string|null} [opts.bucketScope]
 * @return {Object} Verification result
 */
function buildTemporaryResult(opts) {
    return ({
        accessKeyId: opts.accessKeyId,
        secretAccessKey: opts.secretAccessKey || null,
        userUuid: opts.userUuid,
        user: opts.user || { uuid: opts.userUuid },
        account: { uuid: opts.userUuid },
        isTemporary: true,
        isTemporaryCredential: true,
        assumedRole: opts.assumedRole || null,
        principalUuid: opts.principalUuid || opts.userUuid,
        credentialType: 'temporary',
        expiration: opts.expiration || null,
        signingKey: opts.signingKey,
        bucketScope: (opts.bucketScope != null) ? opts.bucketScope : null
    });
}


/**
 * @brief Build the standard result object for permanent credential
 * verification.
 *
 * Shared by handlePermanentCredentialRedis and
 * handlePermanentCredentialUfds to prevent divergence in result
 * construction (the source of bugs C1 and C3).
 *
 * @param {Object} user - User object (full from Redis or
 *   {uuid} stub from UFDS)
 * @param {string} accessKeyId - Verified access key ID
 * @param {Buffer} signingKey - Derived signing key
 * @param {string|null} bucketScope - Scope JSON string or null
 * @return {Object} Verification result
 */
function buildPermanentResult(user, accessKeyId, signingKey, bucketScope) {
    return ({
        user: user,
        accessKeyId: accessKeyId,
        signingKey: signingKey,
        bucketScope: (bucketScope != null) ? bucketScope : null
    });
}


/**
 * @brief Handle permanent credential verification via Redis
 *
 * Extracted from verifySigV4() to reduce indentation and isolate
 * the Redis-based permanent key verification path.
 *
 * 1. Reverse-lookup /accesskey/{id} to get userUuid
 * 2. Fetch /uuid/{uuid} to get user record with accesskeys map
 * 3. Extract secret + scope from key data (object or legacy string)
 * 4. Verify SigV4 signature
 * 5. Return result via buildPermanentResult()
 *
 * On Redis miss, delegates to handlePermanentCredentialUfds()
 * or the negative cache.
 *
 * @param {Object} authInfo - Parsed auth header
 * @param {Object} req - HTTP request
 * @param {Object} log - Bunyan logger
 * @param {Object} redis - Redis client
 * @param {Object|null} ufds - UFDS client (null when unavailable)
 * @param {Function} cb - callback(err, result)
 */
function handlePermanentCredentialRedis(
    authInfo, req, log, redis, ufds, cb) {

    var accessKeyLookupKey = sprintf('/accesskey/%s',
        authInfo.accessKeyId);
    redis.get(accessKeyLookupKey, function (err, lookupVal) {
        if (err) {
            cb(new errors.RedisError(err));
            return;
        }

        if (!lookupVal) {
            /*
             * Key not in Redis.  This happens
             * when a key was just created in
             * UFDS but the replicator has not
             * synced it yet (~2s).  Fall through
             * to a direct UFDS lookup so the
             * first request succeeds without
             * requiring a client retry.
             */
            if (!ufds) {
                addToNegativeCache(
                    authInfo.accessKeyId);
                cb(new errors.InvalidSignatureError(
                    'Invalid access key'));
                return;
            }
            log.info({
                accessKeyId: authInfo.accessKeyId
            }, 'sigv4.verify: permanent key' +
               ' not in Redis, trying UFDS' +
               ' read-through');
            handlePermanentCredentialUfds(
                authInfo, req, log,
                redis, ufds, cb);
            return;
        }

        /*
         * Reverse-lookup values are always JSON
         * objects with a userUuid field.  Legacy
         * plain-UUID format is no longer written
         * but tolerated for in-flight keys that
         * have not been re-replicated yet.
         */
        var userUuid;
        if (lookupVal.charAt(0) === '{') {
            try {
                var parsed = JSON.parse(lookupVal);
                userUuid = parsed.userUuid;
            } catch (e) {
                cb(new errors.InvalidSignatureError(
                    'Corrupt access key lookup'));
                return;
            }
        } else {
            userUuid = lookupVal;
        }

        if (!userUuid) {
            cb(new errors.InvalidSignatureError(
                'Invalid access key data'));
            return;
        }

        var userKey = sprintf('/uuid/%s', userUuid);
        redis.get(userKey, function (userErr, userRes) {
            if (userErr) {
                cb(new errors.RedisError(userErr));
                return;
            }

            if (!userRes) {
                cb(new errors.InvalidSignatureError(
                    'User not found'));
                return;
            }

            var user;
            try {
                user = JSON.parse(userRes);
            } catch (parseErr) {
                log.error({
                    err: parseErr,
                    userUuid: userUuid,
                    userRes: userRes ?
                        userRes.substring(0, 100) :
                        'null'
                }, 'Failed to parse user data' +
                    ' from Redis');
                cb(new errors.InvalidSignatureError(
                    'Corrupt user data'));
                return;
            }
            if (!user.accesskeys ||
                !user.accesskeys[authInfo.accessKeyId]) {
                cb(new errors.InvalidSignatureError(
                    'Access key not found'));
                return;
            }

            /*
             * Extract secret key and optional
             * bucket scope from access key data.
             *
             * The new replicator writes all permanent
             * keys as objects:
             *   { secret: "...", scope: <json|null> }
             *
             * The string fallback below handles the
             * pre-upgrade Redis format where permanent
             * keys were stored as bare secret strings.
             * During a rolling upgrade, existing keys
             * remain as strings until the replicator
             * re-writes them (on status toggle, scope
             * change, or key rotation).  Remove this
             * branch once all deployments have been
             * upgraded and keys re-replicated.
             */
            var keyData =
                user.accesskeys[authInfo.accessKeyId];
            var secretKey;
            var bucketScope = null;
            if (keyData &&
                typeof (keyData) === 'object') {
                secretKey = keyData.secret;
                bucketScope = keyData.scope ||
                    null;
            } else if (typeof (keyData) === 'string') {
                secretKey = keyData;
            }
            if (!secretKey) {
                log.warn({
                    accessKeyId: authInfo.accessKeyId,
                    keyDataType: typeof (keyData),
                    hasSecret: keyData &&
                        typeof (keyData) === 'object' ?
                        !!keyData.secret : 'n/a'
                }, 'Access key data present but ' +
                    'secret could not be extracted');
                cb(new errors.InvalidSignatureError(
                    'Access key secret not found'));
                return;
            }

            var sigResult = verifySigV4Signature(
                authInfo, secretKey, req, log);
            if (sigResult.err) {
                cb(sigResult.err);
                return;
            }

            log.debug({
                accessKeyId: authInfo.accessKeyId,
                userUuid: userUuid
            }, 'SigV4 verification successful');
            cb(null, buildPermanentResult(
                user, authInfo.accessKeyId,
                sigResult.signingKey, bucketScope));
        });
    });
}


/**
 * @brief Handle temporary credential verification via Redis
 *
 * Extracted from verifySigV4() to reduce indentation and isolate
 * the Redis-based temporary credential verification path.
 *
 * Called after JWT session token validation succeeds.  Looks up
 * the temporary credential in Redis, checks expiration, derives
 * the signing key, and returns the result.
 *
 * On Redis miss or parse failure, delegates to
 * handleTemporaryCredential() (UFDS path).
 *
 * @param {Object} authInfo - Parsed auth header
 * @param {Object} tokenData - Validated JWT token data
 * @param {string} sessionToken - Raw session token string
 * @param {Object} req - HTTP request
 * @param {Object} log - Bunyan logger
 * @param {Object} redis - Redis client
 * @param {Object|null} ufds - UFDS client (null when unavailable)
 * @param {Function} cb - callback(err, result)
 */
function handleTemporaryCredentialRedis(
    authInfo, tokenData, sessionToken, req, log, redis, ufds, cb) {

    var accessKeyLookupKey = sprintf('/accesskey/%s',
        authInfo.accessKeyId);
    redis.get(accessKeyLookupKey, function (redisErr, credentialData) {
        if (redisErr) {
            log.error({
                err: redisErr,
                accessKeyId: authInfo.accessKeyId
            }, 'sigv4.verify: Redis lookup failed for' +
                ' temporary credential');
            cb(new errors.RedisError(redisErr));
            return;
        }

        if (credentialData) {
            var tempCredData;
            try {
                tempCredData = JSON.parse(credentialData);
            } catch (_parseErr) {
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

                if (ufds) {
                    handleTemporaryCredential(authInfo,
                        sessionToken, req, log, ufds, cb);
                    return;
                } else {
                    cb(new errors.InvalidSignatureError(
                        'Cannot verify temporary credentials'));
                    return;
                }
            }

            if (tempCredData.expiration &&
                new Date(tempCredData.expiration) < new Date()) {
                log.info({
                    accessKeyId: authInfo.accessKeyId,
                    expiration: tempCredData.expiration
                }, 'sigv4.verify: Temporary credential expired');
                cb(new errors.InvalidSignatureError(
                    'Credential expired'));
                return;
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

            var redisSigResult = calculateSignature(
                tempCredData.secretAccessKey,
                authInfo.dateStamp,
                authInfo.region,
                authInfo.service,
                'dummy');

            cb(null, buildTemporaryResult({
                accessKeyId: tempCredData.accessKeyId,
                secretAccessKey: tempCredData.secretAccessKey,
                userUuid: tempCredData.userUuid,
                assumedRole: tempCredData.assumedRole,
                expiration: tempCredData.expiration,
                signingKey: redisSigResult.signingKey,
                bucketScope: (tempCredData.bucketScope != null)
                    ? tempCredData.bucketScope : null
            }));
            return;
        }

        // Not found in Redis - try UFDS if available
        if (ufds) {
            log.info({
                accessKeyId: authInfo.accessKeyId
            }, 'sigv4.verify: Temporary credential' +
                ' not in Redis, trying UFDS');
            handleTemporaryCredential(authInfo,
                sessionToken, req, log, ufds, cb);
            return;
        }

        log.error({
            accessKeyId: authInfo.accessKeyId
        }, 'sigv4.verify: Temporary credential' +
            ' not found in Redis and no UFDS available');
        cb(new errors.InvalidSignatureError(
            'Cannot verify temporary credentials'));
    });
}


/**
 * @brief Verify AWS Signature Version 4 authentication
 *
 * Dispatcher that routes to the appropriate credential handler
 * based on whether a session token is present (temporary) or
 * not (permanent).
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
 * @since 2.1.0
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
        /*
         * UFDS client (or pool proxy with .search()).
         * Used for read-through when a key is absent
         * from Redis (replication lag).  Null when UFDS
         * is not configured — permanent key misses go
         * to the negative cache, temp cred misses fail.
         */
        var ufds = opts.ufds || null;

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
        // Maximum length per sdc-ufds schema (MAX_ACCESSKEYID_LENGTH)
        if (authInfo.accessKeyId &&
            typeof (authInfo.accessKeyId) === 'string' &&
            authInfo.accessKeyId.length > MAX_ACCESSKEYID_LENGTH) {
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

            var secretConfig = opts.secretConfig;

            if (!secretConfig || !secretConfig.secrets) {
                log.error({
                    accessKeyId: authInfo.accessKeyId
                }, 'sigv4.verify: No session secret config available for ' +
                    'JWT validation');
                cb(new errors.InvalidSignatureError(
                    'Cannot verify session token'));
                return;
            }

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

            sessionTokenModule.verifySessionToken(sessionToken,
                secretConfig, {},
                function (jwtErr, tokenData) {
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
                    cb(new errors.InvalidSignatureError(
                        'Invalid session token'));
                    return;
                }

                if (!tokenData || !tokenData.uuid) {
                    log.error({
                        accessKeyId: authInfo.accessKeyId,
                        tokenData: tokenData
                    }, 'sigv4.verify: JWT session token validation failed' +
                        ' - no user UUID');
                    cb(new errors.InvalidSignatureError(
                        'Invalid session token'));
                    return;
                }

                log.info({
                    accessKeyId: authInfo.accessKeyId,
                    tokenData: tokenData,
                    tokenValid: !!tokenData,
                    userUuid: tokenData ? tokenData.uuid : null
                }, 'sigv4.verify: JWT session token verification SUCCESS');

                handleTemporaryCredentialRedis(
                    authInfo, tokenData, sessionToken,
                    req, log, redis, ufds, cb);
            });
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

        /*
         * Handle permanent credentials via Redis.
         *
         * Short-circuit with the negative cache so that
         * repeated requests with the same invalid key ID
         * do not hit Redis on every attempt.  Only check
         * when UFDS is unavailable — when UFDS is present,
         * a key cached as missing in Redis may still be
         * found via UFDS read-through (newly created key).
         */
        if (!ufds &&
            isNegativelyCached(authInfo.accessKeyId)) {
            log.debug({
                accessKeyId: authInfo.accessKeyId
            }, 'sigv4: rejected by negative cache');
            cb(new errors.InvalidSignatureError(
                'Invalid access key'));
            return;
        }

        handlePermanentCredentialRedis(
            authInfo, req, log, redis, ufds, cb);
}

module.exports = {
        parseAuthHeader: parseAuthHeader,
        verifySigV4: verifySigV4,
        _handleTemporaryCredential: handleTemporaryCredential,
        _handlePermanentCredentialRedis: handlePermanentCredentialRedis,
        _handleTemporaryCredentialRedis: handleTemporaryCredentialRedis,
        _buildPermanentResult: buildPermanentResult,
        _buildTemporaryResult: buildTemporaryResult
};
