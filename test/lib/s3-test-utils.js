/*
 * This Source Code Form is subject to the terms of the
 * Mozilla Public License, v. 2.0. If a copy of the MPL
 * was not distributed with this file, You can obtain
 * one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright (c) 2025, Joyent, Inc.
 */

/**
 * S3 Test Utilities
 *
 * Comprehensive test utilities for S3-related testing including
 * STS token generation, IAM policy builders, request/response
 * validation, and helpers for common test scenarios.
 */

var assert = require('assert-plus');
var _crypto = require('crypto');

/* --- STS Token Generation --- */

/**
 * @brief Generate a mock STS session token
 *
 * Creates a mock AWS STS session token for testing. The token
 * includes temporary credentials (access key, secret key, and
 * session token) with configurable expiration.
 *
 * @param {object} opts Token generation options
 * @param {string} [opts.accessKeyId] Base access key
 *        (default: generated)
 * @param {string} [opts.accountId] AWS account ID
 * @param {string} [opts.userName] IAM user name
 * @param {number} [opts.durationSeconds] Token duration
 *        (default: 3600)
 * @param {string} [opts.policy] IAM policy JSON string
 * @param {number} [opts.timestamp] Token issue time (ms)
 *        (default: Date.now())
 *
 * @return {object} STS credentials object with accessKeyId,
 *         secretAccessKey, sessionToken, and expiration
 *
 * @example
 * var creds = generateSTSToken({
 *     accountId: '123456789012',
 *     userName: 's3user',
 *     durationSeconds: 3600
 * });
 * // creds.accessKeyId = 'ASIATEMPORARY...'
 * // creds.sessionToken = 'FwoGZXIv...'
 *
 * @since 1.0.0
 */
function generateSTSToken(opts) {
    opts = opts || {};
    assert.optionalString(opts.accessKeyId, 'opts.accessKeyId');
    assert.optionalString(opts.accountId, 'opts.accountId');
    assert.optionalString(opts.userName, 'opts.userName');
    assert.optionalNumber(opts.durationSeconds,
        'opts.durationSeconds');
    assert.optionalString(opts.policy, 'opts.policy');
    assert.optionalNumber(opts.timestamp, 'opts.timestamp');

    var now = opts.timestamp || Date.now();
    var duration = opts.durationSeconds || 3600;
    var expiration = new Date(now + (duration * 1000));

    /* Generate temporary access key ID (ASIA prefix) */
    var tempAccessKeyId = opts.accessKeyId ||
        'ASIA' + _randomString(16);

    /* Generate temporary secret key */
    var tempSecretKey = _randomString(40);

    /* Generate session token */
    var sessionData = {
        accountId: opts.accountId || '123456789012',
        userName: opts.userName || 'testuser',
        expiration: expiration.toISOString(),
        policy: opts.policy || null
    };
    var sessionToken = _encodeSessionToken(sessionData);

    return {
        accessKeyId: tempAccessKeyId,
        secretAccessKey: tempSecretKey,
        sessionToken: sessionToken,
        expiration: expiration.toISOString()
    };
}

/**
 * @brief Encode session data into a session token string
 *
 * Internal helper to encode session metadata into a
 * Base64-encoded session token string.
 *
 * @param {object} data Session data to encode
 *
 * @return {string} Base64-encoded session token
 *
 * @since 1.0.0
 */
function _encodeSessionToken(data) {
    var json = JSON.stringify(data);
    var buf = new Buffer(json, 'utf8');
    return ('FwoG' + buf.toString('base64'));
}

/**
 * @brief Decode a session token string
 *
 * Decodes a Base64-encoded session token back into session
 * data. Useful for validating token contents in tests.
 *
 * @param {string} token Session token string to decode
 *
 * @return {object} Decoded session data
 *
 * @example
 * var token = generateSTSToken();
 * var data = decodeSessionToken(token.sessionToken);
 * console.log(data.expiration);
 *
 * @since 1.0.0
 */
function decodeSessionToken(token) {
    assert.string(token, 'token');

    /* Remove 'FwoG' prefix */
    var encoded = token.slice(4);
    var buf = new Buffer(encoded, 'base64');
    var json = buf.toString('utf8');
    return (JSON.parse(json));
}

/* --- IAM Policy Builders --- */

/**
 * @brief Build an IAM policy document
 *
 * Creates an IAM policy document with the specified statements.
 * Provides a fluent interface for building complex policies.
 *
 * @return {PolicyBuilder} Policy builder instance
 *
 * @example
 * var policy = buildPolicy()
 *     .allow(['s3:GetObject', 's3:PutObject'])
 *     .onResources(['arn:aws:s3:::mybucket/\*'])
 *     .build();
 *
 * @since 1.0.0
 */
function buildPolicy() {
    return (new PolicyBuilder());
}

/**
 * @brief IAM policy builder class
 *
 * Fluent interface for building IAM policy documents.
 *
 * @constructor
 *
 * @since 1.0.0
 */
function PolicyBuilder() {
    this.statements = [];
    this._currentStatement = null;
}

/**
 * @brief Add an Allow statement to the policy
 *
 * @param {array|string} actions Action or array of actions
 *        to allow
 *
 * @return {PolicyBuilder} this (for chaining)
 *
 * @since 1.0.0
 */
PolicyBuilder.prototype.allow = function allow(actions) {
    this._finishStatement();
    this._currentStatement = {
        Effect: 'Allow',
        Action: Array.isArray(actions) ? actions : [actions],
        Resource: []
    };
    return (this);
};

/**
 * @brief Add a Deny statement to the policy
 *
 * @param {array|string} actions Action or array of actions
 *        to deny
 *
 * @return {PolicyBuilder} this (for chaining)
 *
 * @since 1.0.0
 */
PolicyBuilder.prototype.deny = function deny(actions) {
    this._finishStatement();
    this._currentStatement = {
        Effect: 'Deny',
        Action: Array.isArray(actions) ? actions : [actions],
        Resource: []
    };
    return (this);
};

/**
 * @brief Specify resources for the current statement
 *
 * @param {array|string} resources Resource ARN(s)
 *
 * @return {PolicyBuilder} this (for chaining)
 *
 * @since 1.0.0
 */
PolicyBuilder.prototype.onResources =
    function onResources(resources) {
    assert.ok(this._currentStatement,
        'Must call allow() or deny() first');
    this._currentStatement.Resource = Array.isArray(resources) ?
        resources : [resources];
    return (this);
};

/**
 * @brief Add conditions to the current statement
 *
 * @param {object} conditions Condition object
 *
 * @return {PolicyBuilder} this (for chaining)
 *
 * @example
 * builder.allow('s3:GetObject')
 *     .onResources('arn:aws:s3:::bucket/\*')
 *     .withConditions({
 *         'StringEquals': {
 *             's3:x-amz-server-side-encryption': 'AES256'
 *         }
 *     });
 *
 * @since 1.0.0
 */
PolicyBuilder.prototype.withConditions =
    function withConditions(conditions) {
    assert.ok(this._currentStatement,
        'Must call allow() or deny() first');
    this._currentStatement.Condition = conditions;
    return (this);
};

/**
 * @brief Build the final policy document
 *
 * @return {object} IAM policy document
 *
 * @since 1.0.0
 */
PolicyBuilder.prototype.build = function build() {
    this._finishStatement();
    return {
        Version: '2012-10-17',
        Statement: this.statements
    };
};

/**
 * @brief Build and return as JSON string
 *
 * @return {string} JSON-encoded policy document
 *
 * @since 1.0.0
 */
PolicyBuilder.prototype.toJSON = function toJSON() {
    return (JSON.stringify(this.build()));
};

/**
 * @brief Internal: Finish current statement
 *
 * @since 1.0.0
 */
PolicyBuilder.prototype._finishStatement =
    function _finishStatement() {
    if (this._currentStatement) {
        this.statements.push(this._currentStatement);
        this._currentStatement = null;
    }
};

/**
 * @brief Create a common S3 read-only policy
 *
 * Creates a policy that allows GetObject and ListBucket on
 * specified resources.
 *
 * @param {string} bucket Bucket name or ARN pattern
 *
 * @return {object} IAM policy document
 *
 * @example
 * var policy = s3ReadOnlyPolicy('mybucket');
 *
 * @since 1.0.0
 */
function s3ReadOnlyPolicy(bucket) {
    assert.string(bucket, 'bucket');
    return (buildPolicy()
        .allow(['s3:GetObject', 's3:ListBucket'])
        .onResources([
            'arn:aws:s3:::' + bucket,
            'arn:aws:s3:::' + bucket + '/*'
        ])
        .build());
}

/**
 * @brief Create a common S3 full-access policy
 *
 * Creates a policy that allows all S3 operations on specified
 * bucket.
 *
 * @param {string} bucket Bucket name or ARN pattern
 *
 * @return {object} IAM policy document
 *
 * @since 1.0.0
 */
function s3FullAccessPolicy(bucket) {
    assert.string(bucket, 'bucket');
    return (buildPolicy()
        .allow(['s3:*'])
        .onResources([
            'arn:aws:s3:::' + bucket,
            'arn:aws:s3:::' + bucket + '/*'
        ])
        .build());
}

/* --- Request Builders --- */

/**
 * @brief Build a mock S3 HTTP request
 *
 * Creates a mock HTTP request object for testing S3 endpoints.
 *
 * @param {object} opts Request options
 * @param {string} opts.method HTTP method
 * @param {string} opts.path Request path
 * @param {object} [opts.headers] Request headers
 * @param {object} [opts.query] Query parameters
 * @param {object|string} [opts.body] Request body
 *
 * @return {object} Mock request object
 *
 * @example
 * var req = buildRequest({
 *     method: 'GET',
 *     path: '/bucket/object',
 *     headers: {'x-amz-date': '20250116T120000Z'}
 * });
 *
 * @since 1.0.0
 */
function buildRequest(opts) {
    assert.object(opts, 'opts');
    assert.string(opts.method, 'opts.method');
    assert.string(opts.path, 'opts.path');
    assert.optionalObject(opts.headers, 'opts.headers');
    assert.optionalObject(opts.query, 'opts.query');

    var headers = opts.headers || {};
    var query = opts.query || {};
    var body = opts.body;

    /* Ensure body is string if object */
    if (body && typeof (body) === 'object') {
        body = JSON.stringify(body);
        headers['content-type'] = 'application/json';
    }

    return {
        method: opts.method.toUpperCase(),
        path: opts.path,
        url: opts.path,
        headers: headers,
        query: query,
        body: body
    };
}

/**
 * @brief Build a mock S3 response
 *
 * Creates a mock HTTP response object for testing.
 *
 * @param {object} opts Response options
 * @param {number} [opts.statusCode] HTTP status code
 *        (default: 200)
 * @param {object} [opts.headers] Response headers
 * @param {object|string} [opts.body] Response body
 *
 * @return {object} Mock response object
 *
 * @since 1.0.0
 */
function buildResponse(opts) {
    opts = opts || {};
    assert.optionalNumber(opts.statusCode, 'opts.statusCode');
    assert.optionalObject(opts.headers, 'opts.headers');

    var statusCode = opts.statusCode || 200;
    var headers = opts.headers || {};
    var body = opts.body;

    /* Ensure body is string if object */
    if (body && typeof (body) === 'object') {
        body = JSON.stringify(body);
        headers['content-type'] = 'application/json';
    }

    return {
        statusCode: statusCode,
        headers: headers,
        body: body
    };
}

/* --- Response Validators --- */

/**
 * @brief Validate an authentication response
 *
 * Validates that an authentication response has the expected
 * structure and fields.
 *
 * @param {object} response Response object to validate
 * @param {object} expected Expected values
 * @param {boolean} [expected.valid] Expected valid flag
 * @param {string} [expected.accessKeyId] Expected access key
 * @param {string} [expected.userUuid] Expected user UUID
 *
 * @return {object} Validation result with {valid: bool,
 *          errors: []}
 *
 * @example
 * var result = validateAuthResponse(response, {
 *     valid: true,
 *     accessKeyId: 'AKIA123'
 * });
 * if (!result.valid) {
 *     console.error(result.errors);
 * }
 *
 * @since 1.0.0
 */
function validateAuthResponse(response, expected) {
    assert.object(response, 'response');
    assert.object(expected, 'expected');

    var errors = [];

    if (expected.hasOwnProperty('valid') &&
        response.valid !== expected.valid) {
        errors.push('Expected valid=' + expected.valid +
            ' but got ' + response.valid);
    }

    if (expected.accessKeyId &&
        response.accessKeyId !== expected.accessKeyId) {
        errors.push('Expected accessKeyId=' +
            expected.accessKeyId + ' but got ' +
            response.accessKeyId);
    }

    if (expected.userUuid &&
        response.userUuid !== expected.userUuid) {
        errors.push('Expected userUuid=' + expected.userUuid +
            ' but got ' + response.userUuid);
    }

    return {
        valid: errors.length === 0,
        errors: errors
    };
}

/**
 * @brief Validate an STS token response
 *
 * Validates that an STS token response has the expected
 * structure.
 *
 * @param {object} response STS response to validate
 *
 * @return {object} Validation result
 *
 * @since 1.0.0
 */
function validateSTSResponse(response) {
    assert.object(response, 'response');

    var errors = [];

    if (!response.accessKeyId) {
        errors.push('Missing accessKeyId');
    }
    if (!response.secretAccessKey) {
        errors.push('Missing secretAccessKey');
    }
    if (!response.sessionToken) {
        errors.push('Missing sessionToken');
    }
    if (!response.expiration) {
        errors.push('Missing expiration');
    }

    /* Validate expiration is valid ISO date */
    if (response.expiration) {
        var exp = Date.parse(response.expiration);
        if (isNaN(exp)) {
            errors.push('Invalid expiration date format');
        }
    }

    return {
        valid: errors.length === 0,
        errors: errors
    };
}

/* --- Time Utilities --- */

/**
 * @brief Generate an ISO 8601 timestamp for SigV4
 *
 * Generates a timestamp in the format required by AWS SigV4
 * (YYYYMMDDTHHmmssZ).
 *
 * @param {number} [timestamp] Unix timestamp in ms
 *        (default: Date.now())
 *
 * @return {string} ISO 8601 timestamp string
 *
 * @example
 * var ts = generateTimestamp();
 * // "20250116T120000Z"
 *
 * @since 1.0.0
 */
function generateTimestamp(timestamp) {
    var date = timestamp ? new Date(timestamp) : new Date();
    var year = date.getUTCFullYear();
    var month = _pad(date.getUTCMonth() + 1);
    var day = _pad(date.getUTCDate());
    var hour = _pad(date.getUTCHours());
    var min = _pad(date.getUTCMinutes());
    var sec = _pad(date.getUTCSeconds());

    return (year + month + day + 'T' + hour + min + sec + 'Z');
}

/**
 * @brief Generate a date string for SigV4 scope
 *
 * Generates a date string in the format required by AWS SigV4
 * credential scope (YYYYMMDD).
 *
 * @param {number} [timestamp] Unix timestamp in ms
 *        (default: Date.now())
 *
 * @return {string} Date string
 *
 * @example
 * var date = generateDateString();
 * // "20250116"
 *
 * @since 1.0.0
 */
function generateDateString(timestamp) {
    var date = timestamp ? new Date(timestamp) : new Date();
    var year = date.getUTCFullYear();
    var month = _pad(date.getUTCMonth() + 1);
    var day = _pad(date.getUTCDate());

    return ('' + year + month + day);
}

/**
 * @brief Calculate timestamp that is expired for SigV4
 *
 * Returns a timestamp that is outside the SigV4 15-minute
 * validity window.
 *
 * @param {number} [baseTime] Base time in ms
 *        (default: Date.now())
 * @param {boolean} [future] If true, return future expired
 *        time (default: false = past)
 *
 * @return {string} Expired ISO 8601 timestamp
 *
 * @example
 * var expired = expiredTimestamp();
 * // Returns timestamp >15 minutes in the past
 *
 * @since 1.0.0
 */
function expiredTimestamp(baseTime, future) {
    var base = baseTime || Date.now();
    var offset = 16 * 60 * 1000; /* 16 minutes in ms */

    if (future) {
        return (generateTimestamp(base + offset));
    } else {
        return (generateTimestamp(base - offset));
    }
}

/* --- Helper Functions --- */

/**
 * @brief Generate a random alphanumeric string
 *
 * Internal helper for generating random strings.
 *
 * @param {number} length Length of string to generate
 *
 * @return {string} Random alphanumeric string
 *
 * @since 1.0.0
 */
function _randomString(length) {
    var chars =
        'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz' +
        '0123456789';
    var result = '';
    for (var i = 0; i < length; i++) {
        var idx = Math.floor(Math.random() * chars.length);
        result += chars.charAt(idx);
    }
    return (result);
}

/**
 * @brief Pad a number to 2 digits
 *
 * Internal helper for zero-padding numbers.
 *
 * @param {number} num Number to pad
 *
 * @return {string} Zero-padded string
 *
 * @since 1.0.0
 */
function _pad(num) {
    return ((num < 10 ? '0' : '') + num);
}

/* --- Exports --- */

module.exports = {
    /* STS utilities */
    generateSTSToken: generateSTSToken,
    decodeSessionToken: decodeSessionToken,

    /* IAM policy builders */
    buildPolicy: buildPolicy,
    s3ReadOnlyPolicy: s3ReadOnlyPolicy,
    s3FullAccessPolicy: s3FullAccessPolicy,

    /* Request/response builders */
    buildRequest: buildRequest,
    buildResponse: buildResponse,

    /* Response validators */
    validateAuthResponse: validateAuthResponse,
    validateSTSResponse: validateSTSResponse,

    /* Time utilities */
    generateTimestamp: generateTimestamp,
    generateDateString: generateDateString,
    expiredTimestamp: expiredTimestamp
};
