/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2025 Edgecast Cloud LLC.
 */

/**
 * @file Secure session token management for STS operations
 *
 * Provides cryptographically signed JWTs for session tokens using
 * jsonwebtoken library compatible with Node.js v0.10.48.
 */

var jwt = require('jsonwebtoken');
var crypto = require('crypto');
var assert = require('assert-plus');

// Session token configuration constants
var DEFAULT_ALGORITHM = 'HS256';
var DEFAULT_ISSUER = 'manta-mahi';
var DEFAULT_AUDIENCE = 'manta-s3';
var DEFAULT_SESSION_DURATION = 3600; // 1 hour
var MAX_SESSION_DURATION = 43200;    // 12 hours
var DEFAULT_GRACE_PERIOD = 86400;    // 24 hours for secret rotation

/**
 * @brief Generate cryptographically signed session token with rotation support
 *
 * Creates a v1.1 JWT with HMAC-SHA256 signature and mandatory key ID
 * for rotation support. All tokens support rotation from the start.
 *
 * @param {Object} sessionData Session payload data
 * @param {string} sessionData.uuid User UUID who assumed the role
 * @param {string} sessionData.roleArn ARN of the assumed role
 * @param {string} sessionData.sessionName Role session name
 * @param {number} sessionData.expires Unix timestamp expiration
 * @param {Object} secretKey Secret object with key and keyId
 * @param {string} secretKey.key HMAC signing key
 * @param {string} secretKey.keyId Key identifier for rotation
 * @param {Object} options Optional JWT configuration
 * @param {string} options.issuer JWT issuer identifier
 * @param {string} options.audience JWT audience identifier
 *
 * @returns {string} Signed JWT v1.1 session token
 * @throws {Error} If required parameters missing or invalid
 *
 * @since 1.1.0
 */
function generateSessionToken(sessionData, secretKey, options) {
    assert.object(sessionData, 'sessionData');
    assert.string(sessionData.uuid, 'sessionData.uuid');
    assert.string(sessionData.roleArn, 'sessionData.roleArn');
    assert.string(sessionData.sessionName, 'sessionData.sessionName');
    assert.number(sessionData.expires, 'sessionData.expires');
    assert.object(secretKey, 'secretKey');
    assert.string(secretKey.key, 'secretKey.key');
    assert.string(secretKey.keyId, 'secretKey.keyId');

    options = options || {};

    // Validate session duration
    var now = Math.floor(Date.now() / 1000);
    var requestedDuration = sessionData.expires - now;

    if (requestedDuration <= 0) {
        throw new Error('Session expiration must be in the future');
    }

    if (requestedDuration > MAX_SESSION_DURATION) {
        throw new Error('Session duration exceeds maximum allowed (' +
                       MAX_SESSION_DURATION + ' seconds)');
    }

    // JWT payload with security metadata (v1.1 only)
    var payload = {
        // Core session data
        uuid: sessionData.uuid,
        roleArn: sessionData.roleArn,
        sessionName: sessionData.sessionName,

        // Security metadata
        tokenType: 'sts-session',
        tokenVersion: '1.1', // Always v1.1 with rotation support
        keyId: secretKey.keyId, // Key ID for rotation in payload

        // JWT standard claims
        iss: options.issuer || DEFAULT_ISSUER,
        aud: options.audience || DEFAULT_AUDIENCE,
        iat: now,
        exp: sessionData.expires,
        nbf: now  // Not before (prevents token use before issuance)
    };

    // JWT options (no custom header support in jsonwebtoken 1.1.0)
    var jwtOptions = {
        algorithm: DEFAULT_ALGORITHM
    };

    // Sign with HMAC-SHA256 using jsonwebtoken
    try {
        return (jwt.sign(payload, secretKey.key, jwtOptions));
    } catch (err) {
        throw new Error('Failed to generate session token: ' +
                       err.message);
    }
}

/**
 * @brief Verify and decode session token with rotation support
 *
 * Cryptographically verifies v1.1 JWT signature and validates all claims
 * including expiration, issuer, and audience. Uses multi-secret verification
 * for graceful rotation.
 *
 * @param {string} token JWT v1.1 session token to verify
 * @param {Object} secretConfig Multiple secrets configuration
 * @param {Object} secretConfig.secrets Object mapping key IDs to secret objects
 * @param {number} secretConfig.gracePeriod Grace period for old secrets
 * @param {Object} options Optional verification options
 * @param {string} options.issuer Expected JWT issuer
 * @param {string} options.audience Expected JWT audience
 * @param {Function} callback Optional callback function
 *
 * @returns {Object} Decoded and verified session data
 * @returns {string} returns.uuid User UUID
 * @returns {string} returns.roleArn Assumed role ARN
 * @returns {string} returns.sessionName Role session name
 * @returns {number} returns.expires Token expiration timestamp
 * @returns {number} returns.iat Token issued at timestamp
 *
 * @throws {Error} If token invalid, expired, or tampered
 *
 * @since 1.1.0
 */
function verifySessionToken(token, secretConfig, options, callback) {
    assert.string(token, 'token');
    assert.object(secretConfig, 'secretConfig');
    assert.object(secretConfig.secrets, 'secretConfig.secrets');

    // Handle optional callback (for async compatibility)
    if (typeof (options) === 'function' && !callback) {
        callback = options;
        options = {};
    }
    options = options || {};

    function handleResult(err, result) {
        if (callback) {
            if (err) {
                return (callback(
                    new Error('Session token verification failed: ' +
                              err.message)));
            }
            return (callback(null, result));
        } else {
            if (err) {
                throw new Error('Session token verification failed: ' +
                                err.message);
            }
            return (result);
        }
    }

    try {
        // Only multi-secret verification (rotation support)
        return verifyWithMultipleSecrets(token, secretConfig,
                                         options, handleResult);

    } catch (err) {
        return (handleResult(err));
    }
}

/**
 * @brief Verify token with multiple secrets (rotation support)
 *
 * Attempts to verify JWT token using rotation-aware secret management.
 * First tries to match token's key ID to a specific secret, then falls
 * back to trying all valid secrets during grace periods.
 *
 * @param {string} token JWT session token to verify
 * @param {Object} secretConfig Secret configuration object
 * @param {Object} secretConfig.secrets Map of key IDs to secret objects
 * @param {number} secretConfig.gracePeriod Grace period for old secrets in
 * seconds
 * @param {Object} options Verification options (issuer, audience, etc.)
 * @param {Function} callback Callback function(err, result)
 *
 * @private
 * @since 1.1.0
 */
function verifyWithMultipleSecrets(token, secretConfig, options, callback) {
    var secrets = secretConfig.secrets || {};

    // Try to decode payload to get key ID
    var payloadKeyId;
    try {
        var decoded = jwt.decode(token);
        payloadKeyId = decoded ? decoded.keyId : null;
    } catch (err) {
        // If decode fails, fall back to trying all secrets
        payloadKeyId = null;
    }

    // If we have a key ID from payload, try to find matching secret first
    if (payloadKeyId && secrets[payloadKeyId]) {
        jwt.verify(token, secrets[payloadKeyId].key, function (err, payload) {
            if (err) {
                // If specific key ID fails, try all valid secrets as fallback
                return (tryAllValidSecrets());
            } else {
                try {
                    var result = validateTokenPayload(payload, options);
                    return (callback(null, result));
                } catch (validateErr) {
                    return (tryAllValidSecrets());
                }
            }
        });
        return (undefined);
    }

    // Fallback: try all valid secrets
    function tryAllValidSecrets() {
        var validSecrets = getValidSecrets(secrets, secretConfig.gracePeriod);

        if (validSecrets.length === 0) {
            return (callback(new Error('No valid secrets available')));
        }

        var secretIndex = 0;
        var lastError;

        function tryNextSecret() {
            if (secretIndex >= validSecrets.length) {
                return callback(lastError ||
                                new Error('No valid signing key found'));
            }

            var secret = validSecrets[secretIndex];
            secretIndex++;

            return jwt.verify(token, secret.key, function (err, payload) {
                if (err) {
                    lastError = err;
                    return (tryNextSecret());
                }

                try {
                    var result = validateTokenPayload(payload, options);
                    return (callback(null, result));
                } catch (validateErr) {
                    lastError = validateErr;
                    return (tryNextSecret());
                }
            });
        }

        return (tryNextSecret());
    }

    // Start fallback
    return (tryAllValidSecrets());
}


/**
 * @brief Validate token payload claims
 *
 * Performs comprehensive validation of JWT payload including token type,
 * version compatibility, timing claims (exp, nbf, iat), and issuer/audience
 * verification if specified.
 *
 * @param {Object} payload Decoded JWT payload to validate
 * @param {string} payload.tokenType Expected to be 'sts-session'
 * @param {string} payload.tokenVersion Expected to be '1.1'
 * @param {number} payload.exp Token expiration timestamp
 * @param {number} payload.nbf Not-before timestamp
 * @param {string} payload.iss Token issuer
 * @param {string} payload.aud Token audience
 * @param {Object} options Validation options
 * @param {string} [options.issuer] Expected issuer (validates if provided)
 * @param {string} [options.audience] Expected audience (validates if provided)
 *
 * @returns {Object} Validated session data with normalized fields
 * @returns {string} returns.uuid User UUID
 * @returns {string} returns.roleArn Assumed role ARN
 * @returns {string} returns.sessionName Role session name
 * @returns {number} returns.expires Token expiration timestamp
 * @returns {number} returns.iat Token issued at timestamp
 * @returns {string} returns.tokenVersion Token version ('1.1')
 * @returns {string} returns.keyId Key ID used to sign token
 *
 * @throws {Error} If token type invalid, version unsupported, expired,
 *                 or claims invalid
 * @private
 * @since 1.1.0
 */
function validateTokenPayload(payload, options) {
    // Validate session-specific claims
    if (payload.tokenType !== 'sts-session') {
        throw new Error('Invalid token type: ' + payload.tokenType);
    }

    // Only accept v1.1 tokens with rotation support
    if (payload.tokenVersion !== '1.1') {
        throw new Error('Unsupported token version: ' +
                        payload.tokenVersion + ' (only v1.1 supported)');
    }

    // Validate timing claims (expiration always enforced)
    var now = Math.floor(Date.now() / 1000);

    if (payload.exp && payload.exp <= now) {
        throw new Error('Session token has expired');
    }

    if (payload.nbf && payload.nbf > now) {
        throw new Error('Session token not yet valid');
    }

    // Validate issuer if specified
    if (options.issuer && payload.iss !== options.issuer) {
        throw new Error('Invalid issuer: expected ' +
                       options.issuer + ', got ' + payload.iss);
    }

    // Validate audience if specified
    if (options.audience && payload.aud !== options.audience) {
        throw new Error('Invalid audience: expected ' +
                       options.audience + ', got ' + payload.aud);
    }

    // Return standardized session data
    return {
        uuid: payload.uuid,
        roleArn: payload.roleArn,
        sessionName: payload.sessionName,
        expires: payload.exp,
        iat: payload.iat,
        tokenVersion: payload.tokenVersion,
        keyId: payload.keyId  // Include key ID for rotation tracking
    };
}

/**
 * @brief Check if secret is still valid based on grace period
 *
 * Determines whether a secret can still be used for JWT verification
 * based on rotation timing and grace period policies. Primary secrets
 * are always valid, while old secrets expire after the grace period.
 *
 * @param {Object} secret Secret object to validate
 * @param {string} secret.key HMAC signing key
 * @param {string} secret.keyId Unique key identifier
 * @param {boolean} secret.isPrimary True if this is the current primary secret
 * @param {number} secret.addedAt Timestamp when secret was added/rotated
 * @param {number} [gracePeriod] Grace period in seconds
 * (defaults to DEFAULT_GRACE_PERIOD)
 *
 * @returns {boolean} True if secret is valid for use, false if expired
 * @private
 * @since 1.1.0
 */
function isSecretValid(secret, gracePeriod) {
    if (secret.isPrimary) {
        return (true);
    }

    var now = Date.now();
    var secretAge = now - (secret.addedAt || 0);
    var maxAge = (gracePeriod || DEFAULT_GRACE_PERIOD) * 1000;

    return (secretAge < maxAge);
}

/**
 * @brief Get all currently valid secrets
 *
 * Filters the secrets map to return only those secrets that are still
 * valid for JWT verification, based on grace period expiration rules.
 * Used during fallback verification when specific key ID lookup fails.
 *
 * @param {Object} secrets Map of key IDs to secret objects
 * @param {string} secrets[keyId].key HMAC signing key
 * @param {string} secrets[keyId].keyId Unique key identifier
 * @param {boolean} secrets[keyId].isPrimary True if primary secret
 * @param {number} secrets[keyId].addedAt Timestamp when secret was added
 * @param {number} [gracePeriod] Grace period in seconds for old secret validity
 *
 * @returns {Array<Object>} Array of valid secret objects
 * @returns {string} returns[].key HMAC signing key
 * @returns {string} returns[].keyId Unique key identifier
 * @returns {boolean} returns[].isPrimary True if primary secret
 * @returns {number} returns[].addedAt Timestamp when secret was added
 * @private
 * @since 1.1.0
 */
function getValidSecrets(secrets, gracePeriod) {
    var validSecrets = [];

    Object.keys(secrets).forEach(function (keyId) {
        var secret = secrets[keyId];
        if (isSecretValid(secret, gracePeriod)) {
            validSecrets.push(secret);
        }
    });

    return (validSecrets);
}

/**
 * @brief Generate versioned key ID for rotation
 *
 * @param {string} prefix Optional prefix (default: 'key')
 * @returns {string} Versioned key ID (e.g., 'key-20250120-a1b2c3d4')
 */
function generateKeyId(prefix) {
    prefix = prefix || 'key';
    var timestamp = new Date().toISOString().slice(0, 10).replace(/-/g, '');
    var random = crypto.randomBytes(4).toString('hex');
    return (prefix + '-' + timestamp + '-' + random);
}

/**
 * @brief Generate cryptographically secure session secret key
 *
 * Creates a random 256-bit key for HMAC-SHA256 operations.
 * Key should be stored securely and rotated regularly.
 *
 * @returns {string} Hex-encoded 256-bit secret key
 *
 * @since 1.0.0
 */
function generateSessionSecret() {
    return (crypto.randomBytes(32).toString('hex'));
}

/**
 * @brief Extract session token from Authorization header
 *
 * Parses AWS STS session token from various header formats.
 * Supports both X-Amz-Security-Token and Authorization schemes.
 *
 * @param {Object} headers HTTP request headers
 * @returns {string|null} Extracted session token or null if not found
 *
 * @since 1.0.0
 */
function extractSessionToken(headers) {
    assert.object(headers, 'headers');

    // Check X-Amz-Security-Token header (AWS standard)
    if (headers['x-amz-security-token']) {
        return (headers['x-amz-security-token']);
    }

    // Check Authorization header for session token
    var authHeader = headers.authorization || headers.Authorization;
    if (authHeader && authHeader.indexOf('SessionToken=') !== -1) {
        /*JSSTYLED*/
        var match = authHeader.match(/SessionToken=([^,\s]+)/);
        return (match ? match[1] : null);
    }

    return (null);
}

/**
 * @brief Decode token payload without verification (for debugging)
 *
 * Extracts token payload for inspection without signature verification.
 * Use only for debugging - never trust unverified token data.
 *
 * @param {string} token JWT session token
 * @returns {Object} Decoded payload (unverified)
 * @throws {Error} If token format invalid
 *
 * @since 1.0.0
 */
function decodeSessionToken(token) {
    assert.string(token, 'token');

    try {
        // Split JWT into parts (header.payload.signature)
        var parts = token.split('.');
        if (parts.length !== 3) {
            throw new Error('Invalid JWT format');
        }

        // Decode payload (base64url)
        var payloadB64 = parts[1];
        // Convert base64url to base64
        payloadB64 += '==='.slice(0, (4 - payloadB64.length % 4) % 4);
        payloadB64 = payloadB64.replace(/-/g, '+').replace(/_/g, '/');

        // Safe buffer creation for Node.js v0.10.48 compatibility
        if (payloadB64.length > 87380) { // Base64 encoding of 64KB
            throw new Error('Session token too large');
        }
        var payloadJson = new Buffer(payloadB64, 'base64').toString('utf8');
        return (JSON.parse(payloadJson));

    } catch (err) {
        throw new Error('Failed to decode token payload: ' + err.message);
    }
}

module.exports = {
    generateSessionToken: generateSessionToken,
    verifySessionToken: verifySessionToken,
    generateSessionSecret: generateSessionSecret,
    extractSessionToken: extractSessionToken,
    decodeSessionToken: decodeSessionToken,
    generateKeyId: generateKeyId,

    // Constants for external use
    DEFAULT_SESSION_DURATION: DEFAULT_SESSION_DURATION,
    MAX_SESSION_DURATION: MAX_SESSION_DURATION,
    DEFAULT_GRACE_PERIOD: DEFAULT_GRACE_PERIOD
};
