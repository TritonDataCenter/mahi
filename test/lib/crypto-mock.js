/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright 2026 Edgecast Cloud LLC.
 */

/*
 * test/lib/crypto-mock.js: Mock crypto.randomBytes for testing
 *
 * Provides a fast pseudo-random replacement for crypto.randomBytes() to avoid
 * entropy pool exhaustion when running many tests on Node.js v0.10.48.
 *
 * Uses crypto.pseudoRandomBytes() which provides high-quality randomness
 * without depleting the kernel entropy pool.
 */

var crypto = require('crypto');

var originalRandomBytes = crypto.randomBytes;
var mockEnabled = false;

/**
 * Mock implementation of crypto.randomBytes using pseudoRandomBytes
 * Signature matches Node.js crypto.randomBytes
 *
 * @param {Number} size - Number of bytes to generate
 * @param {Function} callback - Optional callback(err, buffer)
 * @returns {Buffer} Buffer with pseudo-random bytes (if no callback)
 */
function mockRandomBytes(size, callback) {
    // Use pseudoRandomBytes which doesn't deplete entropy pool
    // but still provides good randomness for testing
    if (typeof (callback) === 'function') {
        return (crypto.pseudoRandomBytes(size, callback));
    } else {
        return (crypto.pseudoRandomBytes(size));
    }
}

/**
 * Replace crypto.randomBytes with pseudoRandomBytes implementation
 * Call this in test setUp to avoid entropy pool exhaustion
 */
function enableMockCrypto() {
    if (mockEnabled) {
        return;
    }

    crypto.randomBytes = mockRandomBytes;
    mockEnabled = true;
}

// Auto-enable crypto mock when this module loads
// This ensures the mock is active before any test modules load
// crypto-dependent code
enableMockCrypto();

/**
 * Restore original crypto.randomBytes implementation
 * Call this in test tearDown to clean up
 */
function disableMockCrypto() {
    if (!mockEnabled) {
        return;
    }

    crypto.randomBytes = originalRandomBytes;
    mockEnabled = false;
}

module.exports = {
    enable: enableMockCrypto,
    disable: disableMockCrypto
};
