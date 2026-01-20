/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright 2026 Edgecast Cloud LLC.
 */

/*
 * test/00-crypto-setup.test.js: Enable crypto mock globally for all tests
 *
 * This test file runs first (alphabetically) and enables the crypto mock
 * at module load time, before any other test modules load their dependencies.
 * This prevents entropy pool exhaustion on Node.js v0.10.48 and fixes test
 * order dependency issues.
 *
 * Uses crypto.pseudoRandomBytes() which provides high-quality randomness
 * without depleting the entropy pool, so tests for randomness/uniqueness
 * still pass.
 */

var cryptoMock = require('./lib/crypto-mock');

// Enable crypto mock globally at module load time
// This happens before any other test modules load server/sts/ufds
cryptoMock.enable();

exports.testCryptoMockEnabled = function (t) {
    var crypto = require('crypto');

    // Verify the mock is active by generating some random bytes
    var buf = crypto.randomBytes(16);
    t.ok(buf, 'should generate random bytes');
    t.equal(buf.length, 16, 'should generate correct length');

    // Verify uniqueness (pseudoRandomBytes should provide good randomness)
    var buf2 = crypto.randomBytes(16);
    t.notDeepEqual(buf, buf2,
        'should generate different random bytes each time');

    t.done();
};
