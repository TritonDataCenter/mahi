#!/usr/bin/env node
/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2025 Edgecast Cloud LLC.
 */

//
// Generate SESSION_SECRET_KEY for mahi service setup
// This script generates a cryptographically secure 256-bit key
// for JWT session token signing/verification
//

var crypto = require('crypto');

/**
 * Generate cryptographically secure session secret key
 * Creates a random 256-bit key for HMAC-SHA256 operations  
 */
function generateSessionSecret() {
    return crypto.randomBytes(32).toString('hex');
}

// Generate and output the secret key
var secretKey = generateSessionSecret();
console.log(secretKey);