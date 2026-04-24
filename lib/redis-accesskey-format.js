/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2026 Edgecast Cloud LLC.
 */

/*
 * Canonical Redis entry builders for permanent access keys.
 *
 * Two code paths write permanent key data to Redis:
 *   1. Replicator transforms (UFDS → Redis sync)
 *   2. cachePush endpoint (CloudAPI → Redis shortcut)
 *
 * Both must produce identical structures.  This module
 * is the single source of truth for the Redis format
 * so the invariant is enforced by construction, not by
 * convention.
 *
 * Permanent key format (in /uuid/{uuid}.accesskeys):
 *   { secret: string, scope: string|null }
 *
 * Reverse lookup format (in /accesskey/{keyId}):
 *   { type: "accesskey", accessKeyId, userUuid,
 *     credentialType: "permanent", scope: string|null }
 */


/**
 * @brief Build the accesskeys map entry for a permanent key
 *
 * Stored at /uuid/{ownerUuid}.accesskeys[accessKeyId].
 *
 * @param {string} secret - Secret access key
 * @param {string|null} scope - Scope JSON string or null
 * @return {Object} { secret, scope }
 */
function buildPermanentKeyEntry(secret, scope) {
    return ({
        secret: secret,
        scope: scope || null
    });
}


/**
 * @brief Build the reverse-lookup entry for a permanent key
 *
 * Stored at /accesskey/{accessKeyId}.
 *
 * @param {string} accessKeyId - Access key ID
 * @param {string} userUuid - Owner UUID
 * @param {string|null} scope - Scope JSON string or null
 * @return {Object} Reverse-lookup entry
 */
function buildPermanentKeyLookup(accessKeyId, userUuid, scope) {
    return ({
        type: 'accesskey',
        accessKeyId: accessKeyId,
        userUuid: userUuid,
        credentialType: 'permanent',
        scope: scope || null
    });
}


module.exports = {
    buildPermanentKeyEntry: buildPermanentKeyEntry,
    buildPermanentKeyLookup: buildPermanentKeyLookup
};
