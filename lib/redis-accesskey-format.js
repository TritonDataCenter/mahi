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
 *
 * Scope values for permanent keys:
 *   null      — key is unscoped (unrestricted access)
 *   JSON str  — key is scoped (e.g. '{"version":1,...}')
 *   ""        — preserved as-is; downstream parseScope
 *               returns null, causing fail-closed deny
 *
 * Scope values for STS temporary credentials (in sts.js,
 * NOT built by this module):
 *   "none"    — parent key was explicitly unscoped
 *   JSON str  — inherited from scoped parent key
 *   null      — legacy pre-sentinel temp credential
 */


/**
 * @brief Build the accesskeys map entry for a permanent key
 *
 * Stored at /uuid/{ownerUuid}.accesskeys[accessKeyId].
 *
 * @param {string} secret - Secret access key
 * @param {string|null} scope - Scope JSON string or null
 * @param {number} [version] - Write version (changenumber or
 *   0 for unversioned).  Used by the replicator and cachePush
 *   to prevent stale writes from overwriting newer data.
 * @return {Object} { secret, scope, version }
 */
function buildPermanentKeyEntry(secret, scope, version) {
    return ({
        secret: secret,
        scope: (scope != null) ? scope : null,
        version: (version != null) ? version : 0
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
 * @param {number} [version] - Write version (see
 *   buildPermanentKeyEntry)
 * @return {Object} Reverse-lookup entry
 */
function buildPermanentKeyLookup(accessKeyId, userUuid, scope, version) {
    return ({
        type: 'accesskey',
        accessKeyId: accessKeyId,
        userUuid: userUuid,
        credentialType: 'permanent',
        scope: (scope != null) ? scope : null,
        version: (version != null) ? version : 0
    });
}


/*
 * Revocation tombstone constants and helpers.
 *
 * When an operator calls POST /scope-revoke/:accesskeyid,
 * a tombstone key is written to Redis with a TTL.  The
 * replicator checks for the tombstone before writing a key
 * to Redis — if present, the write is skipped, making the
 * revocation durable across replication cycles.
 *
 * The tombstone auto-expires after REVOKE_TTL_SECONDS.
 * The operator should delete the key from UFDS (via CloudAPI)
 * before the tombstone expires to make revocation permanent.
 * Repeated scope-revoke calls renew the tombstone TTL.
 */
var REVOKE_TTL_SECONDS = 86400; // 24 hours


/**
 * @brief Build the Redis key path for a revocation tombstone
 *
 * @param {string} accesskeyid - Access key ID
 * @return {string} Redis key path
 */
function revokedKeyPath(accesskeyid) {
    return ('/revoked/' + accesskeyid);
}


/**
 * @brief Build the revocation tombstone value
 *
 * @param {string} userUuid - Owner UUID of the revoked key
 * @return {Object} Tombstone data
 */
function buildRevocationTombstone(userUuid) {
    return ({
        revokedAt: Date.now(),
        userUuid: userUuid
    });
}


module.exports = {
    buildPermanentKeyEntry: buildPermanentKeyEntry,
    buildPermanentKeyLookup: buildPermanentKeyLookup,
    REVOKE_TTL_SECONDS: REVOKE_TTL_SECONDS,
    revokedKeyPath: revokedKeyPath,
    buildRevocationTombstone: buildRevocationTombstone
};
