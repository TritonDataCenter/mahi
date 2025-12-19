/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2025 Edgecast Cloud LLC.
 */

var assert = require('assert-plus');
var sprintf = require('util').format;

function add(opts, cb) {
    assert.object(opts, 'opts');
    assert.object(opts.changes, 'opts.changes');
    assert.object(opts.log, 'opts.log');
    assert.object(opts.redis, 'opts.redis');
    assert.func(cb, 'callback');

    var changes = opts.changes;
    var log = opts.log;
    var redis = opts.redis;

    log.debug('accesskey.add: entered');

    if (!changes._owner) {
        cb(new Error('_owner is required'));
        return;
    }

    var batch = redis.multi();

    // If accesskey's status is absent or not "Active", don't add it.
    if (!changes.status ||
        !changes.status.length ||
        changes.status[0] !== 'Active') {
        log.debug({ accesskeyid: changes.accesskeyid[0] },
            'Skipping non-Active accesskey');
        cb(null, batch);
        return;
    }

    var accesskeyid = changes.accesskeyid[0];
    var accesskeysecret = changes.accesskeysecret[0];
    var uuid = Array.isArray(changes._owner) ?
        changes._owner[0] : changes._owner;
    var key = sprintf('/uuid/%s', uuid);

    /**
     * @brief Extract STS-related fields for temporary credentials
     *
     * Handles both permanent and temporary access key replication
     * with enhanced metadata for STS-issued credentials including
     * expiration, session tokens, and role assumption data.
     *
     * @note Temporary credentials include additional metadata:
     *   - credentialtype: 'temporary' vs 'permanent'
     *   - expiration: ISO timestamp for credential expiry
     *   - sessiontoken: Associated session token
     *   - principaluuid: Original user who assumed role
     *   - assumedrole: ARN of assumed role
     *
     * @since 1.0.0
     */
    var credentialType = changes.credentialtype ? changes.credentialtype[0] :
        'permanent';
    var expiration = changes.expiration ? changes.expiration[0] : null;
    var sessionToken = changes.sessiontoken ? changes.sessiontoken[0] : null;
    var principalUuid = changes.principaluuid ? changes.principaluuid[0] : null;
    var assumedRole = changes.assumedrole ? changes.assumedrole[0] : null;

    // Skip expired temporary credentials during replication
    if (credentialType === 'temporary' && expiration) {
        var now = new Date();
        var expiryDate = new Date(expiration);
        if (now > expiryDate) {
            log.debug({
                accesskeyid: accesskeyid,
                expiration: expiration
            }, 'Skipping expired temporary credential during replication');
            cb(null, batch);
            return;
        }
    }

    redis.get(key, function (err, res) {
        if (err) {
            cb(err);
            return;
        }

        var payload = res ? JSON.parse(res) : {};
        payload.accesskeys = payload.accesskeys || {};

        // Store enhanced credential data for temporary credentials
        if (credentialType === 'temporary') {
            payload.accesskeys[accesskeyid] = {
                secret: accesskeysecret,
                type: credentialType,
                expiration: expiration,
                sessionToken: sessionToken,
                principalUuid: principalUuid,
                assumedRole: assumedRole
            };
        } else {
            // Keep legacy format for permanent credentials
            payload.accesskeys[accesskeyid] = accesskeysecret;
        }

        batch.set(key, JSON.stringify(payload));

        // Add reverse lookup: access key ID ->
        // user UUID or full credential data
        var accessKeyLookupKey = sprintf('/accesskey/%s', accesskeyid);
        if (credentialType === 'temporary') {
            // Store full credential data for temporary
            // credentials for STS
            var credentialData = {
                type: 'accesskey',
                accessKeyId: accesskeyid,
                secretAccessKey: accesskeysecret,
                sessionToken: sessionToken,
                userUuid: uuid,
                expiration: expiration,
                credentialType: 'temporary',
                created: Date.now().toString(),
                principalUuid: principalUuid
            };

            // Add assumedRole data if available
            if (assumedRole) {
                credentialData.assumedRole = assumedRole;
            }

            var credentialJson = JSON.stringify(credentialData);
            batch.set(accessKeyLookupKey, credentialJson);

            log.debug({
                accesskeyid: accesskeyid,
                credentialType: credentialType,
                hasAssumedRole: !!assumedRole
            }, 'Storing full credential data for temporary credential');
        } else {
            // For permanent credentials, store just the UUID (legacy behavior)
            batch.set(accessKeyLookupKey, uuid);
        }
        log.debug({batch: batch.queue}, 'accesskey.add: done');
        cb(null, batch);
    });
}


function del(opts, cb) {
    assert.object(opts, 'opts');
    assert.object(opts.changes, 'opts.changes');
    assert.object(opts.log, 'opts.log');
    assert.object(opts.redis, 'opts.redis');
    assert.func(cb, 'callback');

    var changes = opts.changes;
    var log = opts.log;
    var redis = opts.redis;

    log.debug('accesskeys.del: entered');

    if (!changes._owner) {
        cb(new Error('_owner is required'));
        return;
    }

    var batch = redis.multi();
    var accesskeyid = changes.accesskeyid[0];
    var uuid = Array.isArray(changes._owner) ?
        changes._owner[0] : changes._owner;
    var key = sprintf('/uuid/%s', uuid);

    redis.get(key, function (err, res) {
        if (err) {
            cb(err);
            return;
        }

        var payload = res ? JSON.parse(res) : {};
        if (payload.accesskeys && accesskeyid) {
            delete payload.accesskeys[accesskeyid];
        }
        batch.set(key, JSON.stringify(payload));

        // Remove reverse lookup
        var accessKeyLookupKey = sprintf('/accesskey/%s', accesskeyid);
        batch.del(accessKeyLookupKey);

        log.debug({batch: batch.queue}, 'accesskeys.del: done');
        cb(null, batch);
    });
}

function modify(opts, cb) {
    assert.object(opts, 'opts');
    assert.object(opts.redis, 'opts.redis');
    assert.func(cb, 'callback');

    var log = opts.log;
    var redis = opts.redis;
    var changes = opts.changes;
    var modEntry = opts.modEntry;
    var status = null;
    var batch = redis.multi();

    log.debug('accesskey.modify: entered');

    /*
     * When the status changes we'll encounter a structure such as this:
     *
     * [
     *   {
     *      'operation': 'replace',
     *      'modification': {
     *         'type': 'status',
     *         'vals': [
     *           'Inactive'
     *         ]
     *       }
     *   },
     *   ...
     * ];
     *
     */

    /*
     * Temporary keys are not allowed to be modified
     */
    var credentialType = modEntry.credentialtype ? modEntry.credentialtype[0] :
        'permanent';
    if (credentialType === 'temporary') {
        log.debug({change: modEntry},
                  'Modifying a temporary key is a NOP');
        cb(null, batch);
        return;
    }

    for (var i = changes.length - 1; i >= 0; i -= 1) {
        if (changes[i].operation === 'replace' &&
            changes[i].modification.type === 'status') {
            status = changes[i].modification.vals[i];
        }
    }

    // Mahi only needs to perform an update if status changes
    if (!status) {
        log.debug({ changes: changes },
            'Skipping non-status related change to accesskey');
        cb(null, batch);
        return;
    }

    var accesskeyid = modEntry.accesskeyid[0];
    var accesskeysecret = modEntry.accesskeysecret[0];
    var uuid = Array.isArray(modEntry._owner) ?
        modEntry._owner[0] : modEntry._owner;
    var key = sprintf('/uuid/%s', uuid);

    if (!modEntry._owner) {
        cb(new Error('_owner is required'));
        return;
    }

    redis.get(key, function _redisGet(err, res) {
        if (err) {
            cb(err);
            return;
        }

        var payload = res ? JSON.parse(res) : {};

        // If status is Active, add the key
        if (status === 'Active') {
            payload.accesskeys = payload.accesskeys || {};
            payload.accesskeys[accesskeyid] = accesskeysecret;
            batch.set(key, JSON.stringify(payload));

            // Add reverse lookup: access key ID -> user UUID
            var activeLookup = sprintf('/accesskey/%s', accesskeyid);
            batch.set(activeLookup, uuid);
            log.debug({batch: batch.queue}, 'accesskeys.modify: done');
            cb(null, batch);
            return;
        }

        // If status is not Active, remove the key
        if (payload.accesskeys && accesskeyid) {
            delete payload.accesskeys[accesskeyid];
            batch.set(key, JSON.stringify(payload));

            // Remove reverse lookup
            var inactiveLookup = sprintf('/accesskey/%s', accesskeyid);
            batch.del(inactiveLookup);
            log.debug({batch: batch.queue}, 'accesskeys.modify: done');
            cb(null, batch);
            return;
        }

        log.debug({batch: batch.queue}, 'accesskeys.modify: done');
        cb(null, batch);
        return;
    });
}

module.exports = {
    add: add,
    delete: del,
    modify: modify
};
