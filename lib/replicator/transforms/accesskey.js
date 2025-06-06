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
    var accesskeyid = changes.accesskeyid[0];
    var accesskeysecret = changes.accesskeysecret[0];
    var uuid = Array.isArray(changes._owner) ?
        changes._owner[0] : changes._owner;
    var key = sprintf('/uuid/%s', uuid);

    redis.get(key, function (err, res) {
        if (err) {
            cb(err);
            return;
        }

        var payload = res ? JSON.parse(res) : {};
        payload.accesskeys = payload.accesskeys || {};
        payload.accesskeys[accesskeyid] = accesskeysecret;
        batch.set(key, JSON.stringify(payload));
        // Add reverse lookup: access key ID -> user UUID
        var accessKeyLookupKey = sprintf('/accesskey/%s', accesskeyid);
        batch.set(accessKeyLookupKey, uuid);
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

// Modifying an access key is a NOP, we create new ones
// or just delete the existing ones, through cloudapi endpoint:
// /<userid>/accesskey/<accesskey id that you want to delete>
    setImmediate(function () {
        cb(null, opts.redis.multi());
    });
}

module.exports = {
    add: add,
    delete: del,
    modify: modify
};
