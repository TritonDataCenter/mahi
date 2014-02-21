// Copyright (c) 2014, Joyent, Inc. All rights reserved.

var assert = require('assert-plus');
var common = require('./common.js');

var sprintf = require('util').format;

function add(opts, cb) {
    assert.object(opts, 'opts');
    assert.object(opts.entry, 'opts.entry');
    assert.object(opts.changes, 'opts.changes');
    assert.object(opts.log, 'opts.log');
    assert.object(opts.redis, 'opts.redis');
    assert.func(cb, 'callback');

    var changes = opts.changes;
    var entry = opts.entry;
    var log = opts.log;
    var redis = opts.redis;

    log.debug('sdckey.add: entered');

    var batch = redis.multi();
    var fingerprint = changes.fingerprint[0];
    var pkcs = changes.pkcs[0];
    var uuid = common.getDNValue(entry.targetdn, 1);
    var key = sprintf('/uuid/%s', uuid);

    redis.get(key, function (err, res) {
        if (err) {
            cb(err);
            return;
        }

        var payload = JSON.parse(res) || {};

        payload.keys = payload.keys || {};
        payload.keys[fingerprint] = pkcs;
        batch.set(key, JSON.stringify(payload));

        log.debug({batch: batch.queue}, 'sdckey.add: done');
        cb(null, batch);
    });
}


function del(opts, cb) {
    assert.object(opts, 'opts');
    assert.object(opts.entry, 'opts.entry');
    assert.object(opts.changes, 'opts.changes');
    assert.object(opts.log, 'opts.log');
    assert.object(opts.redis, 'opts.redis');
    assert.func(cb, 'callback');

    var changes = opts.changes;
    var entry = opts.entry;
    var log = opts.log;
    var redis = opts.redis;

    log.debug('sdckey.del: entered');

    var batch = redis.multi();
    var fingerprint = changes.fingerprint[0];
    var uuid = common.getDNValue(entry.targetdn, 1);
    var key = sprintf('/uuid/%s', uuid);

    redis.get(key, function (err, res) {
        if (err) {
            cb(err);
            return;
        }

        var payload = JSON.parse(res) || {};

        if (payload.keys) {
            delete payload.keys[fingerprint];
        }

        batch.set(key, JSON.stringify(payload));
        log.debug({batch: batch.queue}, 'sdckey.del: done');
        cb(null, batch);
    });
}


function modify(opts, cb) {
    assert.object(opts, 'opts');
    assert.object(opts.redis, 'opts.redis');
    assert.func(cb, 'callback');

    // Do nothing. The fingerprint can't be modified because the dn for sdckey
    // contains the key fingerprint. If the fingerprint can't be modified,
    // neither can the key. Those are the only two bits we care about.

    setImmediate(function () {
        cb(null, opts.redis.multi());
    });
}

module.exports = {
    add: add,
    delete: del,
    modify: modify
};
