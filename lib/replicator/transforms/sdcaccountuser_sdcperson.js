/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright (c) 2014, Joyent, Inc.
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

    log.debug('sdcaccountuser.add: entered');

    var batch = redis.multi();
    var uuid = changes.uuid[0];
    var account = changes.account[0];
    var login = changes.alias[0];

    var payload = {
        type: 'user',
        uuid: uuid,
        account: account,
        login: login
    };

    batch.set(sprintf('/uuid/%s', uuid), JSON.stringify(payload));
    batch.set(sprintf('/user/%s/%s', account, login), uuid);
    batch.sadd(sprintf('/set/users/%s', account), uuid);

    log.debug({batch: batch.queue}, 'sdcaccountuser.add: done');
    setImmediate(function () {
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

    log.debug('sdcaccountuser.del: entered');

    var batch = redis.multi();
    var uuid = changes.uuid[0];
    var login = changes.alias[0];
    var account = changes.account[0];

    batch.del(sprintf('/uuid/%s', uuid));
    batch.del(sprintf('/user/%s/%s', account, login));
    batch.srem(sprintf('/set/users/%s', account), uuid);

    log.debug({batch: batch.queue}, 'sdcaccountuser.del: done');
    setImmediate(function () {
        cb(null, batch);
    });
}


function modify(opts, cb) {
    assert.object(opts, 'opts');
    assert.object(opts.changes, 'opts.changes');
    assert.object(opts.log, 'opts.log');
    assert.object(opts.modEntry, 'opts.modEntry');
    assert.object(opts.redis, 'opts.redis');
    assert.func(cb, 'callback');

    var changes = opts.changes;
    var log = opts.log;
    var modEntry = opts.modEntry;
    var redis = opts.redis;

    log.debug('sdcaccountuser.modify: entered');

    var batch = redis.multi();
    var uuid = modEntry.uuid[0];
    var account = modEntry.account[0];
    var login = modEntry.alias[0];
    var key = sprintf('/uuid/%s', uuid);

    redis.get(key, function (err, res) {
        if (err) {
            cb(err);
            return;
        }

        var payload = JSON.parse(res);

        log.debug({
            payload: payload
        }, 'sdcaccountuser.modify: got redis payload');

        changes.forEach(function (change) {
            if (change.modification.type === 'login') {
                log.debug({
                    change: change
                }, 'sdcaccountuser.modify: login change');

                batch.del(sprintf('/user/%s/%s', account, payload.login));

                payload.login = login;
                batch.set(sprintf('/user/%s/%s', account, payload.login), uuid);
                batch.set(key, JSON.stringify(payload));
            } else {
                log.warn({type: change.modification.type},
                    'sdcaccountuser.modify: unhandled modification type');
            }
        });
        log.debug({batch: batch.queue}, 'sdcaccountuser.modify: done');
        cb(null, batch);
    });
}

module.exports = {
    add: add,
    delete: del,
    modify: modify
};
