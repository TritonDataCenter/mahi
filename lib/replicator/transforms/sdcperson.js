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

    log.debug('sdcperson.add: entered');

    var batch = redis.multi();
    var uuid = changes.uuid[0];
    var login = changes.login[0];
    var approved = changes.approved_for_provisioning &&
        changes.approved_for_provisioning[0] &&
        changes.approved_for_provisioning[0] === 'true'; // booleans from ldap
                                                         // are serialized as
                                                         // strings
    var tcns = changes.triton_cns_enabled &&
        changes.triton_cns_enabled[0] &&
        changes.triton_cns_enabled[0] === 'true';

    var payload = {
        type: 'account',
        uuid: uuid,
        login: login,
        groups: [],
        approved_for_provisioning: approved,
        triton_cns_enabled: tcns
    };

    batch.set(sprintf('/uuid/%s', uuid), JSON.stringify(payload));
    batch.set(sprintf('/account/%s', login), uuid);
    batch.sadd('/set/accounts', uuid);

    log.debug({batch: batch.queue}, 'sdcperson.add: done');
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

    log.debug('sdcperson.del: entered');

    var batch = redis.multi();
    var uuid = changes.uuid[0];
    var login = changes.login[0];

    batch.del('/uuid/' + uuid);
    batch.del('/account/' + login);
    batch.srem('/set/accounts', uuid);
    batch.del('/set/users/' + uuid);
    batch.del('/set/policies/' + uuid);
    batch.del('/set/roles/' + uuid);

    log.debug({batch: batch.queue}, 'sdcperson.del: done');
    setImmediate(function () {
        cb(null, batch);
    });
}


function modify(opts, cb) {
    assert.object(opts, 'opts');
    assert.object(opts.changes, 'opts.changes');
    assert.object(opts.modEntry, 'opts.modEntry');
    assert.object(opts.log, 'opts.log');
    assert.object(opts.redis, 'opts.redis');
    assert.func(cb, 'callback');

    var changes = opts.changes;
    var log = opts.log;
    var redis = opts.redis;

    log.debug('sdcperson.modify: entered');

    var batch = redis.multi();
    var uuid = opts.modEntry.uuid[0];
    var key = sprintf('/uuid/%s', uuid);

    redis.get(key, function (err, res) {
        if (err) {
            cb(err);
            return;
        }

        var payload = JSON.parse(res);

        log.debug({payload: payload}, 'sdcperson.modify: got redis payload');

        changes.forEach(function (change) {
            var type = change.modification.type;
            if (type === 'approved_for_provisioning' ||
                type === 'triton_cns_enabled') {

                log.debug({
                    change: change
                }, 'sdcperson.modify: %s', type);

                if (change.operation === 'delete') {
                    payload[type] = false;
                } else if (change.operation === 'replace' ||
                    change.operation === 'add') {

                    payload[type] = (change.modification.vals[0] === 'true');
                }

                log.debug({
                    payload: payload
                }, 'sdcperson.modify: setting redis payload');

                batch.set(key, JSON.stringify(payload));
            } else if (type === 'login') {
                log.debug({
                    change: change
                }, 'sdcperson.modify: login');

                batch.del('/account/' + payload.login);

                payload.login = change.modification.vals[0];
                batch.set('/account/' + payload.login, uuid);

                log.debug({
                    payload: payload
                }, 'sdcperson.modify: setting redis payload');

                batch.set(key, JSON.stringify(payload));
            } else {
                log.warn({type: type},
                    'sdcperson.modify: unhandled modification type');
            }
        });

        log.debug({batch: batch.queue}, 'sdcperson.modify: done');
        setImmediate(function () {
            cb(null, batch);
        });
    });
}

module.exports = {
    add: add,
    delete: del,
    modify: modify
};
