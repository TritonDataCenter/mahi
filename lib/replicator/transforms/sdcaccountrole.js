// Copyright (c) 2014, Joyent, Inc. All rights reserved.

var assert = require('assert-plus');
var common = require('./common.js');
var vasync = require('vasync');

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

    log.debug({entry: opts.entry}, 'sdcaccountrole.add: entered');

    var batch = redis.multi();
    var account = changes.account[0];
    var name = changes.name[0];
    var uuid = changes.uuid[0];
    var memberpolicy;
    if (changes.memberpolicy) {
        memberpolicy = changes.memberpolicy.map(function (r) {
            return (common.getDNValue(r, 0));
        });
    }

    var payload = {
        type: 'role',
        uuid: uuid,
        name: name,
        account: account,
        policies: memberpolicy
    };

    batch.set(sprintf('/uuidv2/%s', uuid), JSON.stringify(payload));
    batch.set(sprintf('/role/%s/%s', account, name), uuid);
    batch.sadd(sprintf('/set/roles/%s', account), uuid);

    if (changes.uniquemember) {
        vasync.forEachParallel({
            func: function add(userdn, parallelcb) {
                // like uuid=foo, uuid=bar, ou=users, o=smartdc
                var user = common.getDNValue(userdn, 0);
                common.addToSet({
                    key: '/uuidv2/' + user,
                    set: 'roles',
                    element: uuid,
                    batch: batch,
                    log: log,
                    redis: redis
                }, parallelcb);
            },
            inputs: changes.uniquemember
        }, function parallelEnd(err, res) {
            if (err) {
                log.error({
                    err: err,
                    res: res
                }, 'sdcaccountrole.add error');

                cb(err);
                return;
            }

            log.debug({batch: batch.queue}, 'sdcaccountrole.add: done');
            cb(null, batch);
        });
    } else {
        log.debug({
            role: uuid,
            name: name
        }, 'sdcaccountrole.add: no users to add');
        log.debug({batch: batch.queue}, 'sdcaccountrole.add: done');
        setImmediate(function () {
            cb(null, batch);
        });
    }
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

    log.debug('sdcaccountrole.del: entered');

    var batch = redis.multi();
    var uuid = changes.uuid[0];
    var name = changes.name[0];
    var account = changes.account[0];

    batch.del('/uuidv2/' + uuid);
    batch.del(sprintf('/role/%s/%s', account, name));
    batch.srem('/set/roles/' + account, uuid);

    if (changes.uniquemember) {
        vasync.forEachParallel({
            func: function del(userdn, parallelcb) {
                // like uuid=foo, uuid=bar, ou=users, o=smartdc
                var user = common.getDNValue(userdn, 0);
                common.delFromSet({
                    key: '/uuidv2/' + user,
                    set: 'roles',
                    element: uuid,
                    batch: batch,
                    log: log,
                    redis: redis
                }, parallelcb);
            },
            inputs: changes.uniquemember
        }, function parallelEnd(err, res) {
            if (err) {
                log.error({
                    err: err,
                    res: res
                }, 'sdcaccountrole.del error');

                cb(err);
                return;
            }

            log.debug({batch: batch.queue}, 'sdcaccountrole.del: done');
            cb(null, batch);
        });
    } else {
        log.debug({
            role: uuid,
            name: name
        }, 'sdcaccountrole.del: no users to delete');
        log.debug({batch: batch.queue}, 'sdcaccountrole.del: done');
        setImmediate(function () {
            cb(null, batch);
        });
    }
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

    log.debug('sdcaccountrole.modify: entered');

    var batch = redis.multi();
    var uuid = modEntry.uuid[0];

    vasync.forEachPipeline({
        func: function handleChange(change, pipelinecb) {
            if (change.modification.type === 'cn') {
                common.rename({
                    name: change.modification.vals[0],
                    type: 'role',
                    uuid: uuid,
                    batch: batch,
                    log: log,
                    redis: redis
                }, pipelinecb);
            } else if (change.modification.type === 'memberpolicy') {
                var roles = change.modification.vals.map(function (r) {
                    return (common.getDNValue(r, 0));
                }).sort();
                if (change.operation === 'add') {
                    common.setUnion({
                        key: '/uuidv2/' + uuid,
                        set: 'policies',
                        elements: roles,
                        batch: batch,
                        log: log,
                        redis: redis
                    }, pipelinecb);
                } else if (change.operation === 'delete') {
                    common.setDifference({
                        key: '/uuidv2/' + uuid,
                        set: 'policies',
                        elements: roles,
                        batch: batch,
                        log: log,
                        redis: redis
                    }, pipelinecb);
                } else {
                    log.warn({
                        operation: change.operation
                    }, 'groupofuniquenames.modify: unsupported opration type');
                    pipelinecb();
                }
            } else if (change.modification.type === 'uniquemember') {
                vasync.forEachParallel({
                    func: function modUser(userdn, parallelcb) {
                        var user = common.getDNValue(userdn, 0);
                        if (change.operation === 'add') {
                            common.addToSet({
                                key: '/uuidv2/' + user,
                                set: 'roles',
                                element: uuid,
                                batch: batch,
                                log: log,
                                redis: redis
                            }, parallelcb);
                        } else if (change.operation === 'delete') {
                            common.delFromSet({
                                key: '/uuidv2/' + user,
                                set: 'roles',
                                element: uuid,
                                batch: batch,
                                log: log,
                                redis: redis
                            }, parallelcb);
                        } else {
                            log.warn({
                                operation: change.operation
                            }, 'groupofuniquenames.modify: ' +
                               'unsupported operation type');

                            parallelcb();
                        }
                    },
                    inputs: change.modification.vals
                }, pipelinecb);
            } else {
                log.warn({
                    type: change.modification.type
                }, 'groupofuniquenames.modify: unhandled modification type');
                pipelinecb();
            }
        },
        inputs: changes
    }, function pipelineEnd(err, res) {
        if (err) {
            log.error({err: err, res: res}, 'groupofuniquenames.modify error');
            cb(err);
            return;
        }
        log.debug({batch: batch.queue}, 'groupofuniquenames.modify: done');
        cb(null, batch);
    });
}

module.exports = {
    add: add,
    delete: del,
    modify: modify
};
