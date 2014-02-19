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

    log.debug({entry: opts.entry}, 'sdcaccountgroup.add: entered');

    var batch = redis.multi();
    var account = changes.account[0];
    var name = changes.cn[0];
    var uuid = changes.uuid[0];
    var memberpolicy;
    if (changes.memberpolicy) {
        memberpolicy = changes.memberpolicy.map(function (r) {
            return (common.getDNValue(r, 0));
        });
    }

    var payload = {
        type: 'group',
        uuid: uuid,
        name: name,
        account: account,
        roles: memberpolicy
    };

    batch.set(sprintf('/uuid/%s', uuid), JSON.stringify(payload));
    batch.set(sprintf('/group/%s/%s', account, name), uuid);
    batch.sadd(sprintf('/set/groups/%s', account), uuid);

    if (changes.uniquemember) {
        vasync.forEachParallel({
            func: function add(userdn, parallelcb) {
                // like uuid=foo, uuid=bar, ou=users, o=smartdc
                var user = common.getDNValue(userdn, 0);
                common.addToSet({
                    key: '/uuid/' + user,
                    set: 'groups',
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
                }, 'sdcaccountgroup.add error');

                cb(err);
                return;
            }

            log.debug({batch: batch.queue}, 'sdcaccountgroup.add: done');
            cb(null, batch);
        });
    } else {
        log.debug({
            group: uuid,
            name: name
        }, 'sdcaccountgroup.add: no users to add');
        log.debug({batch: batch.queue}, 'sdcaccountgroup.add: done');
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

    log.debug('sdcaccountgroup.del: entered');

    var batch = redis.multi();
    var uuid = changes.uuid[0];
    var name = changes.cn[0];
    var account = changes.account[0];

    batch.del('/uuid/' + uuid);
    batch.del(sprintf('/group/%s/%s', account, name));
    batch.srem('/set/groups/' + account, uuid);

    if (changes.uniquemember) {
        vasync.forEachParallel({
            func: function del(userdn, parallelcb) {
                // like uuid=foo, uuid=bar, ou=users, o=smartdc
                var user = common.getDNValue(userdn, 0);
                common.delFromSet({
                    key: '/uuid/' + user,
                    set: 'groups',
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
                }, 'sdcaccountgroup.del error');

                cb(err);
                return;
            }

            log.debug({batch: batch.queue}, 'sdcaccountgroup.del: done');
            cb(null, batch);
        });
    } else {
        log.debug({
            group: uuid,
            name: name
        }, 'sdcaccountgroup.del: no users to delete');
        log.debug({batch: batch.queue}, 'sdcaccountgroup.del: done');
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

    log.debug('sdcaccountgroup.modify: entered');

    var batch = redis.multi();
    var uuid = modEntry.uuid[0];

    vasync.forEachPipeline({
        func: function handleChange(change, pipelinecb) {
            if (change.modification.type === 'cn') {
                common.rename({
                    name: change.modification.vals[0],
                    type: 'group',
                    uuid: uuid,
                    batch: batch,
                    log: log,
                    redis: redis
                }, pipelinecb);
            } else if (change.modification.type === 'memberrole') {
                var roles = change.modification.vals.map(function (r) {
                    return (common.getDNValue(r, 0));
                }).sort();
                if (change.operation === 'add') {
                    common.setUnion({
                        key: '/uuid/' + uuid,
                        set: 'roles',
                        elements: roles,
                        batch: batch,
                        log: log,
                        redis: redis
                    }, pipelinecb);
                } else if (change.operation === 'delete') {
                    common.setDifference({
                        key: '/uuid/' + uuid,
                        set: 'roles',
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
                                key: '/uuid/' + user,
                                set: 'groups',
                                element: uuid,
                                batch: batch,
                                log: log,
                                redis: redis
                            }, parallelcb);
                        } else if (change.operation === 'delete') {
                            common.delFromSet({
                                key: '/uuid/' + user,
                                set: 'groups',
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
