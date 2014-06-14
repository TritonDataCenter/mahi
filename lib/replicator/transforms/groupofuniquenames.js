// Copyright (c) 2014, Joyent, Inc. All rights reserved.

var assert = require('assert-plus');
var common = require('./common.js');
var errors = require('../errors.js');
var multi = require('../MultiCache.js');
var vasync = require('vasync');

function add(opts, cb) {
    assert.object(opts, 'opts');
    assert.object(opts.changes, 'opts.changes');
    assert.object(opts.entry, 'opts.entry');
    assert.object(opts.log, 'opts.log');
    assert.object(opts.redis, 'opts.redis');
    assert.func(cb, 'callback');

    var changes = opts.changes;
    var entry = opts.entry;
    var log = opts.log;
    var redis = opts.redis;

    log.debug({entry: opts.entry}, 'groupofuniquenames.add: entered');

    var batch = multi.multi(redis);
    // like cn=operators, ou=groups, o=smartdc
    var group = common.getDNValue(entry.targetdn, 0);

    if (!changes.uniquemember) {
        log.debug('groupofuniquenames.add: no uniquemembers in group');
        log.debug('groupofuniquenames.add: done');
        setImmediate(function () {
            cb(null, batch);
        });
        return;
    }

    vasync.forEachParallel({
        func: function add(accountdn, parallelcb) {
            // like uuid=foo, ou=users, o=smartdc
            var account = common.getDNValue(accountdn, 0);
            common.addToGroup({
                member: account,
                group: group,
                type: 'groups',
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
            }, 'groupofuniquenames.add error');

            cb(err);
            return;
        }

        log.debug({batch: batch.queue}, 'groupofuniquenames.add: done');
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

    log.debug({entry: opts.entry}, 'groupofuniquenames.del: entered');

    var batch = multi.multi(redis);
    // like cn=operators, ou=groups, o=smartdc
    var group = common.getDNValue(entry.targetdn, 0);

    if (!changes.uniquemember) {
        log.debug('groupofuniquenames.del: no uniquemembers in group');
        log.debug({batch: batch.queue}, 'groupofuniquenames.del: done');
        setImmediate(function () {
            cb(null, batch);
        });
        return;
    }

    vasync.forEachParallel({
        func: function del(accountdn, parallelcb) {
            // like uuid=foo, ou=users, o=smartdc
            var account = common.getDNValue(accountdn, 0);
            common.delFromGroup({
                member: account,
                group: group,
                type: 'groups',
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
            }, 'groupofuniquenames.del error');

            cb(err);
            return;
        }

        log.debug({batch: batch.queue}, 'groupofuniquenames.del: done');
        cb(null, batch);
    });
}

function modify(opts, cb) {
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

    log.debug('groupofuniquenames.modify: entered');

    var batch = multi.multi(redis);
    // like cn=operators, ou=groups, o=smartdc
    var group = common.getDNValue(entry.targetdn, 0);

    vasync.forEachPipeline({
        func: function handleChange(change, pipelinecb) {
            var uuids;
            if (change.modification.type === 'uniquemember') {
                uuids = change.modification.vals.map(function (dn) {
                    return (common.getDNValue(dn, 0));
                });
                if (change.operation === 'add') {
                    vasync.forEachParallel({
                        func: function add(account, parallelcb) {
                            common.addToGroup({
                                member: account,
                                group: group,
                                type: 'groups',
                                batch: batch,
                                log: log,
                                redis: redis
                            }, parallelcb);
                        },
                        inputs: uuids
                    }, pipelinecb);
                } else if (change.operation === 'delete') {
                    vasync.forEachParallel({
                        func: function del(account, parallelcb) {
                            common.delFromGroup({
                                member: account,
                                group: group,
                                type: 'groups',
                                batch: batch,
                                log: log,
                                redis: redis
                            }, parallelcb);
                        },
                        inputs: uuids
                    }, pipelinecb);
                } else if (change.operation === 'replace') {
                    common.replaceGroup({
                        members: uuids,
                        group: group,
                        type: 'groups',
                        batch: batch,
                        log: log,
                        redis: redis
                    }, pipelinecb);
                } else {
                    pipelinecb(new errors.UnsupportedOperationError(
                        change.operation,
                        change.modification.type));
                }
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
            log.error({
                err: err,
                res: res
            }, 'groupofuniquenames.modify error');
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
