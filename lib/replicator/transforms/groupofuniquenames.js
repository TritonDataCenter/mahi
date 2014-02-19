// Copyright (c) 2014, Joyent, Inc. All rights reserved.

var assert = require('assert-plus');
var common = require('./common.js');
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

    var batch = redis.multi();
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
            common.addToMapSet({
                key: '/uuid/' + account,
                set: 'groups',
                element: group,
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

    var batch = redis.multi();
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
            common.delFromMapSet({
                key: '/uuid/' + account,
                set: 'groups',
                element: group,
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

    var batch = redis.multi();
    // like cn=operators, ou=groups, o=smartdc
    var group = common.getDNValue(entry.targetdn, 0);

    vasync.forEachPipeline({
        func: function handleChange(change, pipelinecb) {
            if (change.modification.type === 'uniquemember') {
                vasync.forEachParallel({
                    func: function mod(accountdn, parallelcb) {
                        // like uuid=foo, ou=users, o=smartdc
                        var account = common.getDNValue(accountdn, 0);
                        if (change.operation === 'add') {
                            common.addToMapSet({
                                key: '/uuid/' + account,
                                set: 'groups',
                                element: group,
                                batch: batch,
                                log: log,
                                redis: redis
                            }, parallelcb);
                        } else if (change.operation === 'delete') {
                            common.delFromMapSet({
                                key: '/uuid/' + account,
                                set: 'groups',
                                element: group,
                                batch: batch,
                                log: log,
                                redis: redis
                            }, parallelcb);
                        } else {
                            log.warn({
                                operation: change.operation
                            }, 'groupofuniquenames.modify: ' +
                               'unhandled operation');

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
