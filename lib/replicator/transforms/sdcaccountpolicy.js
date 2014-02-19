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
    assert.object(opts.parser, 'opts.parser');
    assert.func(cb, 'callback');

    var changes = opts.changes;
    var log = opts.log;
    var parser = opts.parser;
    var redis = opts.redis;

    log.debug('putRole: entered');

    var batch = redis.multi();
    var account = changes.account[0];
    var name = changes.name[0];
    var uuid = changes.uuid[0];
    var policies;
    if (changes.policydocument) {
        policies = changes.policydocument.map(function (p) {
            return ([p, parser.parse(p)]);
        });
    }

    var payload = {
        type: 'role',
        uuid: uuid,
        name: name,
        policies: policies,
        account: account
    };

    batch.set(sprintf('/uuid/%s', uuid), JSON.stringify(payload));
    batch.set(sprintf('/role/%s/%s', account, name), uuid);
    batch.sadd(sprintf('/set/roles/%s', account), uuid);

    if (changes.membergroup) {
        vasync.forEachParallel({
            func: function addGroup(groupdn, parallelcb) {
                // like group-uuid=foo, uuid=bar, ou=users, o=smartdc
                var group = common.getDNValue(groupdn, 0);
                common.addToSet({
                    key: sprintf('/uuid/%s', group),
                    set: 'roles',
                    element: uuid,
                    batch: batch,
                    log: log,
                    redis: redis
                }, parallelcb);
            },
            inputs: changes.membergroup
        }, function parallelEndGroup(err, res) {
            if (err) {
                log.error({
                    err: err,
                    res: res
                }, 'putRole error');

                cb(err);
                return;
            }

            cb(null, batch);
        });
    } else {
        log.debug({
            role: uuid,
            name: name
        }, 'putRole: no membergroups in role');
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

    log.debug('sdcaccountpolicy.del: entered');

    var batch = redis.multi();
    var account = changes.account;
    var name = changes.name;
    var uuid = changes.uuid;

    batch.del(sprintf('/uuid/%s', uuid));
    batch.del(sprintf('/role/%s/%s', account, name));
    batch.srem(sprintf('/set/roles/%s', account), uuid);

    if (changes.membergroup) {
        vasync.forEachParallel({
            func: function delGroup(groupdn, parallelcb) {
                // like group-uuid=foo, uuid=bar, ou=smartdc, o=smartdc
                var group = common.getDNValue(groupdn, 0);
                common.delFromSet({
                    key: sprintf('/uuid/%s', group),
                    set: 'roles',
                    element: uuid,
                    batch: batch,
                    log: log,
                    redis: redis
                }, parallelcb);
            },
            inputs: changes.membergroup
        }, function parallelEndGroup(err, res) {
            if (err) {
                log.error({
                    err: err,
                    res: res
                }, 'sdcaccountpolicy.del error');
                cb(err);
                return;
            }

            cb(null, batch);
        });
    } else {
        log.debug('sdcaccountpolicy.del: policy is not a member of any roles');
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
    assert.object(opts.parser, 'opts.parser');
    assert.object(opts.redis, 'opts.redis');
    assert.func(cb, 'callback');

    var changes = opts.changes;
    var log = opts.log;
    var modEntry = opts.modEntry;
    var parser = opts.parser;
    var redis = opts.redis;

    log.debug('sdcaccountpolicy.modify: entered');

    var batch = redis.multi();
    var uuid = modEntry.uuid[0];

    vasync.forEachPipeline({
        func: function handleChange(change, pipelinecb) {
            var policies;
            if (change.modification.type === 'name') {
                common.rename({
                    name: change.modification.vals[0],
                    type: 'role',
                    uuid: uuid,
                    batch: batch,
                    log: log,
                    redis: redis
                }, pipelinecb);
            } else if (change.modification.type === 'policydocument') {
                policies = change.modification.vals.map(function (p) {
                    return ([p, parser.parse(p)]);
                });
                if (change.operation === 'add') {
                    common.setUnion({
                        key: sprintf('/uuid/%s', uuid),
                        set: 'policies',
                        elements: policies,
                        batch: batch,
                        log: log,
                        redis: redis
                    }, pipelinecb);
                } else if (change.operation === 'delete') {
                    common.setDifference({
                        key: sprintf('/uuid/%s', uuid),
                        set: 'policies',
                        elements: policies,
                        batch: batch,
                        log: log,
                        redis: redis
                    }, pipelinecb);
                } else if (change.operation === 'modify') {
                    common.setValue({
                        key: sprintf('/uuid/%s', uuid),
                        property: 'policies',
                        value: policies,
                        batch: batch,
                        log: log,
                        redis: redis
                    }, pipelinecb);
                } else {
                    log.warn({
                        operation: change.operation
                    }, 'sdcaccountpolicy.modify: unhandled operation for ' +
                       'type %s', change.modification.type);

                    pipelinecb();
                }
            } else if (change.modification.type === 'membergroup') {
                vasync.forEachParallel({
                    func: function modGroup(groupdn, parallelcb) {
                        // like group-uuid=foo, uuid=bar, ou=users, o=smartdc
                        var group = common.getDNValue(groupdn, 0);
                        if (change.operation === 'add') {
                            common.addToSet({
                                key: sprintf('/uuid/%s', group),
                                set: 'roles',
                                element: uuid,
                                batch: batch,
                                log: log,
                                redis: redis
                            }, parallelcb);
                        } else if (change.operation === 'delete') {
                            common.delFromSet({
                                key: sprintf('/uuid/%s', group),
                                set: 'roles',
                                element: uuid,
                                batch: batch,
                                log: log,
                                redis: redis
                            }, parallelcb);
                        } else {
                            log.warn({
                                operation: change.operation
                            }, 'sdcaccountpolicy.modify: unhandled operation ' +
                               'for type %s', change.modification.type);

                            parallelcb();
                        }
                    },
                    inputs: change.modification.vals
                }, pipelinecb);
            } else {
                log.warn({
                    type: change.modification.type
                }, 'sdcaccountpolicy.modify: unhandled modification type');
                pipelinecb();
            }
        },
        inputs: changes
    }, function pipelineEnd(err, res) {
        if (err) {
            log.error({err: err, res: res}, 'sdcaccountpolicy.modify error');
            cb(err);
            return;
        }
        log.debug({batch: batch.queue}, 'sdcaccountpolicy.modify: done');
        cb(null, batch);
    });
}

module.exports = {
    add: add,
    delete: del,
    modify: modify
};
