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

    log.debug('sdcaccountpolicy.add: entered');

    var batch = redis.multi();
    var account = changes.account[0];
    var name = changes.name[0];
    var uuid = changes.uuid[0];
    var rules;
    if (changes.rule) {
        rules = changes.rule.map(function (r) {
            return ([r, parser.parse(r)]);
        });
    }

    var payload = {
        type: 'policy',
        uuid: uuid,
        name: name,
        rules: rules,
        account: account
    };

    batch.set(sprintf('/uuidv2/%s', uuid), JSON.stringify(payload));
    batch.set(sprintf('/policy/%s/%s', account, name), uuid);
    batch.sadd(sprintf('/set/policies/%s', account), uuid);

    if (changes.memberrole) {
        vasync.forEachParallel({
            func: function addRole(roledn, parallelcb) {
                // like group-uuid=foo, uuid=bar, ou=users, o=smartdc
                var role = common.getDNValue(roledn, 0);
                common.addToSet({
                    key: sprintf('/uuidv2/%s', role),
                    set: 'policies',
                    element: uuid,
                    batch: batch,
                    log: log,
                    redis: redis
                }, parallelcb);
            },
            inputs: changes.memberrole
        }, function parallelEndRole(err, res) {
            if (err) {
                log.error({
                    err: err,
                    res: res
                }, 'sdcaccountpolicy.add error');

                cb(err);
                return;
            }

            cb(null, batch);
        });
    } else {
        log.debug({
            policy: uuid,
            name: name
        }, 'sdaccountpolicy.add: no memberroles in policy');
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
    var name = changes.name[0];
    var uuid = changes.uuid[0];

    batch.del(sprintf('/uuidv2/%s', uuid));
    batch.del(sprintf('/policy/%s/%s', account, name));
    batch.srem(sprintf('/set/policies/%s', account), uuid);

    if (changes.memberrole) {
        vasync.forEachParallel({
            func: function delRole(roledn, parallelcb) {
                // like group-uuid=foo, uuid=bar, ou=smartdc, o=smartdc
                var role = common.getDNValue(roledn, 0);
                common.delFromSet({
                    key: sprintf('/uuidv2/%s', role),
                    set: 'policies',
                    element: uuid,
                    batch: batch,
                    log: log,
                    redis: redis
                }, parallelcb);
            },
            inputs: changes.memberrole
        }, function parallelEndRole(err, res) {
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
            var rules;
            if (change.modification.type === 'name') {
                common.rename({
                    name: change.modification.vals[0],
                    type: 'policy',
                    uuid: uuid,
                    batch: batch,
                    log: log,
                    redis: redis
                }, pipelinecb);
            } else if (change.modification.type === 'rule') {
                rules = change.modification.vals.map(function (r) {
                    return ([r, parser.parse(r)]);
                });
                if (change.operation === 'add') {
                    common.setUnion({
                        key: sprintf('/uuidv2/%s', uuid),
                        set: 'rules',
                        elements: rules,
                        batch: batch,
                        log: log,
                        redis: redis
                    }, pipelinecb);
                } else if (change.operation === 'delete') {
                    common.setDifference({
                        key: sprintf('/uuidv2/%s', uuid),
                        set: 'rules',
                        elements: rules,
                        batch: batch,
                        log: log,
                        redis: redis
                    }, pipelinecb);
                } else if (change.operation === 'replace') {
                    common.setValue({
                        key: sprintf('/uuidv2/%s', uuid),
                        property: 'rules',
                        value: rules,
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
            } else if (change.modification.type === 'memberrole') {
                vasync.forEachParallel({
                    func: function modRole(roledn, parallelcb) {
                        // like group-uuid=foo, uuid=bar, ou=users, o=smartdc
                        var role = common.getDNValue(roledn, 0);
                        if (change.operation === 'add') {
                            common.addToSet({
                                key: sprintf('/uuidv2/%s', role),
                                set: 'policies',
                                element: uuid,
                                batch: batch,
                                log: log,
                                redis: redis
                            }, parallelcb);
                        } else if (change.operation === 'delete') {
                            common.delFromSet({
                                key: sprintf('/uuidv2/%s', role),
                                set: 'policies',
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
