// Copyright (c) 2014, Joyent, Inc. All rights reserved.

var assert = require('assert-plus');
var common = require('./common.js');
var errors = require('../errors.js');
var multi = require('../MultiCache.js');
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

    var batch = multi.multi(redis);
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

    batch.set(sprintf('/uuid/%s', uuid), JSON.stringify(payload));
    batch.set(sprintf('/role/%s/%s', account, name), uuid);
    batch.sadd(sprintf('/set/roles/%s', account), uuid);

    if (changes.uniquemember) {
        vasync.forEachParallel({
            func: function addMember(userdn, parallelcb) {
                // like uuid=foo, uuid=bar, ou=users, o=smartdc
                var user = common.getDNValue(userdn, 0);
                common.addToGroup({
                    member: user,
                    group: uuid,
                    type: 'roles',
                    batch: batch,
                    log: log,
                    redis: redis
                }, parallelcb);
            },
            inputs: changes.uniquemember
        }, function memberEnd(err, res) {
            if (err) {
                log.error({
                    err: err,
                    res: res
                }, 'sdcaccountrole.add error');

                cb(err);
                return;
            }
            if (changes.uniquememberdefault) {
                vasync.forEachParallel({
                    func: function addDefault(userdn, parallelcb) {
                        // like uuid=foo, uuid=bar, ou=users, o=smartdc
                        var user = common.getDNValue(userdn, 0);
                        common.addToGroup({
                            member: user,
                            group: uuid,
                            type: 'defaultRoles',
                            batch: batch,
                            log: log
                        }, parallelcb);
                    },
                    inputs: changes.uniquememberdefault
                }, function defaultEnd(err, res) {
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
                    return;
                });
            } else {
                log.debug({batch: batch.queue}, 'sdcaccountrole.add: done');
                cb(null, batch);
                return;
            }
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

    var batch = multi.multi(redis);
    var uuid = changes.uuid[0];
    var name = changes.name[0];
    var account = changes.account[0];

    batch.del('/uuid/' + uuid);
    batch.del(sprintf('/role/%s/%s', account, name));
    batch.srem('/set/roles/' + account, uuid);

    if (changes.uniquemember) {
        vasync.forEachParallel({
            func: function delMember(userdn, parallelcb) {
                // like uuid=foo, uuid=bar, ou=users, o=smartdc
                var user = common.getDNValue(userdn, 0);
                common.delFromGroup({
                    member: user,
                    group: uuid,
                    type: 'roles',
                    batch: batch,
                    log: log
                }, parallelcb);
            },
            inputs: changes.uniquemember
        }, function memberEnd(err, res) {
            if (err) {
                log.error({
                    err: err,
                    res: res
                }, 'sdcaccountrole.del error');

                cb(err);
                return;
            }
            if (changes.uniquememberdefault) {
                vasync.forEachParallel({
                    func: function delDefault(userdn, parallelcb) {
                        // like uuid=foo, uuid=bar, ou=users, o=smartdc
                        var user = common.getDNValue(userdn, 0);
                        common.delFromGroup({
                            member: user,
                            group: uuid,
                            type: 'defaultRoles',
                            batch: batch,
                            log: log
                        }, parallelcb);
                    },
                    inputs: changes.uniquememberdefault
                }, function defaultEnd(err, res) {
                    if (err) {
                        log.error({
                            err: err,
                            res: res
                        }, 'sdcaccountrole.del error');

                        cb(err);
                        return;
                    }
                    batch.del('/uuid/%s/%s', uuid, 'defaultRoles');
                    log.debug({batch: batch.queue}, 'sdcaccountrole.del: done');
                    cb(null, batch);
                    return;
                });
            } else {
                batch.del('/uuid/%s/%s', uuid, 'roles');
                log.debug({batch: batch.queue}, 'sdcaccountrole.del: done');
                cb(null, batch);
                return;
            }
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

    var batch = multi.multi(redis);
    var uuid = modEntry.uuid[0];

    vasync.forEachPipeline({
        func: function handleChange(change, pipelinecb) {
            var roles;
            var args;
            var users;
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
                roles = change.modification.vals.map(function (r) {
                    return (common.getDNValue(r, 0));
                }).sort();

                args = {
                    members: roles,
                    group: uuid,
                    type: 'policies',
                    batch: batch,
                    log: log,
                    redis: redis
                };

                if (change.operation === 'add') {
                    common.setUnion(args, pipelinecb);
                } else if (change.operation === 'delete') {
                    common.setDifference(args, pipelinecb);
                } else if (change.operation === 'replace') {
                    common.setValue({
                        key: '/uuid/' + uuid,
                        property: 'policies',
                        value: roles,
                        batch: batch,
                        log: log,
                        redis: redis
                    }, pipelinecb);
                } else {
                    pipelinecb(new errors.UnsupportedOperationError(
                        change.operation,
                        change.modification.type));
                }
            } else if (change.modification.type === 'uniquemember') {
                users = change.modification.vals.map(function (dn) {
                    return (common.getDNValue(dn, 0));
                });
                if (change.operation === 'add') {
                    vasync.forEachParallel({
                        func: function addMember(user, parallelcb) {
                            common.addToGroup({
                                member: user,
                                group: uuid,
                                type: 'roles',
                                batch: batch,
                                log: log
                            }, parallelcb);
                        },
                        inputs: users
                    }, pipelinecb);
                } else if (change.operation === 'delete') {
                    vasync.forEachParallel({
                        func: function delMember(user, parallelcb) {
                            common.delFromGroup({
                                member: user,
                                group: uuid,
                                type: 'roles',
                                batch: batch,
                                log: log
                            }, parallelcb);
                        },
                        inputs: users
                    }, pipelinecb);
                } else if (change.operation === 'replace') {
                    common.replaceGroup({
                        members: users,
                        group: uuid,
                        type: 'roles',
                        batch: batch,
                        log: log
                    }, pipelinecb);
                } else {
                    pipelinecb(new errors.UnsupportedOperationError(
                        change.operation,
                        change.modification.type));
                }
            } else if (change.modification.type === 'uniquememberdefault') {
                users = change.modification.vals.map(function (dn) {
                    return (common.getDNValue(dn, 0));
                });
                if (change.operation === 'add') {
                    vasync.forEachParallel({
                        func: function addDefault(user, parallelcb) {
                            common.addToGroup({
                                member: user,
                                group: uuid,
                                type: 'defaultRoles',
                                batch: batch,
                                log: log
                            }, parallelcb);
                        },
                        inputs: users
                    }, pipelinecb);
                } else if (change.operation === 'delete') {
                    vasync.forEachParallel({
                        func: function delDefault(user, parallelcb) {
                            common.delFromGroup({
                                member: user,
                                group: uuid,
                                type: 'defaultRoles',
                                batch: batch,
                                log: log
                            }, parallelcb);
                        },
                        inputs: users
                    }, pipelinecb);
                } else if (change.operation === 'replace') {
                    common.replaceGroup({
                        members: users,
                        group: uuid,
                        type: 'defaultRoles',
                        batch: batch,
                        log: log
                    }, pipelinecb);
                } else {
                    pipelinecb(new errors.UnsupportedOperationError(
                        change.operation,
                        change.modification.type));
                }
            } else {
                log.warn({
                    type: change.modification.type
                }, 'sdcaccountrole.modify: unhandled modification type');
                pipelinecb();
            }
        },
        inputs: changes
    }, function pipelineEnd(err, res) {
        if (err) {
            log.error({err: err, res: res}, 'sdcaccountrole.modify error');
            cb(err);
            return;
        }
        log.debug({batch: batch.queue}, 'sdcaccountrole.modify: done');
        cb(null, batch);
    });
}

module.exports = {
    add: add,
    delete: del,
    modify: modify
};
