/*
 * Copyright (c) 2013, Joyent, Inc. All rights reserved.
 *
 * Transformations for each type of ufds changelog entry that we care to cache.
 * Transforms ldapjs JSON changelog entries into key/value pairs in redis.
 *
 */
var assert = require('assert-plus');
var sprintf = require('util').format;
var vasync = require('vasync');

module.exports = {
    Transformer: Transformer,
    getDNValue: getDNValue
};


// -- Helpers

function getDNValue(dn, index) {
    assert.string(dn, 'dn');
    assert.number(index, 'index');

    var part = dn.split(',')[index];
    return (part.substring(part.indexOf('=') + 1));
}



// -- Transformer

function Transformer(opts) {
    assert.object(opts, 'opts');
    assert.object(opts.redis, 'opts.redis');
    assert.object(opts.log, 'opts.log');

    var self = this;
    self.redis = opts.redis;
    self.log = opts.log;
}

/*
 * Adds commands to a transaction that, when executed, will make changes in
 * redis that reflect the changelog entry from ufds.
 *
 * batch: a redis transaction object (redis.multi())
 * entry: a ldapjs changelog entry
 * changes: the parsed version of the `changes` string property of the
 *      changelog entry.
 */
Transformer.prototype.transform = function (opts, cb) {
    assert.object(opts, 'opts');
    assert.object(opts.batch, 'opts.batch');
    assert.object(opts.changes, 'opts.changes');
    assert.object(opts.entry, 'opts.entry');
    assert.func(cb, 'callback');

    var self = this;

    var batch = opts.batch;
    var changes = opts.changes;
    var entry = opts.entry;
    var changetype = entry.changetype;
    var modEntry;
    var objectclass;

    // entry.entry only appears on 'modify' changes and contains the
    // complete new entry (instead of just the changes)
    if (changetype === 'modify') {
        modEntry = JSON.parse(entry.entry);
        // XXX objectclass can have multiple elements, which indicates multiple
        // inheritance. This shows up for a user under an account, which has
        // objectclasses sdcperson and sdcaccountuser.
        // A cleaner approach might involve transforming the entry as an
        // sdcperson and as an sdcaccountuser separately, instead of handling
        // "sdcaccountuser sdcperson" as a separate case as is done here.
        objectclass = modEntry.objectclass.sort().join(' ');
    } else {
        objectclass = changes.objectclass.sort().join(' ');
    }

    var args = {
        batch: batch,
        entry: entry,
        modEntry: modEntry,
        changes: changes
    };

    switch (objectclass) {
    case 'groupofuniquenames':
        switch (changetype) {
        case 'add':
            self.putGroup(args, cb);
            break;
        case 'delete':
            self.delGroup(args, cb);
            break;
        case 'modify':
            self.modGroup(args, cb);
            break;
        default:
            cb(new Error('unrecognized changetype: ' + changetype));
            break;
        }
        break;
    case 'sdcaccountgroup':
        switch (changetype) {
        case 'add':
            self.putAccountGroup(args, cb);
            break;
        case 'delete':
            self.delAccountGroup(args, cb);
            break;
        case 'modify':
            self.modAccountGroup(args, cb);
            break;
        default:
            cb(new Error('unrecognized changetype: ' + changetype));
            break;
        }
        break;
    case 'sdcaccountrole':
        switch (changetype) {
        case 'add':
            self.putRole(args, cb);
            break;
        case 'delete':
            self.delRole(args, cb);
            break;
        case 'modify':
            self.modRole(args, cb);
            break;
        default:
            cb(new Error('unrecognized changetype: ' + changetype));
            break;
        }
        break;
    case 'sdcaccountuser sdcperson':
        switch (changetype) {
        case 'add':
            self.putUser(args, cb);
            break;
        case 'delete':
            self.delUser(args, cb);
            break;
        case 'modify':
            self.modUser(args, cb);
            break;
        default:
            cb(new Error('unrecognized changetype: ' + changetype));
            break;
        }
        break;
    case 'sdckey':
        switch (changetype) {
        case 'add':
            self.addKey(args, cb);
            break;
        case 'delete':
            self.delKey(args, cb);
            break;
        case 'modify':
            // Do nothing. The fingerprint can't be modified because the dn for
            // sdckey contains the key fingerprint. If the fingerprint can't be
            // modified, neither can the key. Those are the only two bits we
            // care about.
            cb(null, batch);
            break;
        default:
            cb(new Error('unrecognized changetype: ' + changetype));
            break;
        }
        break;
    case 'sdcperson':
        switch (changetype) {
        case 'add':
            self.putAccount(args, cb);
            break;
        case 'delete':
            self.delAccount(args, cb);
            break;
        case 'modify':
            self.modAccount(args, cb);
            break;
        default:
            cb(new Error('unrecognized changetype: ' + changetype));
            break;
        }
        break;
    default:
        self.log.warn({objectclass: objectclass}, 'unhandled objectclass');
        cb(null, batch);
        break;
    }
};



// -- groupofuniquenames

/*
 * {
 *   "targetdn": "cn=operators, ou=groups, o=smartdc",
 *   "changes": {
 *     "objectclass": [
 *       "groupofuniquenames"
 *     ],
 *     "uniquemember": [
 *       "uuid=930896af-bf8c-48d4-885c-6573a94b1853, ou=users, o=smartdc"
 *     ],
 *     "_parent": [
 *       "ou=groups, o=smartdc"
 *     ]
 *   }
 * }
 */
Transformer.prototype.putGroup = function (opts, cb) {
    assert.object(opts, 'opts');
    assert.object(opts.batch, 'opts.batch');
    assert.object(opts.entry, 'opts.entry');
    assert.object(opts.changes, 'opts.changes');
    assert.func(cb, 'callback');

    var self = this;

    self.log.info('putGroup: entered');

    var changes = opts.changes;
    var entry = opts.entry;
    // like cn=operators, ou=groups, o=smartdc
    var group = getDNValue(entry.targetdn, 0);
    var batch = opts.batch;
    if (!changes.uniquemember) {
        self.log.info('putGroup: no uniquemembers in group');
        self.log.info('putGroup: done');
        cb(null, batch);
        return;
    }

    vasync.forEachParallel({
        func: function add(accountdn, parallelcb) {
            // like uuid=foo, ou=users, o=smartdc
            var uuid = getDNValue(accountdn, 0);
            self.addGroupMember(uuid, group, batch, parallelcb);
        },
        inputs: changes.uniquemember
    }, function parallelEnd(err, res) {
        if (err) {
            self.log.error({
                err: err,
                res: res
            }, 'putGroup error');

            cb(err);
            return;
        }

        self.log.info('putGroup: done');
        cb(null, batch);
    });
};


Transformer.prototype.delGroup = function (opts, cb) {
    assert.object(opts, 'opts');
    assert.object(opts.batch, 'opts.batch');
    assert.object(opts.entry, 'opts.entry');
    assert.object(opts.changes, 'opts.changes');
    assert.func(cb, 'callback');

    var self = this;

    self.log.info('delGroup: entered');

    var changes = opts.changes;
    var entry = opts.entry;
    // like cn=operators, ou=groups, o=smartdc
    var group = getDNValue(entry.targetdn, 0);
    var batch = opts.batch;
    if (!changes.uniquemember) {
        self.log.info('delGroup: no uniquemembers in group');
        self.log.info({batch: batch.queue}, 'delGroup: done');
        cb(null, batch);
        return;
    }

    vasync.forEachParallel({
        func: function del(accountdn, parallelcb) {
            // like uuid=foo, ou=users, o=smartdc
            var uuid = getDNValue(accountdn, 0);
            self.delGroupMember(uuid, group, batch, parallelcb);
        },
        inputs: changes.uniquemember
    }, function parallelEnd(err, res) {
        if (err) {
            self.log.error({
                err: err,
                res: res
            }, 'delGroup error');

            cb(err);
            return;
        }

        self.log.info('delGroup: done');
        cb(null, batch);
    });
};


/*
 * {
 *   "dn": "changenumber=15, cn=changelog",
 *   "controls": [],
 *   "targetdn": "cn=operators, ou=groups, o=smartdc",
 *   "changetype": "modify",
 *   "objectclass": "changeLogEntry",
 *   "changetime": "2013-12-03T19:29:21.734Z",
 *   "changes": [
 *     {
 *       "operation": "add",
 *       "modification": {
 *         "type": "uniquemember",
 *         "vals": [
 *           "uuid=930896af-bf8c-48d4-885c-6573a94b1853, ou=users, o=smartdc"
 *         ]
 *       }
 *     }
 *   ],
 *   "entry": JSON.stringified entry
 *   "changenumber": "15"
 * }
 */
Transformer.prototype.modGroup = function (opts, cb) {
    assert.object(opts, 'opts');
    assert.object(opts.batch, 'opts.batch');
    assert.object(opts.entry, 'opts.entry');
    assert.object(opts.changes, 'opts.changes');
    assert.func(cb, 'callback');

    var self = this;

    self.log.info('modGroup: entered');

    var entry = opts.entry;
    var changes = opts.changes;
    // like cn=operators, ou=groups, o=smartdc
    var group = getDNValue(entry.targetdn, 0);
    var batch = opts.batch;

    vasync.forEachPipeline({
        func: function handleChange(change, pipelinecb) {
            if (change.modification.type === 'uniquemember') {
                vasync.forEachParallel({
                    func: function mod(accountdn, parallelcb) {
                        // like uuid=foo, ou=users, o=smartdc
                        var uuid = getDNValue(accountdn, 0);
                        if (change.operation === 'add') {
                            self.addGroupMember(uuid, group, batch, parallelcb);
                        } else if (change.operation === 'delete') {
                            self.delGroupMember(uuid, group, batch, parallelcb);
                        } else {
                            self.log.warn({
                                operation: change.operation
                            }, 'modGroup: unhandled operation');
                            parallelcb();
                        }
                    },
                    inputs: change.modification.vals
                }, pipelinecb);
            } else {
                self.log.warn({
                    type: change.modification.type
                }, 'modGroup: unhandled modification type');
                pipelinecb();
            }
        },
        inputs: changes
    }, function pipelineEnd(err, res) {
        if (err) {
            self.log.error({err: err, res: res}, 'modGroup error');
            cb(err);
            return;
        }
        self.log.info('modGroup: done');
        cb(null, batch);
    });
};


/*
 * account: account uuid
 * group: name of group
 * batch: redis multi. **modified as a side effect**
 * cb: callback function
 */
Transformer.prototype.addGroupMember = function (account, group, batch, cb) {
    assert.uuid(account, 'account');
    assert.string(group, 'group');
    assert.object(batch, 'batch');
    assert.func(cb, 'callback');

    var self = this;

    self.log.info({account: account, group: group}, 'addGroupMember: entered');

    var key = '/uuid/' + account;
    self.redis.get(key, function gotAccount(err, res) {
        if (err) {
            self.log.error({
                err: err,
                res: res
            }, 'addGroupMember error');

            cb(err);
            return;
        }

        var payload = JSON.parse(res) || {}; // If the account doesn't exist,
                                             // redis returns an empty response.
        self.log.info({payload: payload}, 'addGroupMember: got redis payload');
        payload.groups = payload.groups || {};
        payload.groups[group] = true;
        batch.set(key, JSON.stringify(payload));
        self.log.info({batch: batch.queue}, 'addGroupMember: done');
        cb(null, batch);
    });
};


/*
 * account: account uuid
 * group: name of group
 * batch: redis multi. **modified as a side effect**
 * cb: callback function
 */
Transformer.prototype.delGroupMember = function (account, group, batch, cb) {
    assert.uuid(account, 'account');
    assert.string(group, 'group');
    assert.object(batch, 'batch');
    assert.func(cb, 'callback');

    var self = this;

    self.log.info({account: account, group: group}, 'delGroupMember: entered');

    var key = '/uuid/' + account;
    self.redis.get(key, function gotAccount(err, res) {
        if (err) {
            self.log.error({
                err: err,
                res: res
            }, 'delGroupMember error');

            cb(err);
            return;
        }

        var payload = JSON.parse(res);
        if (!payload) {
            self.log.info('delGroupMember: Account does not exist. ' +
                'Nothing to do.');
            self.log.info('delGroupMember: done');
            cb(null, batch);
            return;
        }

        self.log.info({payload: payload}, 'delGroupMember: got redis payload');

        // XXX If the account wasn't in the group originally we don't take any
        // special action (the effect is the same - the account won't be part of
        // the group). However, it does indicate that we missed an earlier
        // change where the account was added to the group.
        payload.groups = payload.groups || {};
        delete payload.groups[group];
        batch.set(key, JSON.stringify(payload));
        self.log.info({batch: batch.queue}, 'delGroupMember: done');
        cb(null, batch);
    });
};




// -- sdcaccountgroup

Transformer.prototype.putAccountGroup = function (opts, cb) {
    assert.object(opts, 'opts');
    assert.object(opts.batch, 'opts.batch');
    assert.object(opts.changes, 'opts.changes');
    assert.func(cb, 'callback');

    var self = this;

    self.log.info('putAccountGroup: entered');

    var batch = opts.batch;
    var changes = opts.changes;
    var uuid = changes.uuid[0];
    var name = changes.cn[0];
    var account = changes.account[0];
    var memberroles = changes.memberrole.map(function (r) {
        return (getDNValue(r, 0));
    });

    var payload = {
        type: 'group',
        name: name,
        account: account,
        roles: memberroles
    };

    batch.set('/uuid/' + uuid, JSON.stringify(payload));
    batch.set(sprintf('/group/%s/%s', account, name), uuid);
    batch.sadd('/set/groups/' + account, uuid);

    vasync.forEachParallel({
        func: function add(userdn, parallelcb) {
            // like uuid=foo, uuid=bar, ou=users, o=smartdc
            var user = getDNValue(userdn, 0);
            self.addGroupToUser(user, uuid, batch, parallelcb);
        },
        inputs: changes.uniquemember
    }, function parallelEnd(err, res) {
        if (err) {
            self.log.error({
                err: err,
                res: res
            }, 'putAccountGroup error');

            cb(err);
            return;
        }

        self.log.info('putAccountGroup: done');
        cb(null, batch);
    });
};


Transformer.prototype.delAccountGroup = function (opts, cb) {
    assert.object(opts, 'opts');
    assert.object(opts.batch, 'opts.batch');
    assert.object(opts.changes, 'opts.changes');
    assert.func(cb, 'callback');

    var self = this;

    self.log.info('delAccountGroup: entered');

    var batch = opts.batch;
    var changes = opts.changes;
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
                var user = getDNValue(userdn, 0);
                self.delGroupFromUser(uuid, user, batch, parallelcb);
            },
            inputs: changes.uniquemember
        }, function parallelEnd(err, res) {
            if (err) {
                self.log.error({
                    err: err,
                    res: res
                }, 'delAccountGroup error');

                cb(err);
                return;
            }

            self.log.info('delAccountGroup: done');
            cb(null, batch);
        });
    } else {
        self.log.info({
            group: uuid,
            name: name
        }, 'delAccountGroup: no users to delete');
        self.log.info('delAccountGroup: done');
        cb(null, batch);
    }
};


Transformer.prototype.modAccountGroup = function (opts, cb) {
    assert.object(opts, 'opts');
    assert.object(opts.batch, 'opts.batch');
    assert.object(opts.changes, 'opts.changes');
    assert.object(opts.modEntry, 'opts.modEntry');
    assert.func(cb, 'callback');

    var self = this;

    self.log.info('modAccountGroup: entered');

    var changes = opts.changes;
    var batch = opts.batch;
    var group = opts.modEntry.uuid[0];

    vasync.forEachPipeline({
        func: function handleChange(change, pipelinecb) {
            if (change.modification.type === 'cn') { // rename
                self.rename({
                    name: change.modification.vals[0],
                    uuid: group,
                    batch: batch,
                    type: 'group'
                }, pipelinecb);
            } else if (change.modification.type === 'memberrole') {
                vasync.forEachParallel({
                    func: function modRole(roledn, parallelcb) {
                        var role = getDNValue(roledn, 0);
                        if (change.operation === 'add') {
                            self.addRoleMember(group, role, batch, parallelcb);
                        } else if (change.operation === 'delete') {
                            self.delRoleMember(group, role, batch, parallelcb);
                        } else {
                            self.log.warn({
                                operation: change.operation
                            }, 'modAccountGroup: unsupported operation type');
                            parallelcb();
                        }
                    },
                    inputs: change.modification.vals
                }, pipelinecb);
            } else if (change.modification.type === 'uniquemember') {
                vasync.forEachParallel({
                    func: function modUser(userdn, parallelcb) {
                        var user = getDNValue(userdn, 0);
                        if (change.operation === 'add') {
                            self.addGroupToUser(user, group, batch, parallelcb);
                        } else if (change.operation === 'delete') {
                            self.delGroupFromUser(user, group, batch,
                                parallelcb);
                        } else {
                            self.log.warn({
                                operation: change.operation
                            }, 'modAccountGroup: unsupported operation type');
                            parallelcb();
                        }
                    },
                    inputs: change.modification.vals
                }, pipelinecb);
            }
        },
        inputs: changes
    }, function pipelineEnd(err, res) {
        if (err) {
            self.log.error({err: err, res: res}, 'modAccountGroup error');
            cb(err);
            return;
        }
        self.log.info('modAccountGroup: done');
        cb(null, batch);
    });
};


Transformer.prototype.addGroupToUser = function (user, group, batch, cb) {
    assert.uuid(user, 'user');
    assert.uuid(group, 'group');
    assert.object(batch, 'batch');
    assert.func(cb, 'callback');

    var self = this;

    self.log.info({user: user, group: group}, 'addGroupToUser: entered');

    var key = '/uuid/' + user;
    self.redis.get(key, function gotUser(err, res) {
        if (err) {
            self.log.error({
                err: err,
                res: res
            }, 'addGroupToUser error');

            cb(err);
            return;
        }

        var payload = JSON.parse(res) || {};
        self.log.info({payload: payload}, 'addGroupToUser: got redis payload');
        payload.groups = payload.groups || [];
        payload.groups.push(group);

        batch.set(key, JSON.stringify(payload));

        self.log.info({batch: batch.queue}, 'addGroupToUser: done');
        cb(null, batch);
    });
};


Transformer.prototype.delGroupFromUser = function (user, group, batch, cb) {
    assert.uuid(user, 'user');
    assert.uuid(group, 'group');
    assert.object(batch, 'batch');
    assert.func(cb, 'callback');

    var self = this;

    self.log.info({user: user, group: group}, 'delGroupFromUser: entered');

    var key = '/uuid/' + user;
    self.redis.get(key, function gotUser(err, res) {
        if (err) {
            self.log.error({
                err: err,
                res: res
            }, 'delGroupToUser error');

            cb(err);
            return;
        }

        var payload = JSON.parse(res);
        var index;

        if (!payload) {
            self.log.info('delGroupFromUser: User does not exist.');
            self.log.info('delGroupFromuser: done');
            cb(null, batch);
            return;
        }

        payload.groups = payload.groups || [];
        index = payload.groups.indexOf(group);
        if (index > -1) {
            payload.groups.splice(index, 1);
        } else {
            self.log.warn({
                group: group,
                user: user
            }, 'delGroupFromUser: group not found');
        }

        batch.set(key, JSON.stringify(payload));
        self.log.info({batch: batch.queue}, 'addGroupToUser: done');
        cb(null, batch);
    });
};


// -- sdcaccountrole

Transformer.prototype.putRole = function (opts, cb) {
    assert.object(opts, 'opts');
    assert.object(opts.batch, 'opts.batch');
    assert.object(opts.changes, 'opts.changes');
    assert.func(cb, 'callback');

    var self = this;

    self.log.info('putRole: entered');

    var batch = opts.batch;
    var changes = opts.changes;
    var account = changes.account[0];
    var name = changes.role[0];
    var uuid = changes.uuid[0];

    var payload = {
        type: 'role',
        name: name,
        policies: changes.policydocument,
        account: account
    };

    var barrier = vasync.barrier();
    var error = null;

    batch.set('/uuid/' + uuid, JSON.stringify(payload));
    batch.set(sprintf('/role/%s/%s', account, name), uuid);
    batch.sadd('/set/roles/' + account, uuid);

    barrier.start('membergroup');
    barrier.start('uniquemember');
    barrier.on('drain', function barrierDrain() {
        self.log.info('putRole: done');
        cb(error, batch);
    });

    if (changes.uniquemember) {
        vasync.forEachParallel({
            func: function addUser(userdn, parallelcb) {
                // like uuid=foo, uuid=bar, ou=users, o=smartdc
                var user = getDNValue(userdn, 0);
                self.addRoleMember(user, uuid, batch, parallelcb);
            },
            inputs: changes.uniquemember
        }, function parallelEndUser(err, res) {
            if (err) {
                self.log.error({
                    err: err,
                    res: res
                }, 'putRole error');

                error = (error && err) ? [error, err] : err;
            }

            barrier.done('uniquemember');
        });
    } else {
        self.log.info({
            role: uuid,
            name: name
        }, 'putRole: no uniquemembers in role');
        barrier.done('uniquemember');
    }

    if (changes.membergroup) {
        vasync.forEachParallel({
            func: function addGroup(groupdn, parallelcb) {
                // like group-uuid=foo, uuid=bar, ou=users, o=smartdc
                var group = getDNValue(groupdn, 0);
                self.addRoleMember(group, uuid, batch, parallelcb);
            },
            inputs: changes.membergroup
        }, function parallelEndGroup(err, res) {
            if (err) {
                self.log.error({
                    err: err,
                    res: res
                }, 'putRole error');

                error = (error && err) ? [error, err] : err;
            }

            barrier.done('membergroup');
        });
    } else {
        self.log.info({
            role: uuid,
            name: name
        }, 'putRole: no membergroups in role');
        barrier.done('membergroup');
    }
};


// Group members do not count as ldap "leaves" and the delete entry contains
// the list of membergroups and uniquemembers that are no longer part of this
// group.  There are no "modify, operation: delete" entries in the changelog
// before a an empty group is deleted
Transformer.prototype.delRole = function (opts, cb) {
    assert.object(opts, 'opts');
    assert.object(opts.batch, 'opts.batch');
    assert.object(opts.changes, 'opts.changes');
    assert.func(cb, 'callback');

    var self = this;

    self.log.info('delRole: entered');

    var batch = opts.batch;
    var changes = opts.changes;
    var account = changes.account;
    var name = changes.role;
    var uuid = changes.uuid;

    var barrier = vasync.barrier();
    var error = null;

    batch.del('/uuid/' + uuid);
    batch.del(sprintf('/role/%s/%s', account, name));
    batch.srem('/set/roles/' + account, uuid);

    barrier.start('uniquemember');
    barrier.start('membergroup');
    barrier.once('drain', function barrierDrain() {
        self.log.info('delRole: done');
        cb(error, batch);
    });

    if (changes.uniquemember) {
        vasync.forEachParallel({
            func: function delUser(userdn, parallelcb) {
                // like uuid=foo, uuid=bar, ou=users, o=smartdc
                var user = getDNValue(userdn, 0);
                self.delRoleMember(user, uuid, batch, parallelcb);
            },
            inputs: changes.uniquemember
        }, function parallelEndUser(err, res) {
            if (err) {
                self.log.error({
                    err: err,
                    res: res
                }, 'delRole error');
                error = (error && err) ? [error, err] : err;
            }

            barrier.done('uniquemember');
        });
    } else {
        self.log.info('delRole: no uniquemembers in role');
        barrier.done('uniquemember');
    }

    if (changes.membergroup) {
        vasync.forEachParallel({
            func: function delGroup(groupdn, parallelcb) {
                // like group-uuid=foo, uuid=bar, ou=smartdc, o=smartdc
                var group = getDNValue(groupdn, 0);
                self.delRoleMember(group, uuid, batch, parallelcb);
            },
            inputs: changes.membergroup
        }, function parallelEndGroup(err, res) {
            if (err) {
                self.log.error({
                    err: err,
                    res: res
                }, 'delRole error');
                error = (error && err) ? [error, err] : err;
            }

            barrier.done('membergroup');
        });
    } else {
        self.log.info('delRole: role is not a member of any groups');
        barrier.done('membergroup');
    }
};


Transformer.prototype.modRole = function (opts, cb) {
    assert.object(opts, 'opts');
    assert.object(opts.batch, 'opts.batch');
    assert.object(opts.changes, 'opts.changes');
    assert.object(opts.modEntry, 'opts.modEntry');
    assert.func(cb, 'callback');

    var self = this;

    self.log.info('modRole: entered');

    var changes = opts.changes;
    var batch = opts.batch;
    var role = opts.modEntry.uuid[0];

    vasync.forEachPipeline({
        func: function handleChange(change, pipelinecb) {
            if (change.modification.type === 'role') { // rename
                assert.equal(change.operation, 'replace');
                self.rename({
                    name: change.modification.vals[0],
                    uuid: role,
                    batch: batch,
                    type: 'role'
                }, pipelinecb);
            } else if (change.modification.type === 'policydocument') {
                vasync.forEachParallel({
                    func: function modPolicy(policy, parallelcb) {
                        if (change.operation === 'add') {
                            self.addPolicy(policy, role, batch, parallelcb);
                        } else if (change.operation === 'delete') {
                            self.delPolicy(policy, role, batch, parallelcb);
                        } else if (change.operation === 'modify') {
                            self.modPolicy(policy, role, batch, parallelcb);
                        } else {
                            self.log.warn({
                                operation: change.operation
                            }, 'modRole: unhandled operation for type %s',
                            change.modification.type);
                            parallelcb();
                        }
                    },
                    inputs: change.modification.vals
                }, pipelinecb);
            } else if (change.modification.type === 'membergroup') {
                vasync.forEachParallel({
                    func: function modGroup(groupdn, parallelcb) {
                        // like group-uuid=foo, uuid=bar, ou=users, o=smartdc
                        var group = getDNValue(groupdn, 0);
                        if (change.operation === 'add') {
                            self.addRoleMember(group, role, batch, parallelcb);
                        } else if (change.operation === 'delete') {
                            self.delRoleMember(group, role, batch, parallelcb);
                        } else {
                            self.log.warn({
                                operation: change.operation
                            }, 'modRole: unhandled operation for type %s',
                            change.modification.type);
                            parallelcb();
                        }
                    },
                    inputs: change.modification.vals
                }, pipelinecb);

            } else {
                self.log.warn({
                    type: change.modification.type
                }, 'modRole: unhandled modification type');
                pipelinecb();
            }
        },
        inputs: changes
    }, function pipelineEnd(err, res) {
        if (err) {
            self.log.error({err: err, res: res}, 'modRole error');
            cb(err);
            return;
        }
        self.log.info('modRole: done');
        cb(null, batch);
    });
};



Transformer.prototype.rename = function (opts, cb) {
    assert.string(opts.name, 'name');
    assert.uuid(opts.uuid, 'uuid');
    assert.object(opts.batch, 'batch');
    assert.string(opts.type, 'type');
    assert.func(cb, 'cb');

    var self = this;

    self.log.info({name: name, uuid: uuid, type: type}, 'rename: entered');

    var name = opts.name;
    var uuid = opts.uuid;
    var batch = opts.batch;
    var type = opts.type;

    var key = '/uuid/' + uuid;
    self.redis.get(key, function gotValue(err, res) {
        if (err) {
            self.log.error({
                err: err,
                res: res
            }, 'rename redis error');
            cb(err);
            return;
        }

        var payload = JSON.parse(res);

        if (!payload) {
            self.log.warn({
                key: key,
                res: res
            }, 'renaming empty key');
            cb(null, batch);
        }

        batch.del(sprintf('/%s/%s/%s', type, payload.account, payload.name));
        batch.set(sprintf('/%s/%s/%s', type, payload.account, name), uuid);

        payload.name = name;
        batch.set(key, JSON.stringify(payload));

        self.log.info({batch: batch.queue}, 'rename: done');
        cb(null, batch);
    });
};


// add a role to the target user or group
/*
 * uuid: uuid of the target user or group to add the role
 * role: uuid of the role to add
 */
Transformer.prototype.addRoleMember = function (uuid, role, batch, cb) {
    assert.uuid(uuid, 'uuid');
    assert.uuid(role, 'role');
    assert.object(batch, 'batch');
    assert.func(cb, 'callback');

    var self = this;

    self.log.info({uuid: uuid, role: role}, 'addRoleMember: entered');

    var key = '/uuid/' + uuid;
    self.redis.get(key, function gotValue(err, res) {
        if (err) {
            self.log.error({
                err: err,
                res: res
            }, 'addRoleMember error');
            cb(err);
            return;
        }

        var payload = JSON.parse(res) || {};
        payload.roles = payload.roles || [];
        payload.roles.push(role);
        batch.set(key, JSON.stringify(payload));
        self.log.info({batch: batch.queue}, 'addRoleMember: done');
        cb(null, batch);
    });
};


// removes a role from target user or group
Transformer.prototype.delRoleMember = function (uuid, role, batch, cb) {
    assert.uuid(uuid, 'uuid');
    assert.uuid(role, 'role');
    assert.object(batch, 'batch');
    assert.func(cb, 'callback');

    var self = this;

    self.log.info({uuid: uuid, role: role}, 'delRoleMember: entered');

    var key = '/uuid/' + uuid;
    self.redis.get(key, function gotValue(err, res) {
        if (err) {
            self.log.error({
                err: err,
                res: res
            }, 'delRoleMember error');
            cb(err);
            return;
        }

        var payload = JSON.parse(res);
        var index;
        if (!payload) {
            self.log.info('delRoleMember: Key does not exist. Nothing to do.');
            self.log.info('delRoleMember: done');
            cb(null, batch);
            return;
        }

        payload.roles = payload.roles || [];

        // XXX O(N) string comparisons and a O(N) splice
        index = payload.roles.indexOf(role);
        if (index > -1) {
            payload.roles.splice(index, 1);
        } else {
            self.log.warn({
                role: role,
                target: uuid
            }, 'delRoleMember: role not found');
        }

        batch.set(key, JSON.stringify(payload));
        self.log.info({batch: batch.queue}, 'delRoleMember: done');
        cb(null, batch);
    });
};


Transformer.prototype.addPolicy = function (policy, role, batch, cb) {
    assert.string(policy, 'policy');
    assert.uuid(role, 'role');
    assert.object(batch, 'batch');
    assert.func(cb, 'callback');

    var self = this;

    self.log.info({policy: policy, role: role}, 'addPolicy: entered');

    var key = '/uuid/' + role;
    self.redis.get('key', function gotRole(err, res) {
        if (err) {
            self.log.error({
                err: err,
                res: res
            }, 'addPolicy error');
            cb(err);
            return;
        }

        var payload = JSON.parse(res) || {};
        payload.policies = payload.policies || [];
        payload.policies.push(policy);
        batch.set(key, JSON.stringify(payload));
        self.log.info({batch: batch.queue}, 'addPolicy: done');
        cb(null, batch);
    });
};


Transformer.prototype.delPolicy = function (policy, role, batch, cb) {
    assert.string(policy, 'policy');
    assert.uuid(role, 'role');
    assert.object(batch, 'batch');
    assert.func(cb, 'callback');

    var self = this;

    self.log.info({policy: policy, role: role}, 'delPolicy: entered');

    var key = '/uuid/' + role;
    self.redis.get(key, function gotRole(err, res) {
        if (err) {
            self.log.error({
                err: err,
                res: res
            }, 'delPolicy error');
            cb(err);
            return;
        }

        var payload = JSON.parse(res);
        var index;
        if (!payload) {
            self.log.info('delPolicy: Role does not exist. Nothing to do.');
            self.log.info('delPolicy: done');
            cb(null, batch);
            return;
        }

        payload.policies = payload.policies || [];

        // XXX O(N) string comparisons and a O(N) splice
        index = payload.policies.indexOf(policy);
        if (index > -1) {
            payload.policies.splice(index, 1);
        } else {
            self.log.warn({
                policy: policy,
                role: role
            }, 'delPolicy: policy not found');
        }

        batch.set(key, JSON.stringify(payload));
        self.log.info({batch: batch.queue}, 'delPolicy: done');
        cb(null, batch);
    });
};

Transformer.prototype.modPolicy = function (policy, role, batch, cb) {
    assert.string(policy, 'policy');
    assert.uuid(role, 'uuid');
    assert.object(batch, 'batch');
    assert.func(cb, 'callback');

    var self = this;

    self.log.info({policy: policy, role: role}, 'modPolicy: entered');

    var key = '/uuid/' + role;
    self.redis.get('key', function gotRole(err, res) {
        if (err) {
            self.log.error({
                err: err,
                res: res
            }, 'modPolicy error');
            cb(err);
            return;
        }

        var payload = JSON.parse(res) || {};
        payload.policies = [policy];
        batch.set(key, JSON.stringify(payload));
        self.log.info({batch: batch.queue}, 'modPolicy: done');
        cb(null, batch);
    });
};

// -- sdcaccountuser

Transformer.prototype.putUser = function (opts, cb) {
    assert.object(opts, 'opts');
    assert.object(opts.changes, 'opts.changes');
    assert.func(cb, 'callback');

    var self = this;

    self.log.info('putUser: entered');

    var changes = opts.changes;
    var uuid = changes.uuid[0];
    var account = changes.account[0];
    var login = changes.login[0];

    var payload = {
        type: 'user',
        account: account,
        login: login
    };

    var batch = opts.batch;
    batch.set('/uuid/' + uuid, JSON.stringify(payload));
    batch.set(sprintf('/user/%s/%s', account, login), uuid);
    batch.sadd('/set/users/' + account, uuid);

    self.log.info({batch: batch.queue}, 'putUser: done');
    cb(null, batch);
};


Transformer.prototype.delUser = function (opts, cb) {
    assert.object(opts, 'opts');
    assert.object(opts.batch, 'opts.batch');
    assert.object(opts.changes, 'opts.changes');
    assert.func(cb, 'callback');

    var self = this;

    self.log.info('delUser: entered');

    var changes = opts.changes;
    var uuid = changes.uuid[0];
    var login = changes.login[0];
    var account = changes.account[0];

    var batch = opts.batch;
    batch.del('/uuid/' + uuid);
    batch.del(sprintf('/user/%s/%s', account, login));
    batch.srem('/set/users/' + account, uuid);

    self.log.info({batch: batch.queue}, 'delUser: done');
    cb(null, batch);
};


Transformer.prototype.modUser = function (opts, cb) {
    assert.object(opts, 'opts');
    assert.object(opts.batch, 'opts.batch');
    assert.object(opts.changes, 'opts.changes');
    assert.object(opts.modEntry, 'opts.modEntry');
    assert.func(cb, 'callback');

    var self = this;

    self.log.info('modUser: entered');

    var batch = opts.batch;
    var changes = opts.changes;
    var uuid = opts.modEntry.uuid[0];
    var account = opts.modEntry.account[0];
    var key = '/uuid/' + uuid;

    self.redis.get(key, function (redisErr, res) {
        if (redisErr) {
            cb(redisErr);
            return;
        }

        var payload = JSON.parse(res);

        self.log.info({payload: payload}, 'modUser: got redis payload');

        changes.forEach(function (change) {
            if (change.modification.type === 'login') { // rename
                assert.equal(change.operation, 'replace');
                self.log.info({
                    change: change
                }, 'modUser: login change');

                batch.del(sprintf('/user/%s/%s', account, payload.login));

                payload.login = change.modification.vals[0];
                batch.set(sprintf('/user/%s/%s', account, payload.login), uuid);
                batch.set(key, JSON.stringify(payload));
            } else {
                self.log.warn({type: change.modification.type},
                    'modUser: unhandled modification type');
            }
        });
        self.log.info({batch: batch.queue}, 'modUser: done');
        cb(null, batch);
    });
};



// -- sdckey

// add a key to either an account or a user
Transformer.prototype.addKey = function (opts, cb) {
    assert.object(opts, 'opts');
    assert.object(opts.batch, 'opts.batch');
    assert.object(opts.changes, 'opts.changes');
    assert.func(cb, 'callback');

    var self = this;

    self.log.info('addKey: entered');

    var changes = opts.changes;
    var fingerprint = changes.fingerprint[0];
    var pkcs = changes.pkcs[0];
    var uuid = changes._owner;
    var key = '/uuid/' + uuid;

    var batch = opts.batch;
    self.redis.get(key, function (getErr, res) {
        if (getErr) {
            cb(getErr);
            return;
        }

        var payload = JSON.parse(res) || {};

        payload.keys = payload.keys || {};
        payload.keys[fingerprint] = pkcs;
        batch.set(key, JSON.stringify(payload));

        self.log.info({batch: batch.queue}, 'addKey: done');
        cb(null, batch);
    });
};


Transformer.prototype.delKey = function (opts, cb) {
    assert.object(opts, 'opts');
    assert.object(opts.batch, 'opts.batch');
    assert.object(opts.changes, 'opts.changes');
    assert.func(cb, 'callback');

    var self = this;

    self.log.info('delKey: entered');

    var changes = opts.changes;
    var fingerprint = changes.fingerprint[0];
    var uuid = changes.fingerprint;
    var key = '/uuid/' + uuid;

    var batch = opts.batch;
    self.redis.get(key, function (getErr, res) {
        if (getErr) {
            cb(getErr);
            return;
        }

        var payload = JSON.parse(res) || {};

        if (payload.keys) {
            delete payload.keys[fingerprint];
        }

        batch.set(key, JSON.stringify(payload));
        self.log.info({batch: batch.queue}, 'delKey: done');
        cb(null, batch);
    });
};



// -- sdcperson


Transformer.prototype.putAccount = function (opts, cb) {
    assert.object(opts, 'opts');
    assert.object(opts.batch, 'opts.batch');
    assert.object(opts.changes, 'opts.changes');
    assert.func(cb, 'callback');

    var self = this;

    self.log.info('putAccount: entered');

    var changes = opts.changes;
    var uuid = changes.uuid[0];
    var login = changes.login[0];
    var approved = changes.approved_for_provisioning &&
        changes.approved_for_provisioning[0] &&
        changes.approved_for_provisioning[0] === 'true'; // booleans from ldap
                                                         // are serialized as
                                                         // strings
    var payload = {
        type: 'account',
        login: login,
        approved_for_provisioning: approved
    };

    var batch = opts.batch;
    batch.set('/uuid/' + uuid, JSON.stringify(payload));
    batch.set('/account/' + login, uuid);
    batch.sadd('/set/accounts', uuid);

    self.log.info({batch: batch.queue}, 'putAccount: done');
    cb(null, batch);
};


Transformer.prototype.delAccount = function (opts, cb) {
    assert.object(opts, 'opts');
    assert.object(opts.batch, 'opts.batch');
    assert.object(opts.changes, 'opts.changes');
    assert.func(cb, 'callback');

    var self = this;

    self.log.info('delAccount: entered');

    var changes = opts.changes;
    var uuid = changes.uuid[0];
    var login = changes.login[0];

    var batch = opts.batch;
    batch.del('/uuid/' + uuid);
    batch.del('/account/' + login);
    batch.srem('/set/accounts', uuid);
    batch.del('/set/users/' + uuid);
    batch.del('/set/roles/' + uuid);
    batch.del('/set/groups/' + uuid);

    self.log.info({batch: batch.queue}, 'delAccount: done');
    cb(null, batch);
};



/*
 * "changes": [
 *    {
 *      "operation": "delete",
 *      "modification": {
 *        "type": "approved_for_provisioning",
 *        "vals": [
 *          "false"
 *        ]
 *      }
 *    },
 *    {
 *      "operation": "replace",
 *      "modification": {
 *        "type": "updated_at",
 *        "vals": [
 *          "1385576096453"
 *        ]
 *      }
 *    }
 *  ],
 */
Transformer.prototype.modAccount = function (opts, cb) {
    assert.object(opts, 'opts');
    assert.object(opts.batch, 'opts.batch');
    assert.object(opts.changes, 'opts.changes');
    assert.object(opts.modEntry, 'opts.modEntry');
    assert.func(cb, 'callback');

    var self = this;

    self.log.info('modAccount: entered');

    var changes = opts.changes;
    var uuid = opts.modEntry.uuid[0];
    var key = '/uuid/' + uuid;

    var batch = opts.batch;

    self.redis.get(key, function (redisErr, res) {
        if (redisErr) {
            cb(redisErr);
            return;
        }

        var payload = JSON.parse(res);

        self.log.info({payload: payload}, 'modAccount: got redis payload');

        // OK to use forEach loop here because inner function is synchronous
        changes.forEach(function (change) {

            if (change.modification.type === 'approved_for_provisioning') {
                self.log.info({
                    change: change
                }, 'modAccount: approved_for_provisioning');

                if (change.operation === 'delete') {
                    payload.approved_for_provisioning = false;
                } else if (change.operation === 'replace' ||
                    change.operation === 'add') {

                    payload.approved_for_provisioning =
                        change.modification.vals[0] === 'true';
                }

                self.log.info({
                    payload: payload
                }, 'modAccount: setting redis payload');

                batch.set(key, JSON.stringify(payload));
            } else if (change.modification.type === 'login') { // rename
                self.log.info({
                    change: change
                }, 'modAccount: login');

                batch.del('/account/' + payload.login);

                payload.login = change.modification.vals[0];
                batch.set('/account/' + payload.login, uuid);

                self.log.info({
                    payload: payload
                }, 'modAccount: setting redis payload');

                batch.set(key, JSON.stringify(payload));
            } else {
                self.log.warn({type: change.modification.type},
                    'modAccount: unhandled modification type');
            }
        });

        self.log.info({batch: batch.queue}, 'modAccount: done');
        cb(null, batch);
    });
};
