/*
 * Copyright (c) 2013, Joyent, Inc. All rights reserved.
 *
 * Transformations for each type of ufds changelog entry that we care to cache.
 * Transforms ldapjs JSON changelog entries into key/value pairs in redis.
 *
 */
var assert = require('assert-plus');
var vasync = require('vasync');

module.exports = {
    Transformer: Transformer
};

// -- helpers

function getDNValue(dn, index) {
    assert.string(dn, 'dn');
    assert.number(index, 'index');

    var part = dn.split(',')[index];
    return (part.substring(part.indexOf('=') + 1));
}


function Transformer(opts) {
    assert.object(opts, 'opts');
    assert.object(opts.redis, 'opts.redis');
    assert.object(opts.log, 'opts.log');

    var self = this;
    self.redis = opts.redis;
    self.log = opts.log;
}

Transformer.prototype.transform = function (opts, cb) {
    assert.object(opts, 'opts');
    assert.object(opts.entry, 'opts.entry');
    assert.object(opts.changes, 'opts.changes');
    assert.func(cb, 'callback');

    var self = this;

    var entry = opts.entry;
    var changes = opts.changes;
    var changetype = entry.changetype;
    var modEntry;
    var objectclass;

    if (changetype === 'modify') {
        // entry.entry only appears on 'modify' changes and contains the
        // complete new entry (instead of just the changes)
        modEntry = JSON.parse(entry.entry);
        objectclass = modEntry.objectclass[0];
    } else {
        objectclass = changes.objectclass[0];
    }

    var args = {
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
            break;
        case 'modify':
            break;
        default:
            cb(new Error('unrecognized changetype: ' + changetype));
            break;
        }
        break;
    case 'sdcaccountgroup':
        switch (changetype) {
        case 'add':
            break;
        case 'delete':
            break;
        case 'modify':
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
            self.putRole(args, cb);
            break;
        default:
            cb(new Error('unrecognized changetype: ' + changetype));
            break;
        }
        break;
    case 'sdcaccountuser':
        switch (changetype) {
        case 'add':
            break;
        case 'delete':
            break;
        case 'modify':
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
            // TODO investigate modify on sdckey
            self.log.warn({
                objectclass: objectclass,
                changetype: changetype
            }, 'unhandled objectclass/changetype combination');
            cb();
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
        cb();
        break;
    }
};



// -- groupofuniquenames

/*
 * {
 *   "dn": "changenumber=14, cn=changelog",
 *   "controls": [],
 *   "targetdn": "cn=operators, ou=groups, o=smartdc",
 *   "changetype": "add",
 *   "objectclass": "changeLogEntry",
 *   "changetime": "2013-12-03T18:29:25.272Z",
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
 *   },
 *   "changenumber": "14"
 * }
 */
// TODO tests: empty, single, multiple
Transformer.prototype.putGroup = function (opts, cb) {
    assert.object(opts, 'opts');
    assert.object(opts.entry, 'opts.entry');
    assert.object(opts.changes, 'opts.changes');
    assert.func(cb, 'callback');

    var self = this;

    self.log.info('putGroup: entered');

    var changes = opts.changes;
    var entry = opts.entry;
    // like cn=operators, ou=groups, o=smartdc
    var group = getDNValue(entry.targetdn, 0);
    var batch = self.redis.multi();
    if (!changes.uniquemember) {
        self.log.info('putGroup: no uniquemembers in group');
        self.log.info('putGroup: done');
        cb(null, batch);
        return;
    }

    vasync.forEachParallel({
        func: function add(userdn, parallelcb) {
            // like uuid=foo, ou=users, o=smartdc
            var uuid = getDNValue(userdn, 0);
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
    assert.object(opts.entry, 'opts.entry');
    assert.object(opts.changes, 'opts.changes');
    assert.func(cb, 'callback');

    var self = this;

    self.log.info('delGroup: entered');

    var changes = opts.changes;
    var entry = opts.entry;
    // like cn=operators, ou=groups, o=smartdc
    var group = getDNValue(entry.targetdn, 0);
    var batch = self.redis.multi();
    if (!changes.uniquemember) {
        self.log.info('delGroup: no uniquemembers in group');
        self.log.info('delGroup: done');
        cb(null, batch);
        return;
    }

    vasync.forEachParallel({
        func: function del(userdn, parallelcb) {
            // like uuid=foo, ou=users, o=smartdc
            var uuid = getDNValue(userdn, 0);
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
Transformer.prototype.modGroup = function (opts, cb){
    assert.object(opts, 'opts');
    assert.object(opts.entry, 'opts.entry');
    assert.object(opts.changes, 'opts.changes');
    assert.func(cb, 'callback');

    var self = this;

    self.log.info('modGroup: entered');

    var entry = opts.entry;
    var changes = opts.changes;
    // like cn=operators, ou=groups, o=smartdc
    var group = getDNValue(entry.targetdn, 0);
    var batch = self.redis.multi();

    vasync.forEachPipeline({
        func: function handleChange(change, pipelinecb) {
            if (change.modification.type === 'uniquemember') {
                vasync.forEachParallel({
                    func: function mod(userdn, parallelcb) {
                        // like uuid=foo, ou=users, o=smartdc
                        var uuid = getDNValue(userdn, 0);
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
                    inputs: change.vals
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


Transformer.prototype.addGroupMember = function (uuid, group, batch, cb) {
    assert.uuid(uuid, 'uuid');
    assert.string(group, 'group');
    assert.object(batch, 'batch');
    assert.func(cb, 'callback');

    var self = this;

    self.log.info('addGroupMember: entered');

    var key = '/uuid/' + uuid;
    self.redis.get(key, function gotUser(err, res) {
        if (err) {
            self.log.error({
                err: err, res: res
            }, 'addGroupMember error');

            cb(err);
            return;
        }

        var payload = JSON.parse(res);
        payload.groups = payload.groups || {};
        payload.groups[group] = true;
        batch.set(key, JSON.stringify(payload));
        cb(null, batch);
    });
};


Transformer.prototype.delGroupMember = function (uuid, group, batch, cb) {
    assert.uuid(uuid, 'uuid');
    assert.string(group, 'group');
    assert.object(batch, 'batch');
    assert.func(cb, 'callback');

    var self = this;

    self.log.info('delGroupMember: entered');

    var key = '/uuid/' + uuid;
    self.redis.get(key, function gotUser(err, res) {
        if (err) {
            self.log.error({
                err: err, res: res
            }, 'delGroupMember error');

            cb(err);
            return;
        }

        var payload = JSON.parse(res);
        payload.groups = payload.groups || {};
        payload.groups[group] = true;
        batch.set(key, JSON.stringify(payload));
        cb(null, batch);
    });
};




// -- sdcaccountgroup

// -- sdcaccountrole

/*
Transformer.prototype.putRole = function (opts, cb) {
    assert.object(opts, 'opts');
    assert.object(opts.changes, 'opts.changes');
    assert.func(cb, 'callback');

    var self = this;


    var changes = opts.changes;
    var key = '/uuid/' + changes.uuid[0];
    var payload = {
        uuid: changes.uuid[0],
        policies: changes.policydocument
    };

    var batch = self.redis.multi();
    batch.set(key, JSON.stringify(payload));
    batch.exec(function (err, replies) {
        if (err) {
            self.log.error({err: err, replies: replies}, 'putRole error');
            cb(err);
            return;
        }
        self.log.info({replies: replies}, 'putRole: done');
        cb();
    });
};
*/



// -- sdcaccountuser

/*
Transformer.prototype.putUser = function (opts, cb) {
    assert.object(opts, 'opts');
    assert.object(opts.changes, 'opts.changes');
    assert.func(cb, 'callback');

    var self = this;
    var changes = opts.changes;

    var key = '/uuid/' + changes.uuid[0];
    var parentAccount = changes.account[0];

    var payload = {
        uuid: changes.uuid[0],
        account: parentAccount,
        login: changes.login,
        groups: {}
    };

    self.redis.put(key, JSON.stringify(payload), function (err, res) {
        cb(err, res);
    });


};
*/



// -- sdckey

Transformer.prototype.addKey = function (opts, cb) {
    assert.object(opts, 'opts');
    assert.object(opts.entry, 'opts.entry');
    assert.object(opts.changes, 'opts.changes');
    assert.func(cb, 'callback');

    var self = this;

    self.log.info('addKey: entered');

    var entry = opts.entry;
    var changes = opts.changes;
    var fingerprint = changes.fingerprint[0];
    var pkcs = changes.pkcs[0];
    // like fingerprint=foo, uuid=bar, ou=users, o=smartdc
    var uuid = getDNValue(entry.targetdn, 1);
    var key = '/uuid/' + uuid;

    var batch = self.redis.multi();
    self.redis.get(key, function (getErr, res) {
        if (getErr) {
            cb(getErr);
            return;
        }

        var payload = JSON.parse(res);

        payload.keys = payload.keys || {};
        payload.keys[fingerprint] = pkcs;
        batch.set(key, JSON.stringify(payload));

        self.log.info('addKey: done');
        cb(null, batch);
    });
};


Transformer.prototype.delKey = function (opts, cb) {
    assert.object(opts, 'opts');
    assert.object(opts.entry, 'opts.entry');
    assert.object(opts.changes, 'opts.changes');
    assert.func(cb, 'callback');

    var self = this;

    self.log.info('delKey: entered');

    var entry = opts.entry;
    var changes = opts.changes;
    var fingerprint = changes.fingerprint[0];
    // like fingerprint=foo, uuid=bar, ou=users, o=smartdc
    var uuid = getDNValue(entry.targetdn, 1);
    var key = '/uuid/' + uuid;

    var batch = self.redis.multi();
    self.redis.get(key, function (getErr, res) {
        if (getErr) {
            cb(getErr);
            return;
        }

        var payload = JSON.parse(res);

        delete payload.keys[fingerprint];

        batch.set(key, JSON.stringify(payload));
        self.log.info('delKey: done');
        cb(null, batch);
    });
};



// -- sdcperson


Transformer.prototype.putAccount = function (opts, cb) {
    assert.object(opts, 'opts');
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
        uuid: uuid,
        login: login,
        approved_for_provisioning: approved
    };

    var batch = self.redis.multi();
    batch.set('/uuid/' + uuid, JSON.stringify(payload));
    batch.set('/account/' + login, uuid);
    batch.sadd('/set/accounts', uuid);

    self.log.info('putAccount: done');
    cb(null, batch);
};


Transformer.prototype.delAccount = function (opts, cb) {
    assert.object(opts, 'opts');
    assert.object(opts.changes, 'opts.changes');
    assert.func(cb, 'callback');

    var self = this;

    self.log.info('delAccount: entered');

    var changes = opts.changes;
    var uuid = changes.uuid[0];
    var login = changes.login[0];

    var batch = self.redis.multi();
    batch.del('/uuid/' + uuid);
    batch.del('/account/' + login);
    batch.srem('/set/accounts', uuid);

    self.log.info('delAccount: done');
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
// TODO tests: irrelevant, approved, rename, multiple?
Transformer.prototype.modAccount = function (opts, cb) {
    assert.object(opts, 'opts');
    assert.object(opts.changes, 'opts.changes');
    assert.object(opts.modEntry, 'opts.modEntry');
    assert.func(cb, 'callback');

    var self = this;

    self.log.info('modAccount: entered');

    var changes = opts.changes;
    var uuid = opts.modEntry.uuid[0];
    var key = '/uuid/' + uuid;

    var batch = self.redis.multi();

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

        self.log.info('modAccount: done');
        cb(null, batch);
    });
};
