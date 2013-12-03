/*
 * Copyright (c) 2013, Joyent, Inc. All rights reserved.
 *
 * Transformations for each type of ufds changelog entry that we care to cache.
 * Transforms ldapjs JSON changelog entries into key/value pairs in redis.
 *
 */
var assert = require('assert-plus');

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

/* changes like:
 "changes": [
    {
      "operation": "delete",
      "modification": {
        "type": "approved_for_provisioning",
        "vals": [
          "false"
        ]
      }
    },
    {
      "operation": "replace",
      "modification": {
        "type": "updated_at",
        "vals": [
          "1385576096453"
        ]
      }
    }
  ],
*/

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
                // do nothing
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

// -- sdcaccountgroup

// -- sdcaccountrole

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



// -- sdcaccountuser

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

    self.redis.get(key, function (getErr, res) {
        if (getErr) {
            cb(getErr);
            return;
        }

        var payload = JSON.parse(res);

        payload.keys = payload.keys || {};
        payload.keys[fingerprint] = pkcs;

        self.redis.set(key, JSON.stringify(payload), function (setErr, reply) {
            if (setErr) {
                self.log.error({err: setErr, reply: reply}, 'addKey error');
                cb(setErr);
                return;
            }

            self.log.info({reply: reply}, 'addKey: done');
            cb();
        });
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

    self.redis.get(key, function (getErr, res) {
        if (getErr) {
            cb(getErr);
            return;
        }

        var payload = JSON.parse(res);

        delete payload.keys[fingerprint];

        self.redis.set(key, JSON.stringify(payload), function (setErr, reply) {
            if (setErr) {
                self.log.error({err: setErr, reply: reply}, 'delKey error');
                cb(setErr);
                return;
            }

            self.log.info({reply: reply}, 'delKey: done');
            cb();
        });
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
    batch.exec(function (err, replies) {
        if (err) {
            self.log.error({err: err, replies: replies}, 'putAccount error');
            cb(err);
            return;
        }
        self.log.info({replies: replies}, 'putAccount: done');
        cb();
    });
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
    batch.exec(function (err, replies) {
        if (err) {
            self.log.error({err: err, replies: replies}, 'delAccount error');
            cb(err);
            return;
        }
        self.log.info({replies: replies}, 'delAccount: done');
        cb();
    });
};


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

        batch.exec(function (batchErr, replies) {
            if (batchErr) {
                self.log.error({
                    err: batchErr,
                    replies: replies
                }, 'modAccount error');
                cb(batchErr);
                return;
            }
            self.log.info({replies: replies}, 'modAccount: done');
            cb();
        });
    });
};
