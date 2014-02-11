/*
 * Copyright (c) 2013, Joyent, Inc. All rights reserved.
 *
 * Transformations for each type of ufds changelog entry that we care to cache.
 * Transforms ldapjs JSON changelog entries into key/value pairs in redis.
 *
 */
var aperture = require('aperture');
var assert = require('assert-plus');
var binarySearch = require('binary-search');
var sprintf = require('util').format;
var vasync = require('vasync');

module.exports = {
    Transformer: Transformer
};


// -- Helpers

/*
 * parses a ldap dn string and returns the value at the given index
 */
function getDNValue(dn, index) {
    assert.string(dn, 'dn');
    assert.number(index, 'index');

    var part = dn.split(',')[index];
    return (part.substring(part.indexOf('=') + 1));
}

function stringComparator(a, b) {
    return (a.localeCompare(b));
}

function comparator(a, b) {
    // policies are stored as tuples in [policy, parsed] format
    if (Array.isArray(a)) {
        return (stringComparator(a[0], b[0]));
    }

    return (stringComparator(a, b));
}
/*
 * adds an element to an array-backed set
 */
function addToSet(opts, cb) {
    assert.object(opts, 'opts');
    assert.string(opts.key, 'key');
    assert.string(opts.set, 'set');
    assert.string(opts.element, 'element');
    assert.object(opts.batch, 'batch');
    assert.object(opts.log, 'log');
    assert.object(opts.redis, 'redis');
    assert.func(cb, 'callback');

    var key = opts.key;
    var set = opts.set;
    var element = opts.element;
    var batch = opts.batch;
    var log = opts.log;
    var redis = opts.redis;

    log.info({
        key: key,
        set: set,
        element: element
    }, 'addToSet: entered');

    redis.get(key, function gotValue(err, res) {
        if (err) {
            log.error({
                err: err,
                res: res
            }, 'addToSet error');

            cb(err);
            return;
        }

        var payload = JSON.parse(res) || {};
        var index;

        log.info({payload: payload}, 'addToSet: got redis payload');

        payload[set] = payload[set] || [];
        index = binarySearch(payload[set], element, comparator);
        if (index < 0) {
            payload[set].splice(-index - 1, 0, element);
        }

        batch.set(key, JSON.stringify(payload));

        log.info('addToSet: done');
        cb(null, batch);
    });
}


/*
 * removes an element from an array-backed set
 */
function delFromSet(opts, cb) {
    assert.object(opts, 'opts');
    assert.string(opts.key, 'key');
    assert.string(opts.set, 'set');
    assert.string(opts.element, 'element');
    assert.object(opts.batch, 'batch');
    assert.object(opts.log, 'log');
    assert.object(opts.redis, 'redis');
    assert.func(cb, 'callback');

    var key = opts.key;
    var set = opts.set;
    var element = opts.element;
    var batch = opts.batch;
    var log = opts.log;
    var redis = opts.redis;

    log.info({
        key: key,
        set: set,
        element: element
    }, 'delFromSet: entered');

    redis.get(key, function gotValue(err, res) {
        if (err) {
            log.error({
                err: err,
                res: res
            }, 'delFromSet error');

            cb(err);
            return;
        }

        var payload = JSON.parse(res) || {};
        var index;

        log.info({payload: payload}, 'delFromSet: got redis payload');

        payload[set] = payload[set] || [];
        index = binarySearch(payload[set], element, comparator);
        if (index < 0) {
            log.warn('delFromSet: element not found');
        } else {
            payload[set].splice(-index - 1, 1);
        }
        batch.set(key, JSON.stringify(payload));

        log.info('delFromSet: done');
        cb(null, batch);
    });
}


/*
 * adds each element of an array of elements to an array-backed set
 */
function setUnion(opts, cb) {
    assert.object(opts, 'opts');
    assert.string(opts.key, 'key');
    assert.string(opts.set, 'set');
    assert.ok(Array.isArray(opts.elements), 'elements');
    assert.object(opts.batch, 'batch');
    assert.object(opts.log, 'log');
    assert.object(opts.redis, 'redis');
    assert.func(cb, 'callback');

    var key = opts.key;
    var set = opts.set;
    var elements = opts.elements;
    var batch = opts.batch;
    var log = opts.log;
    var redis = opts.redis;

    log.info({
        key: key,
        set: set,
        elements: elements
    }, 'setUnion: entered');

    redis.get(key, function (err, res) {
        if (err) {
            log.error({
                err: err,
                res: res
            }, 'setUnion error');
            cb(err);
            return;
        }

        var payload = JSON.parse(res) || {};
        var i = 0;
        var j = 0;
        var result = [];
        payload[set] = payload[set] || [];

        while (i < elements.length && j < payload[set].length) {
            var diff = comparator(elements[i], payload[set][j]);
            if (diff < 0) {
                result.push(elements[i]);
                i++;
            } else if (diff > 0) {
                result.push(payload[set][j]);
                j++;
            } else {
                result.push(elements[i]);
                i++;
                j++;
            }
        }

        while (i < elements.length) {
            result.push(elements[i]);
            i++;
        }

        while (j < payload[set].length) {
            result.push(payload[set][j]);
            j++;
        }

        payload[set] = result;

        batch.set(key, JSON.stringify(payload));
        log.info('setUnion: done');
        cb(null, batch);
    });
}


/*
 * removes each element of an array of elements from an array-backed set
 */
function setDifference(opts, cb) {
    assert.object(opts, 'opts');
    assert.string(opts.key, 'key');
    assert.string(opts.set, 'set');
    assert.ok(Array.isArray(opts.elements), 'elements');
    assert.object(opts.batch, 'batch');
    assert.object(opts.log, 'log');
    assert.object(opts.redis, 'redis');
    assert.func(cb, 'callback');

    var key = opts.key;
    var set = opts.set;
    var elements = opts.elements;
    var batch = opts.batch;
    var log = opts.log;
    var redis = opts.redis;

    log.info({
        key: key,
        set: set,
        elements: elements
    }, 'setDifference: entered');

    redis.get(key, function (err, res) {
        if (err) {
            log.error({
                err: err,
                res: res
            }, 'setDifference error');
            cb(err);
            return;
        }

        var payload = JSON.parse(res) || {};
        var i = 0;
        var j = 0;
        var result = [];
        payload[set] = payload[set] || [];
        while (i < elements.length && j < payload[set].length) {
            var diff = comparator(elements[i], payload[set][j]);
            if (diff < 0) {
                i++;
            } else if (diff > 0) {
                result.push(payload[set][j]);
                j++;
            } else {
                i++;
                j++;
            }
        }
        while (j < payload[set].length) {
            result.push(payload[set][j]);
            j++;
        }
        payload[set] = result;
        batch.set(key, JSON.stringify(payload));
        log.info('setDifference: done');
        cb(null, batch);
    });
}


/*
 * adds an element to a map-backed set
 */
function addToMapSet(opts, cb) {
    assert.object(opts, 'opts');
    assert.string(opts.key, 'key');
    assert.string(opts.set, 'set');
    assert.string(opts.element, 'element');
    assert.object(opts.batch, 'batch');
    assert.object(opts.log, 'log');
    assert.object(opts.redis, 'redis');
    assert.func(cb, 'callback');

    var key = opts.key;
    var set = opts.set;
    var element = opts.element;
    var batch = opts.batch;
    var log = opts.log;
    var redis = opts.redis;

    log.info({
        key: key,
        set: set,
        element: element
    }, 'addToMapSet: entered');

    redis.get(key, function gotValue(err, res) {
        if (err) {
            log.error({
                err: err,
                res: res
            }, 'addToMapSet error');

            cb(err);
            return;
        }

        var payload = JSON.parse(res) || {};
        log.info({payload: payload}, 'addToMapSet: got redis payload');
        payload[set] = payload[set] || {};
        payload[set][element] = true;
        batch.set(key, JSON.stringify(payload));
        log.info('addToMapSet: done');
        cb(null, batch);
    });
}


/*
 * removes an element from a map-backed set
 */
function delFromMapSet(opts, cb) {
    assert.object(opts, 'opts');
    assert.string(opts.key, 'key');
    assert.string(opts.set, 'set');
    assert.string(opts.element, 'element');
    assert.object(opts.batch, 'batch');
    assert.object(opts.log, 'log');
    assert.object(opts.redis, 'redis');
    assert.func(cb, 'callback');

    var key = opts.key;
    var set = opts.set;
    var element = opts.element;
    var batch = opts.batch;
    var log = opts.log;
    var redis = opts.redis;

    log.info({
        key: key,
        set: set,
        element: element
    }, 'delFromMapSet: entered');

    redis.get(key, function gotValue(err, res) {
        if (err) {
            log.error({
                err: err,
                res: res
            }, 'delFromMapSet error');

            cb(err);
            return;
        }

        var payload = JSON.parse(res) || {};
        log.info({payload: payload}, 'delFromMapSet: got redis payload');
        payload[set] = payload[set] || {};
        delete payload[set][element];
        batch.set(key, JSON.stringify(payload));
        log.info('delFromMapSet: done');
        cb(null, batch);
    });

}


/*
 * Sets the value of a property
 */
function setValue(opts, cb) {
    assert.object(opts, 'opts');
    assert.string(opts.key, 'key');
    assert.string(opts.set, 'property');
    assert.string(opts.element, 'value');
    assert.object(opts.batch, 'batch');
    assert.object(opts.log, 'log');
    assert.object(opts.redis, 'redis');
    assert.func(cb, 'callback');

    var key = opts.key;
    var property = opts.property;
    var value = opts.value;
    var batch = opts.batch;
    var log = opts.log;
    var redis = opts.redis;

    log.info({
        key: key,
        property: property,
        value: value
    }, 'setValue: entered');

    redis.get(key, function gotValue(err, res) {
        if (err) {
            log.error({
                err: err,
                res: res
            }, 'setValue error');

            cb(err);
            return;
        }

        var payload = JSON.parse(res) || {};

        log.info({payload: payload}, 'setValue: got redis payload');

        payload[property] = value;
        batch.set(key, JSON.stringify(payload));

        log.info('setValue: done');
        cb(null, batch);
    });
}


/*
 * rename an entity (not for use with login changes)
 */
function rename(opts, cb) {
    assert.object(opts, 'opts');
    assert.string(opts.name, 'name');
    assert.uuid(opts.uuid, 'uuid');
    assert.object(opts.batch, 'batch');
    assert.string(opts.type, 'type');
    assert.object(opts.log, 'log');
    assert.object(opts.redis, 'redis');
    assert.func(cb, 'cb');

    var name = opts.name;
    var uuid = opts.uuid;
    var batch = opts.batch;
    var type = opts.type;
    var log = opts.log;
    var redis = opts.redis;

    log.info({name: name, uuid: uuid, type: type}, 'rename: entered');

    var key = '/uuid/' + uuid;
    redis.get(key, function gotValue(err, res) {
        if (err) {
            log.error({
                err: err,
                res: res
            }, 'rename redis error');
            cb(err);
            return;
        }

        var payload = JSON.parse(res);

        if (!payload) {
            log.warn({
                key: key,
                res: res
            }, 'renaming empty key');
            cb(null, batch);
        }

        batch.del(sprintf('/%s/%s/%s', type, payload.account, payload.name));
        batch.set(sprintf('/%s/%s/%s', type, payload.account, name), uuid);

        payload.name = name;
        batch.set(key, JSON.stringify(payload));

        log.info('rename: done');
        cb(null, batch);
    });
}



// -- Transformer

function Transformer(opts) {
    assert.object(opts, 'opts');
    assert.object(opts.redis, 'opts.redis');
    assert.object(opts.log, 'opts.log');
    assert.object(opts.typeTable, 'opts.typeTable');

    var self = this;
    self.redis = opts.redis;
    self.log = opts.log;
    self.parser = aperture.createParser({
        types: aperture.types,
        typeTable: opts.typeTable
    });
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
    case 'sdcaccountpolicy':
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
            var account = getDNValue(accountdn, 0);
            addToMapSet({
                key: '/uuid/' + account,
                set: 'groups',
                element: group,
                batch: batch,
                log: self.log,
                redis: self.redis
            }, parallelcb);
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

        self.log.info({batch: batch.queue}, 'putGroup: done');
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
            var account = getDNValue(accountdn, 0);
            delFromMapSet({
                key: '/uuid/' + account,
                set: 'groups',
                element: group,
                batch: batch,
                log: self.log,
                redis: self.redis
            }, parallelcb);
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

        self.log.info({batch: batch.queue}, 'delGroup: done');
        cb(null, batch);
    });
};


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
                        var account = getDNValue(accountdn, 0);
                        if (change.operation === 'add') {
                            addToMapSet({
                                key: '/uuid/' + account,
                                set: 'groups',
                                element: group,
                                batch: batch,
                                log: self.log,
                                redis: self.redis
                            }, parallelcb);
                        } else if (change.operation === 'delete') {
                            delFromMapSet({
                                key: '/uuid/' + account,
                                set: 'groups',
                                element: group,
                                batch: batch,
                                log: self.log,
                                redis: self.redis
                            }, parallelcb);
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
            self.log.error({
                err: err,
                res: res},
            'modGroup error');
            cb(err);
            return;
        }
        self.log.info({batch: batch.queue}, 'modGroup: done');
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
    var memberpolicy;
    if (changes.memberpolicy) {
        memberpolicy = changes.memberpolicy.map(function (r) {
            return (getDNValue(r, 0));
        });
    }

    var payload = {
        type: 'group',
        uuid: uuid,
        name: name,
        account: account,
        roles: memberpolicy
    };

    batch.set('/uuid/' + uuid, JSON.stringify(payload));
    batch.set(sprintf('/group/%s/%s', account, name), uuid);
    batch.sadd('/set/groups/' + account, uuid);

    if (changes.uniquemember) {
        vasync.forEachParallel({
            func: function add(userdn, parallelcb) {
                // like uuid=foo, uuid=bar, ou=users, o=smartdc
                var user = getDNValue(userdn, 0);
                addToSet({
                    key: '/uuid/' + user,
                    set: 'groups',
                    element: uuid,
                    batch: batch,
                    log: self.log,
                    redis: self.redis
                }, parallelcb);
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

            self.log.info({batch: batch.queue}, 'putAccountGroup: done');
            cb(null, batch);
        });
    } else {
        self.log.info({
            group: uuid,
            name: name
        }, 'putAccountGroup: no users to add');
        self.log.info({batch: batch.queue}, 'putAccountGroup: done');
        cb(null, batch);
    }
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
                delFromSet({
                    key: '/uuid/' + user,
                    set: 'groups',
                    element: uuid,
                    batch: batch,
                    log: self.log,
                    redis: self.redis
                }, parallelcb);
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

            self.log.info({batch: batch.queue}, 'delAccountGroup: done');
            cb(null, batch);
        });
    } else {
        self.log.info({
            group: uuid,
            name: name
        }, 'delAccountGroup: no users to delete');
        self.log.info({batch: batch.queue}, 'delAccountGroup: done');
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
    var uuid = opts.modEntry.uuid[0];

    vasync.forEachPipeline({
        func: function handleChange(change, pipelinecb) {
            if (change.modification.type === 'cn') {
                rename({
                    name: change.modification.vals[0],
                    type: 'group',
                    uuid: uuid,
                    batch: batch,
                    log: self.log,
                    redis: self.redis
                }, pipelinecb);
            } else if (change.modification.type === 'memberrole') {
                var roles = change.modification.vals.map(function (r) {
                    return (getDNValue(r, 0));
                });
                if (change.operation === 'add') {
                    setUnion({
                        key: '/uuid/' + uuid,
                        set: 'roles',
                        elements: roles,
                        batch: batch,
                        log: self.log,
                        redis: self.redis
                    }, pipelinecb);
                } else if (change.operation === 'delete') {
                    setDifference({
                        key: '/uuid/' + uuid,
                        set: 'roles',
                        elements: roles,
                        batch: batch,
                        log: self.log,
                        redis: self.redis
                    }, pipelinecb);
                } else {
                    self.log.warn({
                        operation: change.operation
                    }, 'modAccountGroup: unsupported opration type');
                    pipelinecb();
                }
            } else if (change.modification.type === 'uniquemember') {
                vasync.forEachParallel({
                    func: function modUser(userdn, parallelcb) {
                        var user = getDNValue(userdn, 0);
                        if (change.operation === 'add') {
                            addToSet({
                                key: '/uuid/' + user,
                                set: 'groups',
                                element: uuid,
                                batch: batch,
                                log: self.log,
                                redis: self.redis
                            }, parallelcb);
                        } else if (change.operation === 'delete') {
                            delFromSet({
                                key: '/uuid/' + user,
                                set: 'groups',
                                element: uuid,
                                batch: batch,
                                log: self.log,
                                redis: self.redis
                            }, parallelcb);
                        } else {
                            self.log.warn({
                                operation: change.operation
                            }, 'modAccountGroup: unsupported operation type');
                            parallelcb();
                        }
                    },
                    inputs: change.modification.vals
                }, pipelinecb);
            } else {
                self.log.warn({
                    type: change.modification.type
                }, 'modAccountGroup: unhandled modification type');
                pipelinecb();
            }
        },
        inputs: changes
    }, function pipelineEnd(err, res) {
        if (err) {
            self.log.error({err: err, res: res}, 'modAccountGroup error');
            cb(err);
            return;
        }
        self.log.info({batch: batch.queue}, 'modAccountGroup: done');
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
    var name = changes.name[0];
    var uuid = changes.uuid[0];
    var policies;
    if (changes.policydocument) {
        policies = changes.policydocument.map(function (p) {
            return ([p, self.parser.parse(p)]);
        });
    }

    var payload = {
        type: 'role',
        uuid: uuid,
        name: name,
        policies: policies,
        account: account
    };

    batch.set('/uuid/' + uuid, JSON.stringify(payload));
    batch.set(sprintf('/role/%s/%s', account, name), uuid);
    batch.sadd('/set/roles/' + account, uuid);

    if (changes.membergroup) {
        vasync.forEachParallel({
            func: function addGroup(groupdn, parallelcb) {
                // like group-uuid=foo, uuid=bar, ou=users, o=smartdc
                var group = getDNValue(groupdn, 0);
                addToSet({
                    key: '/uuid/' + group,
                    set: 'roles',
                    element: uuid,
                    batch: batch,
                    log: self.log,
                    redis: self.redis
                }, parallelcb);
            },
            inputs: changes.membergroup
        }, function parallelEndGroup(err, res) {
            if (err) {
                self.log.error({
                    err: err,
                    res: res
                }, 'putRole error');

                cb(err);
                return;
            }

            cb(null, batch);
        });
    } else {
        self.log.info({
            role: uuid,
            name: name
        }, 'putRole: no membergroups in role');
        cb(null, batch);
    }
};


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
    var name = changes.name;
    var uuid = changes.uuid;

    batch.del('/uuid/' + uuid);
    batch.del(sprintf('/role/%s/%s', account, name));
    batch.srem('/set/roles/' + account, uuid);

    if (changes.membergroup) {
        vasync.forEachParallel({
            func: function delGroup(groupdn, parallelcb) {
                // like group-uuid=foo, uuid=bar, ou=smartdc, o=smartdc
                var group = getDNValue(groupdn, 0);
                delFromSet({
                    key: '/uuid/' + group,
                    set: 'roles',
                    element: uuid,
                    batch: batch,
                    log: self.log,
                    redis: self.redis
                }, parallelcb);
            },
            inputs: changes.membergroup
        }, function parallelEndGroup(err, res) {
            if (err) {
                self.log.error({
                    err: err,
                    res: res
                }, 'delRole error');
                cb(err);
                return;
            }

            cb(null, batch);
        });
    } else {
        self.log.info('delRole: role is not a member of any groups');
        cb(null, batch);
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
    var uuid = opts.modEntry.uuid[0];

    vasync.forEachPipeline({
        func: function handleChange(change, pipelinecb) {
            var policies;
            if (change.modification.type === 'name') { // rename
                assert.equal(change.operation, 'replace');
                rename({
                    name: change.modification.vals[0],
                    type: 'role',
                    uuid: uuid,
                    batch: batch,
                    log: self.log,
                    redis: self.redis
                }, pipelinecb);
            } else if (change.modification.type === 'policydocument') {
                policies = change.modification.vals.map(function (p) {
                    return ([p, self.parser.parse(p)]);
                });
                if (change.operation === 'add') {
                    setUnion({
                        key: '/uuid/' + uuid,
                        set: 'policies',
                        elements: policies,
                        batch: batch,
                        log: self.log,
                        redis: self.redis
                    }, pipelinecb);
                } else if (change.operation === 'delete') {
                    setDifference({
                        key: '/uuid/' + uuid,
                        set: 'policies',
                        elements: policies,
                        batch: batch,
                        log: self.log,
                        redis: self.redis
                    }, pipelinecb);
                } else if (change.operation === 'modify') {
                    setValue({
                        key: '/uuid/' + uuid,
                        property: 'policies',
                        value: policies,
                        batch: batch,
                        log: self.log,
                        redis: self.redis
                    }, pipelinecb);
                } else {
                    self.log.warn({
                        operation: change.operation
                    }, 'modRole: unhandled operation for type %s',
                            change.modification.type);

                    pipelinecb();
                }
            } else if (change.modification.type === 'membergroup') {
                vasync.forEachParallel({
                    func: function modGroup(groupdn, parallelcb) {
                        // like group-uuid=foo, uuid=bar, ou=users, o=smartdc
                        var group = getDNValue(groupdn, 0);
                        if (change.operation === 'add') {
                            addToSet({
                                key: '/uuid/' + group,
                                set: 'roles',
                                element: uuid,
                                batch: batch,
                                log: self.log,
                                redis: self.redis
                            }, parallelcb);
                        } else if (change.operation === 'delete') {
                            delFromSet({
                                key: '/uuid/' + group,
                                set: 'roles',
                                element: uuid,
                                batch: batch,
                                log: self.log,
                                redis: self.redis
                            }, parallelcb);
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
        self.log.info({batch: batch.queue}, 'modRole: done');
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
    var login = changes.alias[0];

    var payload = {
        type: 'user',
        uuid: uuid,
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
    var login = changes.alias[0];
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
    var login = opts.modEntry.alias[0];
    var key = '/uuid/' + uuid;

    self.redis.get(key, function (redisErr, res) {
        if (redisErr) {
            cb(redisErr);
            return;
        }

        var payload = JSON.parse(res);

        self.log.info({payload: payload}, 'modUser: got redis payload');

        changes.forEach(function (change) {
            if (change.modification.type === 'login') { // renameUser
                assert.equal(change.operation, 'replace');
                self.log.info({
                    change: change
                }, 'modUser: login change');

                batch.del(sprintf('/user/%s/%s', account, payload.login));

                payload.login = login;
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
        uuid: uuid,
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
