// Copyright (c) 2014, Joyent, Inc. All rights reserved.

var assert = require('assert-plus');
var binarySearch = require('binary-search');
var util = require('util');
var vasync = require('vasync');

module.exports = {
    getDNValue: getDNValue,
    comparator: comparator,
    addToGroup: addToGroup,
    delFromGroup: delFromGroup,
    replaceGroup: replaceGroup,
    setUnion: setUnion,
    setDifference: setDifference,
    setValue: setValue,
    rename: rename
};


///--- Globals

var sprintf = util.format;


///--- Helpers

// parses a ldap dn string and returns the value at the given index
function getDNValue(dn, index) {
    assert.string(dn, 'dn');
    assert.number(index, 'index');

    var part = dn.split(',')[index];
    return (part.substring(part.indexOf('=') + 1));
}

function comparator(a, b) {
    function stringComparator(a, b) {
        return (a.localeCompare(b));
    }

    // policies are stored as tuples in [policy, parsed] format
    if (Array.isArray(a)) {
        return (stringComparator(a[0], b[0]));
    }

    return (stringComparator(a, b));
}

/*
 * adds a member to a group
 *
 * member: group member to add
 * group: group to add to
 * type: type of group (e.g. 'roles', 'defaultRoles', 'groups', 'policies')
 * batch: redis.multi() object
 * log: bunyan log
 * redis: redis client
 */
function addToGroup(opts, cb) {
    assert.object(opts, 'opts');
    assert.string(opts.member, 'member');
    assert.string(opts.group, 'group');
    assert.string(opts.type, 'type');
    assert.object(opts.batch, 'batch');
    assert.object(opts.log, 'log');
    assert.func(cb, 'callback');

    var member = opts.member;
    var group = opts.group;
    var type = opts.type;
    var batch = opts.batch;
    var log = opts.log;

    var memberKey = sprintf('/uuid/%s', member);
    var groupKey = sprintf('/uuid/%s/%s', group, type);

    log.trace({
        member: member,
        group: group,
        type: type
    }, 'addToSet: entered');

    batch.sadd(groupKey, member);

    batch.get(memberKey, function gotValue(err, res) {
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

        log.trace({payload: payload}, 'addToSet: got redis payload');

        payload[type] = payload[type] || [];
        index = binarySearch(payload[type], group, comparator);
        if (index < 0) {
            payload[type].splice(-index - 1, 0, group);
        }

        batch.set(memberKey, JSON.stringify(payload));

        log.trace('addToSet: done');
        cb(null, batch);
    });
}


/*
 * removes an element from an array-backed set
 */
function delFromGroup(opts, cb) {
    assert.object(opts, 'opts');
    assert.string(opts.member, 'member');
    assert.string(opts.group, 'group');
    assert.string(opts.type, 'type');
    assert.object(opts.batch, 'batch');
    assert.object(opts.log, 'log');
    assert.func(cb, 'callback');

    var member = opts.member;
    var group = opts.group;
    var type = opts.type;
    var batch = opts.batch;
    var log = opts.log;

    var memberKey = sprintf('/uuid/%s', member);
    var groupKey = sprintf('/uuid/%s/%s', group, type);

    log.trace({
        member: member,
        group: group,
        type: type
    }, 'delFromSet: entered');

    batch.srem(groupKey, member);

    batch.get(memberKey, function gotValue(err, res) {
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

        log.trace({payload: payload}, 'delFromSet: got redis payload');

        payload[type] = payload[type] || [];
        index = binarySearch(payload[type], group, comparator);
        if (index < 0) {
            log.trace('delFromSet: group not found');
        } else {
            payload[type].splice(index, 1);
        }

        batch.set(memberKey, JSON.stringify(payload));

        log.trace('delFromSet: done');
        cb(null, batch);
    });
}


/*
 * replaces the members of a set
 */
function replaceGroup(opts, cb) {
    assert.object(opts, 'opts');
    assert.arrayOfString(opts.members, 'members');
    assert.string(opts.group, 'group');
    assert.string(opts.type, 'type');
    assert.object(opts.batch, 'batch');
    assert.object(opts.log, 'log');
    assert.func(cb, 'callback');

    var newMembers = opts.members;
    var group = opts.group;
    var type = opts.type;
    var batch = opts.batch;
    var log = opts.log;

    var groupKey = sprintf('/uuid/%s/%s', group, type);

    log.trace({
        members: newMembers,
        group: group,
        type: type
    }, 'replaceSet: entered');

    batch.smembers(groupKey, function (err, oldMembers) {
        vasync.parallel({funcs: [
            function addNewMembers(parallelcb) {
                vasync.forEachParallel({
                    func: function add(newMember, addcb) {
                        if (oldMembers.indexOf(newMember) < 0) {
                            addToGroup({
                                member: newMember,
                                group: group,
                                type: type,
                                batch: batch,
                                log: log
                            }, addcb);
                        } else {
                            setImmediate(function () {
                                addcb();
                            });
                        }
                    },
                    inputs: newMembers
                }, parallelcb);
            },
            function removeOldMembers(parallelcb) {
                vasync.forEachParallel({
                    func: function del(oldMember, delcb) {
                        if (newMembers.indexOf(oldMember) < 0) {
                            delFromGroup({
                                member: oldMember,
                                group: group,
                                type: type,
                                batch: batch,
                                log: log
                            }, delcb);
                        } else {
                            setImmediate(function () {
                                delcb();
                            });
                        }
                    },
                    inputs: oldMembers
                }, parallelcb);
            }
        ]}, function (err, res) {
            if (err) {
                log.error({
                    err: err,
                    res: res
                }, 'replaceSet: error');

                cb(err);
                return;
            }
            log.trace('replaceSet: done');
            cb(null, batch);
        });
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

    log.trace({
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
        log.trace('setUnion: done');
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

    log.trace({
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
        log.trace('setDifference: done');
        cb(null, batch);
    });
}



/*
 * Sets the value of a property
 */
function setValue(opts, cb) {
    assert.object(opts, 'opts');
    assert.string(opts.key, 'key');
    assert.string(opts.property, 'property');
    assert.ok(opts.value, 'value');
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

    log.trace({
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

        log.trace({payload: payload}, 'setValue: got redis payload');

        payload[property] = value;
        batch.set(key, JSON.stringify(payload));

        log.trace('setValue: done');
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

    log.trace({name: name, uuid: uuid, type: type}, 'rename: entered');

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
            return;
        }

        batch.del(sprintf('/%s/%s/%s', type, payload.account, payload.name));
        batch.set(sprintf('/%s/%s/%s', type, payload.account, name), uuid);

        payload.name = name;
        batch.set(key, JSON.stringify(payload));

        log.trace('rename: done');
        cb(null, batch);
    });
}
