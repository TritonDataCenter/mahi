// Copyright (c) 2014, Joyent, Inc. All rights reserved.

var assert = require('assert-plus');
var binarySearch = require('binary-search');
var util = require('util');

module.exports = {
    getDNValue: getDNValue,
    addToSet: addToSet,
    delFromSet: delFromSet,
    setUnion: setUnion,
    setDifference: setDifference,
    addToMapSet: addToMapSet,
    delFromMapSet: delFromMapSet,
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

    log.trace({
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

        log.trace({payload: payload}, 'addToSet: got redis payload');

        payload[set] = payload[set] || [];
        index = binarySearch(payload[set], element, comparator);
        if (index < 0) {
            payload[set].splice(-index - 1, 0, element);
        }

        batch.set(key, JSON.stringify(payload));

        log.trace('addToSet: done');
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

    log.trace({
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

        log.trace({payload: payload}, 'delFromSet: got redis payload');

        payload[set] = payload[set] || [];
        index = binarySearch(payload[set], element, comparator);
        if (index < 0) {
            log.trace('delFromSet: element not found');
        } else {
            payload[set].splice(index, 1);
        }
        batch.set(key, JSON.stringify(payload));

        log.trace('delFromSet: done');
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

    log.trace({
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
        log.trace({payload: payload}, 'addToMapSet: got redis payload');
        payload[set] = payload[set] || {};
        payload[set][element] = true;
        batch.set(key, JSON.stringify(payload));
        log.trace('addToMapSet: done');
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

    log.trace({
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
        log.trace({payload: payload}, 'delFromMapSet: got redis payload');
        payload[set] = payload[set] || {};
        delete payload[set][element];
        batch.set(key, JSON.stringify(payload));
        log.trace('delFromMapSet: done');
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
    assert.string(opts.value, 'value');
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
