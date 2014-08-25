/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright (c) 2014, Joyent, Inc.
 */

//
// Transforms ldapjs JSON changelog entries into key/value pairs in redis.
//

var aperture = require('aperture');
var assert = require('assert-plus');
var Backoff = require('backoff');
var Writable = require('stream').Writable;
var util = require('util');

var transforms = require('./transforms');

///--- Globals

///--- API

function Transform(opts) {
    assert.object(opts.redis, 'opts.redis');
    assert.object(opts.log, 'opts.log');
    assert.object(opts.typeTable, 'opts.typeTable');

    Writable.call(this, {
        objectMode: true
    });

    this.log = opts.log.child({component: 'Transform'}, true);
    this.redis = opts.redis;
    this.dead = false;
    this.parser = aperture.createParser({
        types: aperture.types,
        typeTable: opts.typeTable
    });
}
util.inherits(Transform, Writable);
module.exports = Transform;


Transform.prototype.close = function close() {
    var log = this.log;

    log.debug('close: entered');
    this.dead = true;

    if (this.redis) {
        this.redis.quit();
    }

    this.push(null);
    log.debug('close: done');
    setImmediate(this.emit.bind(this, 'close'));
};


Transform.prototype._write = function _write(entry, _, cb) {
    var self = this;

    this._xform(entry, function (err, batch) {
        var backoff = Backoff.exponential({
            randomisationFactor: 0,
            initialDelay: 10,
            maxDelay: 3000
        });

        function onExec(err) {
            if (err) {
                self.log.warn({
                    err: err,
                    batch: batch.queue
                }, 'error executing batch');
                if (!self.dead) {
                    backoff.backoff();
                }
                return;
            }
            self.log.info({batch: batch.queue}, 'batch executed');
            cb();
        }

        backoff.on('backoff', function (number, delay) {
            var level = 'warn';
            if (number > 5) {
                level = 'error';
            }
            self.log[level]('retry attempt %s in %s ms', number, delay);
        });

        backoff.on('ready', function () {
            batch.exec(onExec);
        });

        batch.exec(onExec);
    });
};


Transform.prototype._xform = function _xform(entry, cb) {
    var self = this;

    var backoff = Backoff.exponential({
        randomisationFactor: 0,
        initialDelay: 10,
        maxDelay: 3000
    });
    var changes = JSON.parse(entry.changes);
    var changetype = entry.changetype;
    var modEntry;
    var objectclass;

    function retry(err, batch) {
        if (err) {
            self.log.warn({
                err: err,
                entry: entry
            }, 'error transforming entry');

            if (!self.dead) {
                backoff.backoff();
            }

            return;
        }
        batch.set('changenumber', entry.changenumber);
        self.emit('batch', batch);
        cb(null, batch);
    }

    // entry.entry only appears on 'modify' changes and contains the
    // complete new entry (instead of just the changes)
    if (changetype === 'modify') {
        modEntry = JSON.parse(entry.entry);
        // XXX objectclass can have multiple elements, which indicates multiple
        // inheritance. This shows up for a user under an account, which has
        // objectclasses sdcperson and sdcaccountuser.
        // A cleaner approach might involve transforming the entry as an
        // sdcperson and as an sdcaccountuser separately, instead of handling
        // "sdcaccountuser_sdcperson" as a separate case as is done here.
        objectclass = modEntry.objectclass.sort().join('_');
    } else {
        objectclass = changes.objectclass.sort().join('_');
    }

    var args = {
        changes: changes,
        entry: entry,
        modEntry: modEntry,
        parser: this.parser,
        log: this.log,
        redis: this.redis
    };

    backoff.on('backoff', function (number, delay) {
        var level = 'warn';
        if (number > 5) {
            level = 'error';
        }
        self.log[level]('retry attempt %s in %s ms', number, delay);
    });

    if (!transforms[objectclass]) {
        this.log.warn({objectclass: objectclass}, 'unhandled objectclass');
        setImmediate(function () {
            retry(null, self.redis.multi());
        });
        return;
    }

    if (!transforms[objectclass][changetype]) {
        this.log.warn({
            changetype: changetype
        }, 'unhandled changetype for objectclass %s', objectclass);
        setImmediate(function () {
            retry(null, self.redis.multi());
        });
        return;
    }

    backoff.on('ready', function () {
        transforms[objectclass][changetype](args, retry);
    });

    transforms[objectclass][changetype](args, retry);
};


Transform.prototype.toString = function toString() {
    var str = '[object Transform <';
    str += 'redis=' + this.redis.host + ':' + this.redis.port;
    str += '>]';

    return (str);
};



///--- Tests
