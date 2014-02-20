// Copyright (c) 2014, Joyent, Inc. All rights reserved.

var Writable = require('stream').Writable;
var util = require('util');

var assert = require('assert-plus');
var Backoff = require('backoff');

///--- Globals

///--- API

function RedisWriter(opts) {
    assert.object(opts, 'opts');
    assert.object(opts.log, 'opts.log');
    assert.object(opts.redis, 'opts.redis');

    Writable.call(this, {
        objectMode: true,
        highWaterMark: 0
    });

    this.log = opts.log.child({component: 'RedisWriter'}, true);
    this.redis = opts.redis;
}
util.inherits(RedisWriter, Writable);
module.exports = RedisWriter;


RedisWriter.prototype.close = function close() {
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


RedisWriter.prototype._write = function _write(batch, _, cb) {
    var self = this;
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
        this.log[level]('retry attempt %s in %s ms', number, delay);
    });

    batch.exec(onExec);
};


RedisWriter.prototype.toString = function toString() {
    var str = '[object RedisWriter <';
    str += 'redis=' + this.redis.host + ':' + this.redis.port;
    str += '>]';

    return (str);
};
