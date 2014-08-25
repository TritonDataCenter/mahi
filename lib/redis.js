/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright (c) 2014, Joyent, Inc.
 */

var assert = require('assert-plus');
var backoff = require('backoff');
var extend = require('xtend');
var once = require('once');
var redis = require('redis');
redis.debug_mode = process.env.REDIS_DEBUG ? true : undefined;


// --- Internal Functions

function connect(opts, cb) {
    assert.object(opts, 'options');
    assert.number(opts.connectTimeout, 'options.connectTimeout');
    assert.string(opts.host, 'optionso.host');
    assert.object(opts.log, 'options.log');
    assert.object(opts.options, 'options.options');
    assert.number(opts.port, 'options.port');
    assert.func(cb, 'callback');

    cb = once(cb);
    var log = opts.log;

    var client = redis.createClient(opts.port, opts.host, opts.options);
    var t;

    function onConnectTimeout() {
        client.removeAllListeners('error');
        client.removeAllListeners('ready');

        log.debug('redis: connection timeout');
        cb(new Error('redis: connect timeout'));
    }

    client.once('error', function (err) {
        client.removeAllListeners('ready');
        clearTimeout(t);

        log.debug(err, 'redis: failed to connect');
        cb(err);
    });

    client.once('ready', function onConnect() {
        client.removeAllListeners('error');
        clearTimeout(t);

        log.debug({
            host: opts.host,
            port: opts.port
        }, 'redis: connected');
        cb(null, client);
    });

    t = setTimeout(onConnectTimeout, opts.connectTimeout);
}



// --- API

function createClient(opts, cb) {
    assert.object(opts, 'options');
    assert.string(opts.host, 'options.host');
    assert.object(opts.log, 'options.log');
    assert.object(opts.options, 'options.options');
    assert.number(opts.port, 'options.port');
    assert.optionalNumber(opts.connectTimeout, 'options.connectTimeout');
    assert.optionalNumber(opts.retries, 'options.retries');
    assert.optionalNumber(opts.minTimeout, 'options.minTimeout');
    assert.optionalNumber(opts.maxTimeout, 'options.maxTimeout');
    assert.func(cb, 'callback');

    var log = opts.log.child({component: 'redis'}, true);
    var _opts = {
        connectTimeout: opts.connectTimeout || 2000,
        host: opts.host,
        log: log,
        options: extend({max_attempts: 1}, opts.options),
        port: opts.port
    };

    var retry = backoff.call(connect, _opts, function (err, client) {
        retry.removeAllListeners('backoff');
        log.debug('redis client acquired after %d attempts',
            retry.getResults().length);
        cb(err, client);
    });

    retry.setStrategy(new backoff.ExponentialStrategy({
        initialDelay: opts.minTimeout || 1000,
        maxDelay: opts.maxTimeout || 60000
    }));
    retry.failAfter(opts.retries || Infinity);

    retry.on('backoff', function (number, delay) {
        var level;
        if (number === 0) {
            level = 'info';
        } else if (number < 5) {
            level = 'warn';
        } else {
            level = 'error';
        }
        log[level]({
            attempt: number,
            delay: delay
        }, 'redis: connection attempted');
    });
    retry.start();
}



// --- Exports

module.exports = {
    createClient: createClient
};
