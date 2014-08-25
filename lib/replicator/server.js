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
var errors = require('./errors.js');
var fs = require('fs');
var restify = require('restify');

function createServer(opts) {
    assert.object(opts, 'opts');
    assert.object(opts.log, 'opts.log');
    assert.object(opts.redis, 'opts.redis');

    var server = restify.createServer({
        name: 'mahi-sitter',
        log: opts.log,
        version: '0.0.0'
    });

    server.use(function initHandler(req, res, next) {
        req.redis = opts.redis;
        req.reader = opts.reader;
        req.transform = opts.transform;
        next();
    });

    server.get({
        name: 'ping',
        path: '/ping'
    }, ping);

    server.get({
        name: 'snapshot',
        path: '/snapshot'
    }, [savedb, savewait, senddb]);

    return (server);
}

function ping(req, res, next) {
    req.redis.ping(function (err) {
        if (err) {
            next(new errors.RedisUnavailableError());
            return;
        }
        req.redis.get('virginv2', function (err, redisRes) {
            if (err) {
                next(new errors.RedisError(err));
                return;
            }
            if (redisRes !== null) {
                next(new errors.NotCaughtUpError());
                return;
            }
            res.send(204);
            next();
            return;
        });
    });
}


function savedb(req, res, next) {
    req.redis.lastsave(function (err, res) {
        if (err) {
            next(new errors.RedisError(err));
            return;
        }

        req.lastsave = res;

        req.redis.bgsave(function (err) {
            if (err) {
                req.log.info('bgsave fail');
                next(new errors.RedisError(err));
                return;
            }

            next();
        });
    });
}


function savewait(req, res, next) {
    var retry = backoff.exponential({
        initialDelay: 1, // ms
        maxDelay: 1024 // ms
    });

    retry.failAfter(20); // ~10 seconds

    function callback(err, res) {
        if (err || res === req.lastsave) {
            retry.backoff();
        } else {
            next();
        }
    }

    retry.on('ready', function () {
        req.redis.lastsave(callback);
    });

    retry.on('fail', function () {
        next(new errors.SaveTimedOutError());
        return;
    });

    req.redis.lastsave(callback);
}


function senddb(req, res, next) {
    req.redis.config('get', 'dir', function (err, dirname) {
        req.redis.config('get', 'dbfilename', function (err, basename) {
            var dbPath = dirname[1] + '/' + basename[1];
            var stream = fs.createReadStream(dbPath);
            stream.pipe(res);
            stream.once('end', function () {
                res.send(201);
                next();
            });
        });
    });
}

module.exports = {
    createServer: createServer
};
