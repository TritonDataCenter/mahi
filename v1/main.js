/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright (c) 2014, Joyent, Inc.
 */

/*
 * Main entry-point for the auth cache.
 */
var bunyan = require('bunyan');
var fs = require('fs');
var optimist = require('optimist');
var AuthCache = require('./lib/index');


var ARGV = optimist.options({
    'd': {
        alias: 'debug',
        describe: 'debug level'
    },
    'f': {
        alias: 'file',
        demand: true,
        describe: 'configuration file'
    }
}).argv;

var CFG;

var LOG = bunyan.createLogger({
    level: ARGV.d ? (ARGV.d > 1 ? 'trace' : 'debug') : 'info',
    name: 'auth-cache',
    serializers: {
        err: bunyan.stdSerializers.err
    },
    src: ARGV.d ? true : false
});

function readConfig() {
    if (!CFG) {
        CFG = JSON.parse(fs.readFileSync(ARGV.f, 'utf8'));
        LOG.info({config: CFG, file: ARGV.f}, 'Configuration loaded');
    }

    return (CFG);
}

var cfg = readConfig();

cfg.log = LOG;
cfg.redisCfg.log = LOG;

var authCache = AuthCache.createAuthCache(cfg);

process.on('uncaughtException', function (err) {
    LOG.fatal({err: err}, 'uncaughtException (exiting error code 1)');
    process.exit(1);
});
