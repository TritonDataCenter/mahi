/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright (c) 2014, Joyent, Inc.
 */

var apertureConfig = require('aperture-config').config;
var bunyan = require('bunyan');
var dashdash = require('dashdash');
var path = require('path');

var Redis = require('../redis.js');
var ChangeLogReader = require('./change_log_reader.js');
var Transform = require('./transform.js');
var Server = require('./server.js');


var options = [
    {
        names: ['help', 'h'],
        type: 'bool',
        help: 'Print this help and exit.'
    },
    {
        names: ['config', 'c'],
        type: 'string',
        env: 'MAHI_CONFIG',
        helpArg: 'PATH',
        default: path.resolve(__dirname, '../../etc/mahi.json'),
        help: 'configuration file with ufds and redis config settings'
    },
    {
        names: ['aperture'],
        type: 'string',
        env: 'MAHI_APERTURE_PATH',
        helpArg: 'PATH',
        help: 'configuration file for aperture'
    },
    {
        names: ['ufds-url'],
        type: 'string',
        env: 'MAHI_UFDS_URL',
        helpArg: 'URL',
        help: 'ufds url (overrides config)'
    },
    {
        names: ['redis-host'],
        type: 'string',
        env: 'MAHI_REDIS_HOST',
        helpArg: 'HOST',
        help: 'redis host (overrides config)'
    },
    {
        names: ['redis-port'],
        type: 'number',
        env: 'MAHI_REDIS_PORT',
        helpArg: 'PORT',
        help: 'redis port (overrides config)'
    }
];

function main() {
    var parser = dashdash.createParser({options: options});
    var opts;
    try {
        opts = parser.parse(process.argv);
    } catch (e) {
        console.error('error: %s', e.message);
        process.exit(1);
    }

    if (opts.help) {
        var help = parser.help().trimRight();
        console.log('usage: \n' + help);
        process.exit(0);
    }

    /*
     * Dynamic config loading: These requires use runtime-resolved paths
     * from CLI arguments and cannot be hoisted to module top.
     */
    var config = require(path.resolve(opts.config));
    var typeTable = opts.aperture ?
        require(path.resolve(opts.aperture)).typeTable :
        apertureConfig.typeTable;
    var ufdsConfig = config.ufds;
    var redisConfig = config.redis;
    var replicatorConfig = config.replicator || {};

    var log = bunyan.createLogger({
        name: 'authcache-replicator',
        level: process.env.LOG_LEVEL || 'info'
    });

    ufdsConfig.url = opts['ufds-url'] || ufdsConfig.url;
    redisConfig.host = opts['redis-host'] || redisConfig.host;
    redisConfig.port = opts['redis-port'] || redisConfig.port;

    redisConfig.log = log;
    Redis.createClient(redisConfig, function (err, redis) {
        if (err) {
            log.fatal({err: err}, 'error creating redis client');
            process.exit(1);
        }
        setupRedis(redis, redisConfig, function (err) {
            if (err) {
                log.fatal({err: err}, 'error setting up redis');
                process.exit(1);
            }

            redis.get('changenumber', function (err, changenumber) {
                if (err) {
                    log.fatal({err: err},
                        'error getting changenumber from redis');
                    process.exit(1);
                }

                redis.set('virgin', 'true', function (err) {
                    if (err) {
                        log.fatal({err: err}, 'error setting virgin flag');
                        process.exit(1);
                    }

                    changenumber = parseInt(changenumber, 10);

                    var reader = new ChangeLogReader({
                        log: log,
                        ufds: ufdsConfig,
                        changenumber: changenumber || 0
                    });

                    var transform = new Transform({
                        log: log,
                        redis: redis,
                        typeTable: typeTable
                    });

                    var server = Server.createServer({
                        log: log,
                        redis: redis,
                        reader: reader,
                        transform: transform
                    });

                    server.listen(replicatorConfig.port || 8080);

                    reader.once('fresh', function onFresh() {
                        redis.del('virgin', function delVirgin(err) {
                            if (err) {
                                log.error({err: err},
                                    'error removing virgin flag');
                                return;
                            }
                            log.info('virgin flag removed');
                        });
                    });

                    reader.pipe(transform);
                });
            });
        });
    });
}

function setupRedis(redis, redisConfig, cb) {
    redis.select(redisConfig.db || 0, cb);
}

if (require.main === module) {
    main();
}
