// Copyright (c) 2014, Joyent, Inc. All rights reserved.

var bunyan = require('bunyan');
var dashdash = require('dashdash');
var path = require('path');

var Redis = require('../redis.js');
var ChangeLogReader = require('./change_log_reader.js');
var Transform = require('./transform.js');
var RedisWriter = require('./redis_writer.js');


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
        default: path.resolve(__dirname, '../../etc/aperture.json'),
        help: 'configuration file for aperture'
    },
    {
        names: ['ufds-url'],
        type: 'string',
        env: 'MAHI_UFDS_URL',
        helpArg: 'URL',
        help: 'ufds url (overrides config if specified)'
    },
    {
        names: ['redis-host'],
        type: 'string',
        env: 'MAHI_REDIS_HOST',
        helpArg: 'HOST',
        help: 'redis host (overrides config if specified)'
    },
    {
        names: ['redis-port'],
        type: 'number',
        env: 'MAHI_REDIS_PORT',
        helpArg: 'PORT',
        help: 'redis port (overrides config if specified)'
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
        var help = parser.help({includeEnv: true}).trimRight();
        console.log('usage: \n' + help);
        process.exit(0);
    }

    var config = require(path.resolve(opts.config));
    var apertureConfig = require(path.resolve(opts.aperture));
    var ufdsConfig = config.ufds;
    var redisConfig = config.redis;

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

        redis.get('changenumber', function (err, changenumber) {
            if (err) {
                log.fatal({err: err}, 'error getting changenumber from redis');
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
                typeTable: apertureConfig.typeTable
            });

            var writer = new RedisWriter({
                log: log,
                redis: redis
            });

            reader.pipe(transform).pipe(writer);
        });
    });
}

if (require.main === module) {
    main();
}
