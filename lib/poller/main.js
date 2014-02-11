// Copyright (c) 2014, Joyent, Inc. All rights reserved.

var Redis = require('../redis.js');
var ChangelogReader = require('./changelogreader.js').ChangelogReader;
var Poller = require('./poller.js').Poller;
var Transformer = require('./transformer.js').Transformer;

//TODO dash-dash this up

if (require.main === module) {
    (function () {
        var cfg = require('../../etc/laptop.config.json');
        var apertureOpts = require('../../etc/aperture.json');
        var ldapCfg = cfg.ldapCfg;
        var redisCfg = cfg.redisCfg;
        var log = require('bunyan').createLogger({
            name: 'authcache',
            level: 'info'
        });
        redisCfg.log = log;

        Redis.createClient(redisCfg, function (err, redis) {
            var changelogReader = new ChangelogReader({
                ldapCfg: ldapCfg,
                log: log,
                pollInterval: 2000
            });

            var transformer = new Transformer({
                log: log,
                redis: redis,
                typeTable: apertureOpts.typeTable
            });

            var poller = new Poller({
                log:  log,
                changelogReader: changelogReader,
                transformer: transformer,
                redis: redis
            });

            poller.setup(function (err) {
                if (err) {
                    log.fatal({err: err}, 'error during setup');
                    process.exit(1);
                }
                poller.start();
            });
        });
    }());
}
