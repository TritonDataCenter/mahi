// Copyright (c) 2013, Joyent, Inc. All rights reserved.
var assert = require('assert-plus');
var vasync = require('vasync');

var Redis = require('../redis.js');
var Poller = require('./jsonpoller.js').Poller;
var Transformer = require('./transformer.js').Transformer;

function main(opts) {
    assert.object(opts, 'opts');
    assert.object(opts.log, 'opts.log');
    assert.object(opts.ldapCfg, 'opts.ldapCfg');
    assert.object(opts.redisCfg, 'opts.redisCfg');
    assert.optionalNumber(opts.ldapCfg.timeout, 'opts.ldapCfg.timeout');
    assert.number(opts.pollInterval, 'opts.pollInterval');

    function transform(err, entry) {
        assert.object(entry, 'entry');

        var changes = JSON.parse(entry.changes);
        var batch = redis.multi();
        log.info({entry: entry}, 'got entry');
        log.info({changes: changes}, 'got changes');

        // this function modifies `batch` as a side effect
        transformer.transform({
            batch: batch,
            changes: changes,
            entry: entry
        }, function transformed(err) {
            if (err) {
                log.error({
                    err: err,
                    batch: batch.queue
                }, 'transform error');
                // TODO retry? skip & continue? fatal?
                return;
            }

            var newchangenumber = +entry.changenumber;

            if (changenumber < newchangenumber) {
                log.info('updating changenumber to %s', newchangenumber);
                changenumber = newchangenumber;
                batch.set('changenumber', changenumber);
            } else {
                log.info('no changenumber update');
            }

            log.info({batch: batch.queue}, 'executing batch');

            batch.exec(function onExec(rediserr) {
                if (err) {
                    log.error({
                        err: rediserr,
                        batch: batch.queue
                    }, 'error executing batch');
                    // TODO retry? skip & continue? fatal?
                    return;
                }
                log.info('batch executed');
                poller.getNextChange(transform);
            });
        });
    }


    var changenumber = 0;
    var log = opts.log;
    var poller = null;
    var redis = null;
    var transformer = null;
    var virgin = false;

    opts.redisCfg.log = log;

    vasync.pipeline({funcs: [

        function createRedisClient(_, cb) {
            Redis.createClient(opts.redisCfg, function makeRedis(err, client) {
                if (err) {
                    log.fatal({err: err}, 'redis error');
                    process.exit(1);
                }
                redis = client;
                log.info(opts.redisCfg, 'redis client created');
                cb();
            });
        },

        // assess state of redis
        function virginState(_, cb) {

            vasync.parallel({funcs: [
                function checkFlag(parallelcb) {
                    // the virgin flag is checked by the registrar healthchecker
                    // to determine whether this mahi is ready to serve requests
                    redis.get('virgin', function gotVirgin(err, res) {
                        if (err) {
                            log.fatal({err: err}, 'redis error');
                            process.exit(1);
                        }
                        if (res) {
                            log.info(res, 'redis virgin flag is set');
                            virgin = true;
                        }
                        parallelcb();
                    });
                },
                function getChangenumber(parallelcb) {
                    redis.get('changenumber',
                        function gotChangenumber(err, res) {

                        if (err) {
                            log.fatal({err: err}, 'redis error');
                            process.exit(1);
                        }

                        if (!res) {
                            log.info('no changenumber in redis');
                            virgin = true;
                            redis.set('virgin', 'true',
                                function setVirgin(err) {

                                if (err) {
                                    log.fatal({err: err}, 'redis error');
                                    process.exit(1);
                                }
                                log.info('set virgin flag in redis');
                                parallelcb();
                            });
                        } else {
                            changenumber = +res;
                            parallelcb();
                        }
                    });
                }
            ]}, function parallelEnd(err) {
                if (err) {
                    cb(err);
                    return;
                }

                log.info({
                    changenumber: changenumber,
                    virgin: virgin
                }, 'redis state');

                cb();
            });
        }

    ]}, function pipelineEnd(err) {
        if (err) {
            throw err; // TODO probably don't want to throw
        }

        poller = new Poller({
            log:  opts.log,
            ldapConfig: opts.ldapConfig,
            pollInterval: opts.pollInterval,
            changenumber: changenumber
        });

        transformer = new Transformer({
            redis: redis,
            log: log
        });

        if (virgin) {
            poller.once('fresh', function onFresh() {
                log.info({
                    changenumber: changenumber
                }, 'cache caught up, removing virgin flag');

                redis.del('virgin', function delVirgin(err) {
                    if (err) {
                        log.fatal({err: err}, 'redis error');
                        process.exit(1);
                    }
                });
            });
        }

        poller.getNextChange(transform);
    });
}


if (require.main === module) {
    var cfg = require('../../etc/laptop.config.json');
    var ldapCfg = cfg.ldapCfg;
    var redisCfg = cfg.redisCfg;
    var log = require('bunyan').createLogger({
        name: 'authcache-test',
        src: true,
        level: 'trace'
    });

    main({
        log: log,
        ldapCfg: ldapCfg,
        redisCfg: redisCfg,
        pollInterval: 2000
    });
}
