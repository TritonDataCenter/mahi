// Copyright (c) 2013, Joyent, Inc. All rights reserved.
var assert = require('assert-plus');
var events = require('events');
var ldap = require('ldapjs');
var util = require('util');
var vasync = require('vasync');

var redis = require('./redis.js');
var Poller = require('./poller.js').Poller;
var Transformer = require('./transformer.js').Transformer;

var USER_DN = 'ou=users, o=smartdc';
var GROUP_DN = 'ou=groups, o=smartdc';


module.exports = {
    Mahi: Mahi
};


function Mahi(opts) {
    assert.object(opts, 'opts');
    assert.object(opts.log, 'opts.log');
    assert.object(opts.ldapCfg, 'opts.ldapCfg');
    assert.object(opts.redisCfg, 'opts.redisCfg');
    assert.optionalNumber(opts.ldapCfg.timeout, 'opts.ldapCfg.timeout');
    assert.number(opts.pollInterval, 'opts.pollInterval');

    var self = this;
    var virgin = false;

    self.changenumber = 0;
    self.log = opts.log;
    self.poller = null;
    self.redis = null;
    self.transformer = null;

    opts.redisCfg.log = self.log;

    vasync.pipeline({funcs: [

        function createRedisClient(_, cb) {
            redis.createClient(opts.redisCfg, function makeRedis(err, client) {
                self.redisErrHandler(err);
                self.redis = client;
                self.log.info(opts.redisCfg, 'redis client created');
                cb();
            });
        },

        // assess state of redis
        function virginState(_, cb) {

            vasync.parallel({funcs: [
                function checkFlag(parallelcb) {
                    // the virgin flag is checked by the registrar healthchecker
                    // to determine whether this mahi is ready to serve requests
                    self.redis.get('virgin', function gotVirgin(err, res) {
                        self.redisErrHandler(err);
                        if (res) {
                            self.log.info(res, 'redis virgin flag is set');
                            virgin = true;
                        }
                        parallelcb();
                    });
                },
                function getChangenumber(parallelcb) {
                    self.redis.get('changenumber',
                        function gotChangenumber(err, res) {

                        self.redisErrHandler(err);
                        if (!res) {
                            self.log.info('no changenumber in redis');
                            virgin = true;
                            self.redis.set('virgin', 'true',
                                function setVirgin(err) {

                                self.redisErrHandler(err);
                                self.log.info('set virgin flag in redis');
                                parallelcb();
                            });
                        } else {
                            self.changenumber = +res;
                            parallelcb();
                        }
                    });
                }
            ]}, function parallelEnd(err) {
                if (err) {
                    cb(err);
                    return;
                }

                self.log.info({
                    changenumber: self.changenumber,
                    virgin: virgin,
                }, 'redis state');

                cb();
            });
        }

    ]}, function pipelineEnd(err) {
        if (err) {
            throw err; // TODO probably don't want to throw
        }

        self.poller = new Poller({
            log:  opts.log,
            ldapCfg: opts.ldapCfg,
            pollInterval: opts.pollInterval,
            changenumber: self.changenumber
        });

        self.transformer = new Transformer({
            redis: self.redis,
            log: self.log
        });

        if (virgin) {
            self.poller.once('fresh', function onFresh() {
                self.log.info({
                    changenumber: self.changenumber
                }, 'cache caught up, removing virgin flag');

                self.redis.del('virgin', function delVirgin(err) {
                    self.redisErrHandler(err);
                });
            });
        }

        self.poll();
    });
}


Mahi.prototype.poll = function () {
    var self = this;

    function transform(err, entry) {
        assert.object(entry, 'entry');

        var changes = JSON.parse(entry.changes);
        self.log.info({entry: entry}, 'got entry');
        self.log.info({changes: JSON.parse(entry.changes)}, 'got changes');

        self.transformer.transform({
            entry: entry,
            changes: changes
        }, function transformed(err, batch) {
            if (err) {
                self.log.error({
                    err: err,
                    batch: batch.queue
                }, 'transform error');
                // TODO retry? skip & continue? fatal?
                return;
            }

            var changenumber = +entry.changenumber;

            if (self.changenumber < changenumber) {
                self.log.info('updating changenumber to %s', changenumber);
                self.changenumber = changenumber;
                batch.set('changenumber', changenumber);
            } else {
                self.log.info('no changenumber update');
            }

            self.log.info({batch: batch.queue}, 'executing batch');

            batch.exec(function onExec(rediserr) {
                if (err) {
                    self.log.error({
                        err: rediserr,
                        batch: batch.queue
                    }, 'error executing batch');
                    // TODO retry? skip & continue? fatal?
                    return;
                }
                self.poller.getNextChange(transform);
            });
        });
    }

    self.poller.getNextChange(transform);
};
