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
util.inherits(Mahi, events.EventEmitter);


Mahi.prototype.poll = function () {
    var self = this;

    function transform(err, entry) {
        assert.object(entry, 'entry');

        var changes = JSON.parse(entry.changes);
        self.log.info({entry: entry}, 'got entry');
        self.log.info({changes: JSON.parse(entry.changes)}, 'got changes');

        /*
        if (!self.shouldTransformEntry(entry, changes)) {
            self.poller.getNextChange(transform);
            return;
        }
        */

        vasync.pipeline({
            funcs: [
                function toRedis(_, cb) {
                    self.transformer.transform({
                        entry: entry,
                        changes: changes
                    }, function transformed(err) {
                        if (err) {
                            cb(err);
                            return;
                        }
                        cb();
                    });
                },
                function updateChangenumber(_, cb) {
                    self.updateChangenumber(+entry.changenumber,
                        function updated(err) {

                        if (err) {
                            cb(err);
                            return;
                        }
                        cb();
                    });
                }
            ]
        }, function pipelineEnd(err) {
            if (err) {
                throw err; // TODO don't throw
            }
            self.poller.getNextChange(transform);
        });
    }

    self.poller.getNextChange(transform);
};


Mahi.prototype.updateChangenumber = function (changenumber, cb) {
    assert.number(changenumber, 'changenumber');
    assert.func(cb, 'callback');

    var self = this;

    self.log.info({
        'self.changenumber': self.changenumber,
        changenumber: changenumber
    }, 'updateChangenumber: entering');

    if (self.changenumber < changenumber) {
        self.changenumber = changenumber;
        self.log.info('updating changenumber to %s', self.changenumber);

        self.redis.set('changenumber', self.changenumber, function (err) {
            self.redisErrHandler(err);
            cb(err);
        });
    } else {
        self.log.info('no changenumber update');
        cb();
    }
};


Mahi.prototype.redisErrHandler = function (err) {
    var self = this;
    if (err) {
        self.log.error({err: err}, 'redis error');
        self.emit('error', err);
    }
};


Mahi.prototype.shouldTransformEntry = function (entry, changes) {
    assert.object(entry, 'entry');
    assert.object(changes, 'changes');

    var self = this;

    var targetdn = ldap.parseDN(entry.targetdn);
    var shouldTransform = false;

    // dn has to match
    if (targetdn.childOf(USER_DN) || targetdn.childOf(GROUP_DN)) {
        self.log.info({
            entryObject: entry
        }, 'dn matches');
        // object class has to match if exists
        var objectclass;
        if (changes && changes.objectclass) {
            objectclass = changes.objectclass[0];
            if (objectclass === 'sdcperson' ||
                objectclass === 'sdckey' ||
                objectclass === 'groupofuniquenames') {
                self.log.info({
                    targetdn: targetdn,
                    changenumber: entry.changenumber
                }, 'pushing entry');
                shouldTransform = true;
            }
        } else if (targetdn.childOf(GROUP_DN) &&
                   entry.changetype === 'modify') {
            // Only care about mods of groups as that indicates add/rm
            // user from the group. Only check objectclass once we're
            // sure we have a mod entry
            objectclass = JSON.parse(entry.entry).objectclass[0];
            if (objectclass === 'groupofuniquenames') {
                self.log.info({
                    targetdn: targetdn,
                    changenumber: entry.changenumber
                }, 'pushing group mod entry');
                shouldTransform = true;
            }
        } else if (targetdn.childOf(USER_DN) &&
                   entry.changetype === 'modify') {
            self.log.info({
                targetdn: targetdn,
                changenumber: entry.changenumber
            }, 'got user mod entry');

            // MANTA-1289 We want user modify entries if the entry
            // contains the approved_for_provisioning field. We ignore
            // all other fields.
            // example changes: [
            //    {
            //        "operation": "add",
            //        "modification": {
            //            "type": "approved_for_provisioning",
            //            "vals": [
            //                "true"
            //            ]
            //        }
            //    }
            //]

            // MANTA-1508 we also want to capture user mod entries for when the
            // login changes

            self.log.info({
                targetdn: targetdn,
                changenumber: entry.changenumber
            }, 'pushing user mod entry');
            shouldTransform = true;
        }
    }

    return (shouldTransform);
};

