// Copyright (c) 2014, Joyent, Inc. All rights reserved.

var assert = require('assert-plus');
var Backoff = require('backoff');
var vasync = require('vasync');

function onBackoff(name, number, delay) {
        var level = 'warn';
        if (number > 5) {
            level = 'error';
        }
        this.log[level]('%s: retry attempt %s in %s ms', name, number, delay);
}



function Poller(opts) {
    assert.object(opts, 'opts');
    assert.object(opts.changelogReader, 'changelogReader');
    assert.object(opts.log, 'log');
    assert.object(opts.redis, 'redis');
    assert.object(opts.transformer, 'transformer');

    var self = this;
    self.redis = opts.redis;
    self.transformer = opts.transformer;
    self.changes = opts.changelogReader;
    self.changenumber = 0;
}

Poller.prototype.setup = function setup(cb) {
    var self = this;
    var virgin = false;

    // assess state of redis
    vasync.parallel({funcs: [
        function checkFlag(parallelcb) {
            // the virgin flag is checked by the registrar healthchecker
            // to determine whether this mahi is ready to serve requests
            self.redis.get('virgin', function gotVirgin(err, res) {
                if (err) {
                    self.log.error({err: err}, 'redis error');
                    parallelcb(err);
                    return;
                }
                if (res) {
                    self.log.info(res, 'redis virgin flag is set');
                    virgin = true;
                }
                parallelcb();
            });
        },
        function getChangenumber(parallelcb) {
            self.redis.get('changenumber', function gotChangenumber(err, res) {
                if (err) {
                    self.log.fatal({err: err}, 'redis error');
                    parallelcb(err);
                    return;
                }

                if (!res) {
                    self.log.info('no changenumber in redis');
                    virgin = true;
                    self.redis.set('virgin', 'true', function setVirgin(err) {
                        if (err) {
                            self.log.fatal({err: err}, 'redis error');
                            parallelcb(err);
                            return;
                        }
                        self.log.info('set virgin flag in redis');
                        parallelcb();
                        return;
                    });
                } else {
                    self.changenumber = +res;
                    parallelcb();
                    return;
                }
            });
        }
    ]}, function parallelEnd(err) {
        if (err) {
            self.log.error({err: err}, 'error getting redis state');
            cb(err);
            return;
        }

        self.log.info({
            changenumber: self.changenumber,
            virgin: virgin
        }, 'redis state');

        if (virgin) {
            self.poller.once('fresh', function onFresh() {
                self.log.info({
                    changenumber: self.changenumber,
                }, 'cache caught up, removing virgin flag');

                var backoff = Backoff.exponential({
                    randomisationFactor: 0,
                    initialDelay: 10,
                    maxDelay: 3000
                });

                function delVirgin(err) {
                    if (err) {
                        self.log.error({
                            err: err
                        }, 'error removing virgin flag');
                        backoff.backoff();
                        return;
                    }
                    self.log.info('virgin flag removed');
                }

                backoff.on('ready', function () {
                    self.redis.del('virgin', delVirgin);
                });

                backoff.on('backoff', onBackoff.bind(self, 'delVirgin'));

                self.redis.del('virgin', delVirgin);
            });
        }

        cb();
    });
};

Poller.prototype.start = function start() {
    var self = this;

    function transform(err, entry) {
        assert.object(entry, 'entry');

        var changes = JSON.parse(entry.changes);
        var batch = self.redis.multi();
        var transformBackoff = Backoff.exponential({
            randomisationFactor: 0,
            initialDelay: 10,
            maxDelay: 3000
        });

        function transformed(err) {
            if (err) {
                self.log.error({
                    err: err,
                    batch: batch.queue
                }, 'transform error');
                transformBackoff.backoff();
                return;
            }

            var batchBackoff = Backoff.exponential({
                randomisationFactor: 0,
                initialDelay: 10,
                maxDelay: 3000
            });
            var newchangenumber = +entry.changenumber;

            function onExec(rediserr) {
                if (err) {
                    self.log.error({
                        err: rediserr,
                        batch: batch.queue
                    }, 'error executing batch');
                    batchBackoff.backoff();
                    return;
                }
                self.log.info('batch executed');
                self.poller.getNextChange(transform);
            }

            if (self.changenumber < newchangenumber) {
                self.log.info('updating changenumber to %s', newchangenumber);
                self.changenumber = newchangenumber;
                batch.set('changenumber', self.changenumber);
            } else {
                self.log.info('no changenumber update');
            }

            self.log.info({batch: batch.queue}, 'executing batch');

            batchBackoff.on('ready', function () {
                batch.exec(onExec);
            });
            batchBackoff.on('backoff', onBackoff.bind(self, 'batchExec'));
            batch.exec(onExec);
        }

        self.log.info({entry: entry}, 'got entry');
        self.log.info({changes: changes}, 'got changes');

        transformBackoff.on('ready', function () {
            // this function modifies `batch` as a side effect
            self.transformer.transform({
                batch: batch,
                changes: changes,
                entry: entry
            }, transformed);
        });

        transformBackoff.on('backoff', onBackoff.bind(self, 'transform'));

        // this function modifies `batch` as a side effect
        self.transformer.transform({
            batch: batch,
            changes: changes,
            entry: entry
        }, transformed);
    }

    self.changes.getNextChange(transform);
};
