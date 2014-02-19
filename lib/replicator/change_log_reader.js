// Copyright (c) 2014, Joyent, Inc. All rights reserved.

var Readable = require('stream').Readable;
var util = require('util');

var assert = require('assert-plus');
var ldap = require('ldapjs');



///--- Globals

var sprintf = util.format;

var CHANGELOG_DN = 'cn=changelog';
var FILTER = '(&(changenumber>=%d)' +
    '(|(targetdn=*ou=users*)' +
    '(targetdn=*ou=groups*))' +
    '(!(targetdn=vm*))' +
    '(!(targetdn=amon*))' +
    ')';



///--- API

function ChangeLogStream(opts) {
    assert.object(opts, 'opts');
    assert.object(opts.log, 'opts.log');
    assert.object(opts.ufds, 'opts.ufds');
    assert.number(opts.ufds.interval, 'opts.ufds.interval');
    assert.optionalNumber(opts.ufds.timeout, 'opts.ufds.timeout');
    assert.optionalNumber(opts.changenumber, 'opts.changenumber');

    var self = this;

    Readable.call(this, {
        objectMode: true
    });

    this.log = opts.log.child({component: 'ChangeLogReader'}, true);

    this.changenumber = opts.changenumber || 0;
    this.interval = opts.ufds.interval;
    this.timeout = opts.ufds.timeout || this.interval / 2;
    this.polling = true; // don't poll until client is connected

    var ldap_opts = {
        bindDN: opts.ufds.bindDN,
        bindCredentials: opts.ufds.bindCredentials,
        connectTimeout: opts.ufds.connectTimeout || 4000,
        log: opts.ufds.log || this.log,
        tlsOptions: {
            rejectUnauthorized: false
        },
        url: opts.ufds.url
    };

    var in_error = false;
    var log = self.log;

    function connect() {

        function onConnectError(err) {
            self.client.removeListener('connect', onConnect);
            if (self.dead) {
                return;
            }

            if (!in_error) {
                log.error(err, 'unable to connect to UFDS');
            }

            in_error = true;
            self.client.removeAllListeners('close');
            self.client = null;
            clearTimeout(self.timer);
            setTimeout(connect, 1000);
        }

        function onConnect() {
            self.client.removeListener('error', onConnectError);
            if (self.dead) {
                self.client.unbind(function () {});
                return;
            }

            var dn = ldap_opts.bindDN;
            var pw = ldap_opts.bindCredentials;

            self.client.bind(dn, pw, function onBind(err) {
                if (err) {
                    log.fatal(err, 'unable to bind to UFDS');
                    self.emit('error', err);
                    return;
                }

                // Setup reconnection logic
                self.client.on('error', function onError(err) {
                    if (self.dead) {
                        return;
                    }

                    log.error(err, 'ldap client: had error');
                    self.client.removeAllListeners('close');
                    self.client = null;
                    clearTimeout(self.timer);
                    setTimeout(connect, 1000);
                });

                self.client.on('close', function onClose() {
                    if (self.dead) {
                        return;
                    }

                    self.client.removeAllListeners('error');
                    self.client = null;
                    clearTimeout(self.timer);
                    setTimeout(connect, 1000);
                });

                log.debug('ufds: connected and bound; starting poll');
                self.polling = false;
                self._poll();
            });
        }

        self.client = ldap.createClient(ldap_opts);
        self.client.once('error', onConnectError);
        self.client.once('connect', onConnect);
    }

    connect();
}
util.inherits(ChangeLogStream, Readable);
module.exports = ChangeLogStream;


ChangeLogStream.prototype.close = function close() {
    var log = this.log;
    var self = this;

    log.debug('close: entered');
    clearTimeout(this.timer);
    this.dead = true;

    if (!this.client) {
        setImmediate(this.emit.bind(this, 'close'));
        return;
    }

    this.client.unbind(function (err) {
        if (err) {
            log.debug(err, 'close: failed');
            self.emit('error', err);
            return;
        }

        log.debug('close: done');
        self.push(null);
        self.emit('close');
    });
};


ChangeLogStream.prototype._read = function _read() {
    this._poll();
};


ChangeLogStream.prototype._poll = function _poll() {
    clearTimeout(this.timer);
    if (!this.client || this.polling) {
        return;
    }

    var log = this.log;
    var opts = {
        scope: 'sub',
        filter: sprintf(FILTER, this.changenumber + 1),
        sizeLimit: 1000
    };
    var result;
    var self = this;
    var timer = setTimeout(function onTimeout() {
        if (self.dead) {
            return;
        }

        log.error('_poll: ldap_search timeout');
        if (result) {
            result.removeAllListeners('end');
            result.removeAllListeners('searchEntry');
        }

        self.timer = setTimeout(self._poll.bind(self), self.interval);
    }, this.timeout);

    log.debug('_poll: entered');

    this.polling = true;
    this.client.search(CHANGELOG_DN, opts, function onSearch(err, res) {
        if (err) {
            clearTimeout(timer);
            log.error(err, '_poll: ldap_search failed (start)');
            self.polling = false;
            self.timer = setTimeout(self._poll.bind(self), self.interval);
            return;
        }

        var found = false;

        res.once('error', function onSearchError(err2) {
            clearTimeout(timer);
            log.error(err2, '_poll: ldap_search failed');
            self.polling = false;
            self.timer = setTimeout(self._poll.bind(self), self.interval);
        });

        res.on('searchEntry', function onEntry(entry) {
            clearTimeout(timer);
            log.debug({
                entry: entry.object
            }, '_poll: ldap_search: entry received');

            found = true;
            var changenumber = parseInt(entry.object.changenumber, 10);
            if (changenumber > self.changenumber) {
                self.changenumber = changenumber;
            }

            // If the stream applied backpressure just abandon this request
            // and wait for _read to be called to initiate more
            if (!self.push(entry.object)) {
                res.removeAllListeners();
            }
        });

        res.once('end', function onEnd(stats) {
            clearTimeout(timer);
            log.debug({
                status: stats.status
            }, '_poll: done, setting timer');
            self.polling = false;
            self.timer = setTimeout(self._poll.bind(self), self.interval);
            if (!found) {
                // emit 'fresh' when we poll and find no new entries
                // this is helpful to know when we are caught up
                self.emit('fresh');
            }
        });
    });
};


ChangeLogStream.prototype.toString = function toString() {
    var str = '[object ChangeLogStream <';
    str += 'changenumber=' + this.changenumber + ', ';
    str += 'interval=' + this.interval + ', ';
    str += 'url=' + this.client.url;
    str += '>]';

    return (str);
};



///--- Tests

function test() {
    var bunyan = require('bunyan');

    var log = bunyan.createLogger({
        level: process.env.LOG_LEVEL || 'info',
        name: 'changelog_test',
        stream: process.stdout,
        src: true
    });

    var stream = new ChangeLogStream({
        log: log,
        ufds: {
            bindDN: 'cn=root',
            bindCredentials: 'secret',
            interval: 5000,
            maxConnections: 1,
            log: log,
            tlsOptions: {
                rejectUnauthorized: false
            },
            url: 'ldap://localhost:1389'
        }
    });

    stream.on('data', function (obj) {
        console.log(obj);
    });

    stream.on('end', function () {
        console.log('done');
    });

    setTimeout(stream.close.bind(stream), 2000);
}

if (require.main === module) {
    test();
}
