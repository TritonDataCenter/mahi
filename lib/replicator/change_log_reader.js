/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright (c) 2014, Joyent, Inc.
 */

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

    var client = ldap.createClient({
        connectTimeout: opts.ufds.connectTimeout || 4000,
        reconnect: true,
        disableQueue: true,
        log: opts.ufds.log || this.log,
        tlsOptions: opts.ufds.tlsOptions,
        url: opts.ufds.url,
        bindDN: opts.ufds.bindDN,
        bindCredentials: opts.ufds.bindCredentials
    });
    this.client = client;
    var log = self.log;

    client.on('connect', function () {
        log.info('ufds: connected, starting poll');
        // Start running once connected
        self.polling = false;
        self._poll();
    });

    client.on('close', function () {
        log.warn('ufds: disconnected');
    });

    client.on('connectError', function (err) {
        log.info({err: err}, 'ufds: connection attempt failed');
    });

    client.on('error', function (err) {
        log.error(err, 'ldap client: had error');
    });
}
util.inherits(ChangeLogStream, Readable);
module.exports = ChangeLogStream;


ChangeLogStream.prototype.close = function close() {
    this.log.debug('close: entered');
    clearTimeout(this.timer);

    if (this.dead) {
        setImmediate(this.emit.bind(this, 'close'));
        return;
    }

    this.dead = true;
    this.client.destroy();
    this.push(null);
    this.emit('close');

    this.log.debug('close: done');
};


ChangeLogStream.prototype._read = function _read() {
    this._poll();
};


ChangeLogStream.prototype._poll = function _poll() {
    clearTimeout(this.timer);
    if (!this.client.connected || this.polling) {
        return;
    }

    var log = this.log;
    var opts = {
        scope: 'sub',
        filter: sprintf(FILTER, this.changenumber + 1),
        sizeLimit: 1000
    };
    var timeouts = 0;
    var result;
    var self = this;
    var timer = setTimeout(function onTimeout() {
        if (self.dead) {
            return;
        }

        ++timeouts;
        var level = timeouts > 3 ? 'error' : 'warn';
        log[level]('_poll: ldap_search timeout');
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
            timeouts = 0;
            log.error(err, '_poll: ldap_search failed (start)');
            self.polling = false;
            self.timer = setTimeout(self._poll.bind(self), self.interval);
            return;
        }

        var found = false;

        res.once('error', function onSearchError(err2) {
            clearTimeout(timer);
            timeouts = 0;
            log.error(err2, '_poll: ldap_search failed');
            self.polling = false;
            self.timer = setTimeout(self._poll.bind(self), self.interval);
        });

        res.on('searchEntry', function onEntry(entry) {
            clearTimeout(timer);
            timeouts = 0;
            log.info({
                entry: entry.object
            }, '_poll: ldap_search: entry received');

            found = true;
            var changenumber = parseInt(entry.object.changenumber, 10);
            if (changenumber > self.changenumber) {
                self.changenumber = changenumber;
            } else {
                log.fatal('_poll: changenumber out of order. ' +
                    'expected changenumber > %s, but got %s',
                    self.changenumber, changenumber);
                process.exit(1);
            }

            // If the stream applied backpressure just abandon this request
            // and wait for _read to be called to initiate more
            if (!self.push(entry.object)) {
                self.polling = false;
                res.removeAllListeners();
            }
        });

        res.once('end', function onEnd(stats) {
            clearTimeout(timer);
            timeouts = 0;
            log.debug({
                status: stats.status
            }, '_poll: done, setting timer');
            self.polling = false;
            self.timer = setTimeout(self._poll.bind(self), self.interval);
            if (!found) {
                // emit 'fresh' when we poll and find no new entries
                // this is helpful to know when we are caught up
                self.emit('fresh');
            } else {
                // if we found new entries, there may be more
                self._poll();
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
    var dashdash = require('dashdash');
    var path = require('path');

    var options = [
        {
            names: ['help', 'h'],
            type: 'bool',
            help: 'Print this help and exit.'
        },
        {
            names: ['config', 'f'],
            type: 'string',
            env: 'MAHI_CONFIG',
            helpArg: 'PATH',
            default: path.resolve(__dirname, '../../etc/mahi.json'),
            help: 'configuration file with ufds and redis config settings'
        },
        {
            names: ['changenumber', 'c'],
            type: 'number',
            helpArg: 'CHANGENUMBER',
            default: 0,
            help: 'changenumber to start at'
        },
        {
            names: ['poll', 'p'],
            type: 'bool',
            help: 'continue polling after no new entries are found'
        },
        {
            names: ['ufds-url'],
            type: 'string',
            env: 'MAHI_UFDS_URL',
            helpArg: 'URL',
            help: 'ufds url (overrides config)'
        }
    ];

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

    var config = require(path.resolve(opts.config));
    var ufdsConfig = config.ufds || {
        bindDN: 'cn=root',
        bindCredentials: 'secret',
        interval: 5000,
        maxConnections: 1,
        log: log,
        tlsOptions: {
            rejectUnauthorized: false
        },
        url: 'ldap://localhost:1389'
    };

    ufdsConfig.url = opts['ufds-url'] || ufdsConfig.url;

    var log = bunyan.createLogger({
        level: process.env.LOG_LEVEL || 'info',
        name: 'changelog_test',
        stream: process.stdout,
        src: true
    });

    var stream = new ChangeLogStream({
        log: log,
        ufds: ufdsConfig,
        changenumber: opts.changenumber
    });

    stream.on('data', function (obj) {
        console.log(JSON.stringify(obj));
    });

    stream.on('fresh', function () {
        if (opts.poll) {
            console.warn('no new entries (CTRL+C to exit)');
        } else {
            process.exit(0);
        }
    });
}

if (require.main === module) {
    test();
}
