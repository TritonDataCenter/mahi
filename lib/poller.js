// Copyright (c) 2013, Joyent, Inc. All rights reserved.

var assert = require('assert-plus');
var ldap = require('ldapjs');
var util = require('util');
var sprintf = util.format;

var CHANGELOG = 'cn=changelog';
/* JSSTYLED */
var FILTER = '(&(changenumber>=%d)(|(targetdn=*ou=users*)(targetdn=*ou=groups*))(!(targetdn=vm*))(!(targetdn=amon*)))';

module.exports = {
    Poller: Poller
};


/*
 * emit('fresh') when a poll to ufds returns with no new changes
 * emit('stale') when a poll to ufds returns with changes
 */
function Poller(options) {
    assert.object(options, 'options');
    assert.object(options.log, 'options.log');
    assert.object(options.ldapCfg, 'options.ldapCfg');
    assert.number(options.pollInterval, 'options.pollInterval');
    assert.optionslNumber(options.changenumber, 'options.changenumber');
    assert.optionalNumber(options.ldapCfg.timeout, 'options.ldapCfg.timeout');

    var self = this;
    var ldapCfg = options.ldapCfg;

    self.log = options.log;

    self.log.info('new auth cache with options', options);

    self.changenumber = options.changenumber || 0;
    self.entries = [];
    self.isPolling = false;
    self.pollInterval = options.pollInterval;
    self.timeout = options.ldapCfg.timeout || this.pollInterval / 2;

    self.ldapClient = ldap.createClient(ldapCfg);
    self.ldapClient.on('error', function onLdapErr(err) {
        self.log.error({err: err}, 'ldap client error');
    });

    self.log('ldap client instantiated');
}
util.inherits(Poller, util.EventEmitter);


/*
 * Fetches changelog entries from ufds and caches them in an array. Each time
 * getNextChange is called, the earliest change is returned in the callback.
 * If there are no more entries cached, the poller will poll ufds until changes
 * are found, and then it will return the earliest change in the callback.
 */
Poller.prototype.getNextChange = function (cb) {
    var self = this;

    function poll() {
        var pollId = setTimeout(poll, self.pollInterval);
        if (self.isPolling) {
            self.log.info('already polling, aborting poll');
            return;
        }
        self.isPolling = true;

        var start = +self.changenumber + 1; // ldap doesn't support > (only >=).
                                            // add 1 to make >= equivalent to >
        var filter = sprintf(FILTER, start); // search for changenumber >= start
        var limit = 1000;
        var ldapRes;
        var timeoutId = setTimeout(function onTimeout() {
            if (ldapRes) {
                self.log.info('removing all listeners from current search res');
                ldapRes.removeAllListeners();
            }
            self.log.error('ldap search timed out');
            self.isPolling = false;
        }, self.timeout);

        var opts = {
            scope: 'sub',
            filter: filter,
            sizeLimit: limit
        };

        self.log.info({
            dn: CHANGELOG,
            opts: opts
        }, 'searching ldap');

        self.ldapClient.search(CHANGELOG, opts, function searchRes(err, res) {
            ldapRes = res;
            clearTimeout(timeoutId);

            if (err) {
                self.log.error(err, 'error searching ldap');
                self.isPolling = false;
                return;
            }

            res.on('searchEntry', function onEntry(entry) {
                self.log.info({
                    targetdn: entry.object.targetdn,
                    changenumber: entry.object.changenumber,
                    changetype: entry.object.changetype
                }, 'got search entry');
            });

            res.once('error', function onError(ldapErr) {
                self.log.error({err: ldapErr},
                    'encountered ldap error, aborting current poll');
                self.log.info('removing all res.listeners');
                res.removeAllListeners();
                self.isPolling = false;
            });

            res.once('end', function onEnd(endRes) {
                self.log.info({
                    endResStatus: endRes.status,
                    matchedEntries: self.entries.length
                }, 'search ended.');

                self.isPolling = false;
                if (self.entries.length) {
                    clearTimeout(pollId);
                    self.entries.sort(function sort(a, b) {
                        // Sort so the latest change is at the front of the
                        // array. Then pop() gets changes in order.
                        return (+b.object.changenumber - +a.object.changenumber);
                    });

                    self.emit('stale');
                    cb(null, self.entries);
                } else {
                    // emit 'fresh' every time we poll and receive no new
                    // entries. Useful to know when you are fully caught up.
                    self.emit('fresh');
                }
            });

        });
    }

    if (self.entries.length) {
        // there are entries cached - do not poll
        self.log.info('queued entries', self.entries);
        cb(null, self.entries.pop());
    } else {
        // no entries left - start polling for changes
        self.log.info({pollInterval: self.pollInterval}, 'start polling');
        poll();
    }
};
