// Copyright (c) 2013, Joyent, Inc. All rights reserved.

var assert = require('assert-plus');
var ldap = require('ldapjs');
var util = require('util');
var events = require('events');
var sprintf = util.format;

var CHANGELOG = 'cn=changelog';
/* JSSTYLED */
var FILTER = '(&(changenumber>=%d)(|(targetdn=*ou=users*)(targetdn=*ou=groups*))(!(targetdn=vm*))(!(targetdn=amon*)))';


module.exports = {
    ChangelogReader: ChangelogReader
};


/*
 * emit('fresh') when a poll to ufds returns with no new changes
 * emit('stale') when a poll to ufds returns with changes
 */
function ChangelogReader(opts) {
    assert.object(opts, 'opts');
    assert.object(opts.log, 'opts.log');
    assert.object(opts.ldapCfg, 'opts.ldapCfg');
    assert.number(opts.pollInterval, 'opts.pollInterval');
    assert.optionalNumber(opts.changenumber, 'opts.changenumber');
    assert.optionalNumber(opts.ldapCfg.timeout, 'opts.ldapCfg.timeout');

    var self = this;
    var ldapCfg = opts.ldapCfg;

    self.log = opts.log.child({component: 'ChangelogReader'});

    self.log.info('new auth cache with options', opts);

    self.changenumber = opts.changenumber || 0;
    self.entries = [];
    self.isPolling = false;
    self.pollInterval = opts.pollInterval;
    self.timeout = opts.ldapCfg.timeout || this.pollInterval / 2;

    self.ldapClient = ldap.createClient(ldapCfg);
    self.ldapClient.on('error', function onLdapErr(err) {
        self.log.error({err: err}, 'ldap client error');
    });

    self.log.info('ldap client instantiated');
}
util.inherits(ChangelogReader, events.EventEmitter);


/*
 * Fetches changelog entries from ufds and caches them in an array. Each time
 * getNextChange is called, the earliest change is returned in the callback.
 * If there are no more entries cached, the poller will poll ufds until changes
 * are found, and then it will return the earliest change in the callback.
 *
 * cb: callback in the form f(err, entry)
 */
ChangelogReader.prototype.getNextChange = function (cb) {
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
                var changenumber = +entry.object.changenumber;
                self.entries.push(entry);
                if (changenumber > self.changenumber) {
                    self.changenumber = changenumber;
                }
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

                    // Entries returned come in increasing order by
                    // changenumber. Since we want to return them in the same
                    // order, reverse the array and pop.
                    // http://jsperf.com/queue-push-unshift-vs-shift-pop/3
                    self.entries.reverse();

                    // Emit 'stale' if we poll and receive new entries.
                    // Useful to know when you are behind.
                    self.emit('stale');
                    cb(null, self.entries.pop().object);
                } else {
                    // Emit 'fresh' every time we poll and receive no new
                    // entries. Useful to know when you are fully caught up.
                    self.emit('fresh');
                }
            });

        });
    }

    if (self.entries.length) {
        // there are entries cached - do not poll
        self.log.info('%s queued entries', self.entries.length);
        setImmediate(function () {
            cb(null, self.entries.pop().object);
        });
    } else {
        // no entries left - start polling for changes
        self.log.info({pollInterval: self.pollInterval}, 'start polling');
        poll();
    }
};


ChangelogReader.prototype.close = function (cb) {
    var self = this;
    self.removeAllListeners();
    self.ldapClient.unbind(cb);
};
