/*
 * Copyright (c) 2012, Joyent, Inc. All rights reserved.
 *
 * The authentication cache.
 */
var assert = require('assert-plus');
var EventEmitter = require('events').EventEmitter;
var ldap = require('ldapjs');
var parseDN = ldap.parseDN;
var redis = require('./redis');
var sprintf = require('util').format;
var util = require('util');
var vasync = require('vasync');

var CHANGELOG = 'cn=changelog';
var USER_DN = 'ou=users, o=smartdc';
var GROUP_DN = 'ou=groups, o=smartdc';

/**
 * Redis Schema:
 * login : {
 *     uuid,
 *     keys : {
 *         $fp: publickey
 *     },
 *     groups: {
 *         $groupname
 *     }
 * }
 */
function AuthCache(options) {
    assert.object(options, 'options');
    assert.object(options.log, 'options.log');
    assert.object(options.ldapCfg, 'options.ldapCfg');
    assert.optionalNumber(options.ldapCfg.timeout, 'options.ldapCfg.timeout');
    assert.number(options.pollInterval, 'options.pollInterval');

    EventEmitter.call(this);
    this.log = options.log;
    var ldapCfg = options.ldapCfg;
    var self = this;
    var log = self.log;

    log.info('new auth cache with options', options);

    /**
     * redis client
     */
    this.redisClient = null;

    /**
     * The interval to poll UFDS
     */
    this.pollInterval = options.pollInterval;

    /**
     * The latest consumed changenumber.
     */
    this.changenumber = 0;

    this.timeout = options.ldapCfg.timeout || this.pollInterval / 2;

    /**
     * ldap client
     */
    this.ldapClient = ldap.createClient(ldapCfg);

    /**
     * Flag used to control polling
     */
    this.isPolling = false;

    self.ldapClient.on('error', function(err) {
        log.error({err: err}, 'ldap client error');
    });

    log.info('ldap client instantiated');
    redis.createClient(options.redisCfg, function(err, redisClient) {
        redisErrHandler(self, err);
        self.redisClient = redisClient;
        self.redisClient.get('changenumber', function(err, res) {
            redisErrHandler(self, err);
            if (!res) {
                self.changenumber = 0;
            } else {
                self.changenumber = parseInt(res, 10);
            }

            log.info('created auth client', self);

            log.info({pollInterval: self.pollInterval}, 'start polling');
            setInterval(function(){ poll(self);}, self.pollInterval);
        });
    });
}

module.exports = AuthCache;
util.inherits(AuthCache, EventEmitter);

function poll(self) {
    var log = self.log;
    function pollOnceCb(err, gotEntries) {
        if (err) {
            log.error(err, 'Error when polling');
        }
        if (gotEntries) {
            // continue polling ldap if there were updates
            log.info('continue polling since there were records');
            pollOnce(self, pollOnceCb);
        } else {
            // otherwise stop polling
            log.info('stopping polling until next timeout');
            self.isPolling = false;
        }
    }
    if (self.isPolling) {
        log.info('already polling, aborting poll');
        return;
    } else {
        pollOnce(self, pollOnceCb);
    }
}

function pollOnce(self, cb) {
    var log = self.log;
    self.isPolling = true;

    // because ldap only supports >= and not >, we have to inflate the last cn
    // by 1 so we don't search for it.
    var start = parseInt(self.changenumber, 10) + 1;

    //The default size limit returned from ldap is 1000.  Variablifying it
    // so that we don't mess up the limit in the filter.  The reason that
    // we have a limit, plus the bounded filter is so that we won't miss
    // any data while iterating through the changelog.  Since the filter span
    // is 1000 and we're limiting what we can return to 1000, we're
    // guarenteed to have all rows that match the filter in the 1000 span
    // returned, even though we'll surely recieve less than 1000 rows back.
    // See MANTA-1448.
    var limit = 1000;

    /* JSSTYLED */
    var filter = sprintf('(&(changenumber>=%d)(changenumber<=%d)' +
                           '(|(targetdn=*ou=users*)' +
                             '(targetdn=*ou=groups*))' +
                           '(!(targetdn=vm*))' +
                           '(!(targetdn=amon*))' +
                         ')', start, start + limit - 1);

    var opts = {
        scope: 'sub',
        filter: filter,
        sizeLimit: limit
    };

    log.info({
        dn: CHANGELOG,
        opts: opts,
        changenumber: start
    }, 'searching ldap');

    var ldapRes = null;
    var timeoutId = setTimeout(function onTimeout() {
        if (ldapRes) {
            log.info('removing all listeners from current search res');
            ldapRes.removeAllListeners();
        }
        cb(new Error('ldap search timed out'));
    }, self.timeout);

    // start search
    self.ldapClient.search(CHANGELOG, opts, function(err, res) {
        ldapRes = res;
        clearTimeout(timeoutId);

        // return if unable to search ldap
        if (err) {
            cb(err);
            return;
        }

        var entries = [];
        var latestChangenumber = self.changenumber;
        var rawEntries = 0;

        // save the matching entries.
        res.on('searchEntry', function(entry) {
            log.info({
                targetdn: entry.object.targetdn,
                changenumber: entry.object.changenumber,
                changetype: entry.object.changetype
            }, 'got search entry');
            rawEntries++;

            // cache the cn if it's bigger, in case none of the entries match
            var changenumber = parseInt(entry.object.changenumber, 10);
            if (changenumber > latestChangenumber) {
                latestChangenumber = changenumber;
            }

            var changes = JSON.parse(entry.object.changes);
            if (shouldTransformEntry(entry, changes, log)) {
                entry.parsedChanges = changes;
                entry.self = self;
                entries.push(entry);
            }
        });

        res.once('error', function(err) {
            log.error({err: err},
                'encountered ldap error, aborting current poll');
            log.info('removing all res.listeners');
            res.removeAllListeners();
            cb(err);
        });

        res.once('end', function(endRes) {
            log.info({
                endResStatus: endRes.status,
                latestChangenumber: latestChangenumber,
                rawEntries: rawEntries,
                matchedEntries: entries.length
            }, 'search ended sorting entries');
            entries.sort(sort);

            //TODO: replace this with a sane var name. wtf is e?
            var e = 0;
            function updateNext() {
                var entry = entries[e];

                if (entry) {
                    log.info({
                        entryChangeNumber: entry.object.changenumber,
                        e: e,
                        entriesLength: entries.length
                    }, 'updating next entry');

                    updateEntry(entry, function (err) {
                        if (err) {
                            cb(err);
                            return;
                        }
                        var cnumber = parseInt(entry.object.changenumber, 10);
                        updateChangeNumber(self, cnumber, log, function (err) {
                            redisErrHandler(self, err);
                            if (err) {
                                cb(err);
                                return;
                            }
                            ++e;
                            updateNext();
                        });
                    });

                } else {
                    var lcn = latestChangenumber;
                    updateChangeNumber(self, lcn, log, function (err) {
                        redisErrHandler(self, err);
                        res.removeAllListeners();
                        cb(err, rawEntries);
                    });
                }
            }

            updateNext();
        });
    });
}

function updateChangeNumber(self, changenumber, log, cb) {
    log.info({
        cn: changenumber,
        currCn: self.changenumber
    }, 'updateChangenumber: entering');
    if (self.changenumber < changenumber) {
        self.changenumber = changenumber;
        log.info('updating cn to %s', self.changenumber);

        var client = self.redisClient;

        client.set('changenumber', self.changenumber, function onset(err) {
            redisErrHandler(self, err);
            cb(err);
        });
    } else {
        cb(null);
    }
}

function shouldTransformEntry(entry, changes, log) {
    var targetdn = parseDN(entry.object.targetdn);

    var shouldTransform = false;

    // dn has to match
    if (targetdn.childOf(USER_DN) || targetdn.childOf(GROUP_DN)) {
        log.info({
            entryObject: entry.object
        }, 'dn matches');
        // object class has to match if exists
        var objectclass;
        if (changes && changes.objectclass) {
            objectclass = changes.objectclass[0];
            if (objectclass === 'sdcperson' ||
                objectclass === 'sdckey' ||
                objectclass === 'groupofuniquenames') {
                log.info({
                    targetdn: targetdn,
                    changenumber: entry.object.changenumber
                }, 'pushing entry');
                shouldTransform = true;
            }
        } else if (targetdn.childOf(GROUP_DN) &&
                   entry.object.changetype === 'modify') {
            // Only care about mods of groups as that indicates add/rm
            // user from the group. Only check objectclass once we're
            // sure we have a mod entry
            objectclass = JSON.parse(entry.object.entry).objectclass[0];
            if (objectclass === 'groupofuniquenames') {
                log.info({
                    targetdn: targetdn,
                    changenumber: entry.object.changenumber
                }, 'pushing group mod entry');
                shouldTransform = true;
            }
        } else if (targetdn.childOf(USER_DN) &&
                   entry.object.changetype === 'modify') {
            log.info({
                targetdn: targetdn,
                changenumber: entry.object.changenumber
            }, 'got user mod entry');

            // MANTA-1289 We want user modify entries if the entry
            // contains the approved_for_provisioning field. We ignore
            // all other fields.
            // example changes: [
                //{
                    //"operation": "add",
                    //"modification": {
                        //"type": "approved_for_provisioning",
                        //"vals": [
                            //"true"
                        //]
                    //}
                //}
            //]

            // MANTA-1508 we also want to capture user mod entries for when the
            // login changes

            log.info({
                targetdn: targetdn,
                changenumber: entry.object.changenumber
            }, 'pushing user approved_for_provisioning mod entry');
            shouldTransform = true;
        }
    }

    return shouldTransform;
}

function updateEntry(entry, cb) {
    var self = entry.self;
    var log = self.log;
    var changetype = entry.object.changetype;

    var changenumber = entry.object.changenumber;
    log.info('parsing entry', changenumber);
    switch (changetype) {
    case 'add':
        add(self, entry.parsedChanges, entry, cb);
        break;
    case 'modify':
        // only for group changed_for_provisioning, and login updates
        // modifies don't contain the object class in the change field
        mod(self, entry.parsedChanges, entry, cb);
        break;
    case 'delete':
        del(self, entry.parsedChanges, entry, cb);
        break;
    default:
        cb(new Error('default case invoked.'));
        break;
    }
}

// only process objectclass=groupofuniquenames which is for groups
function mod(self, changes, entry, cb) {
    var log = self.log;

    var changeNum = 0;
    // use this function to atomically go through each change, instead of a
    // foreach loop
    function nextChange() {
        var change = changes[changeNum];

        if (!change) {
            log.info('no more mod changes, returning');
            cb();
            return;
        }

        function onReturn() {
            ++changeNum;
            nextChange();
        }

        log.info({
            changelog: change
        }, 'got modify changelog');
        // uniquemember is for groupofuniquenames
        if (change.modification.type === 'uniquemember') {
            var modNum = 0;
            function nextMod() {
                var userdn = change.modification.vals[modNum];

                if (!userdn) {
                    onReturn();
                    return;
                }

                function onModReturn() {
                    ++modNum;
                    nextMod();
                }

                var groupdn = entry.object.targetdn;
                switch (change.operation) {
                case 'add':
                    addGroupMember(self, userdn, groupdn, onModReturn);
                    break;
                case 'delete':
                    removeGroupMember(self, userdn, groupdn, onModReturn);
                    break;
                default:
                    cb(new Error('default case invoked'));
                    break;
                }
            }

            nextMod();

        } else if (change.modification.type === 'approved_for_provisioning') {
            // MANTA-1289
            // We want user modify entries if the entry contains the
            // approved_for_provisioning field. We ignore all other fields.
            switch (change.operation) {
            case 'add':
            case 'replace':
                updateApprovedForProvisioning(self, entry.object.targetdn,
                                              change.modification.vals,
                                              onReturn);
                break;
            case 'delete':
                updateApprovedForProvisioning(self, entry.object.targetdn,
                                              [false], onReturn);
                break;
            default:
                cb(new Error('default case invoked'));
                break;
            }
        } else if (change.modification.type === 'login') {
            // MANTA-1508 the login might change, so we need to update the
            // login entry, uuid entry, and the sets
            updateLogin(self, entry.object.targetdn,
                        change.modification.vals[0], onReturn);
        }
        else {
            // Nothing, so just invoke onReturn
            onReturn();
        }
    }

    nextChange();
}

function updateLogin(self, userdn, newLogin, cb) {
    assert.string(newLogin, 'newLogin');
    assert.string(userdn, 'userdn');
    assert.func(cb, 'cb');

    var log = self.log;
    var client = self.redisClient;
    var userUuid = userdn.substring(userdn.indexOf('=') + 1,
                                    userdn.indexOf(','));
    log.info({
        userdn: userdn,
        newLogin: newLogin
    }, 'auth_cache.updateLogin: entering');

    // get the old login from uuid
    var uuidKey = sprintf('/uuid/%s', userUuid);

    client.get(uuidKey, function(err, oldLogin) {
        redisErrHandler(self, err);
        if (err) {
            cb(err);
            return;
        }
        var oldLoginKey = sprintf('/login/%s', oldLogin);
        log.info({oldLoginKey: oldLoginKey}, 'getting user entry from redis');
        // get the login entry
        client.get(oldLoginKey, function(err, payload) {
            redisErrHandler(self, err);
            if (err) {
                cb(err);
                return;
            }

            log.info({oldLogin: oldLogin, newLogin: newLogin},
                     'updating login name');
            var newLoginKey = sprintf('/login/%s', newLogin);
            client.multi()
            .set(newLoginKey, payload)
            .set(uuidKey, newLogin)
            .sadd('login', newLogin)
            .del(oldLoginKey)
            .srem('login', oldLogin)
            .exec(function(err, replies) {
                redisErrHandler(self, err);
                log.info('finished updateLogin transaction');
                cb(err);
            });
        });
    });
}

function updateApprovedForProvisioning(self, userdn, value, cb) {
    var log = self.log;
    var client = self.redisClient;
    var userUuid = userdn.substring(userdn.indexOf('=') + 1,
                                    userdn.indexOf(','));
    log.info({
        userdn: userdn,
        value: value
    }, 'auth_cache.updateApprovedForProvisioning: entering');

    // get the login from uuid
    var loginKey = sprintf('/uuid/%s', userUuid);

    client.get(loginKey, function(err, login) {
        redisErrHandler(self, err);
        if (err) {
            cb(err);
            return;
        }
        log.info('result', login);
        var key = sprintf('/login/%s', login);

        client.get(key, function(err, payload) {
            redisErrHandler(self, err);
            if (err) {
                cb(err);
                return;
            }
            log.info({entry: payload}, 'got user entry from redis');
            payload = JSON.parse(payload);

            // false is serialized as a string, we want the boolean value
            // stored in redis
            if (value[0] === 'false') {
                value[0] = false;
            } else if (value[0] === 'true') {
                value[0] = true;
            }
            payload.approved_for_provisioning = value[0];
            payload = JSON.stringify(payload);
            log.info({
                user: login,
                entry: payload
            }, 'setting approved_for_provisioning');
            client.set(key, payload, function(err) {
                redisErrHandler(self, err);
                cb(err);
            });
        });
    });
}

function addGroupMember(self, userdn, groupdn, cb) {
    var log = self.log;

    var client = self.redisClient;
    var group = groupdn.substring(groupdn.indexOf('=') + 1,
                                  groupdn.indexOf(','));
    var userUuid = userdn.substring(userdn.indexOf('=') + 1,
                                    userdn.indexOf(','));
    log.info('adding user %s to group %s', userUuid, group);
    // get the login from uuid
    var loginKey = sprintf('/uuid/%s', userUuid);

    client.get(loginKey, function(err, login) {
        redisErrHandler(self, err);
        if (err) {
            cb(err);
            return;
        }
        log.info('result', login);
        var key = sprintf('/login/%s', login);

        client.get(key, function(err, payload) {
            redisErrHandler(self, err);
            if (err) {
                cb(err);
                return;
            }
            log.info({entry: payload}, 'got user entry from redis');
            payload = JSON.parse(payload);
            if (!payload.groups) {
                payload.groups = {};
            }

            payload.groups[group] = group;
            payload = JSON.stringify(payload);
            log.info({
                user: login,
                key: key,
                entry: payload
            }, 'adding group to user entry');
            client.set(key, payload, function(err) {
                redisErrHandler(self, err);
                cb(err);
            });
        });
    });
}

// remove a group member
function removeGroupMember(self, userdn, groupdn, cb) {
    var log = self.log;
    log.info('removing user %s from group %s', userdn, groupdn);
    var client = self.redisClient;
    var group = groupdn.substring(groupdn.indexOf('=') + 1,
                                  groupdn.indexOf(','));
    var userUuid = userdn.substring(userdn.indexOf('=') + 1,
                                    userdn.indexOf(','));
    // get the login from uuid
    var loginKey = sprintf('/uuid/%s', userUuid);
    log.info('getting login from uuid %s', loginKey);

    client.get(loginKey, function(err, login) {
        redisErrHandler(self, err);
        if (err) {
            cb(err);
            return;
        }
        log.info('got login %s from uuid %s', login, loginKey);
        var key = sprintf('/login/%s', login);

        client.get(key, function(err, payload) {
            redisErrHandler(self, err);
            if (err) {
                cb(err);
                return;
            }
            log.info({
                user: payload
            }, 'got user entry');
            payload = JSON.parse(payload);
            delete payload.groups[group];
            payload = JSON.stringify(payload);
            log.info({
                removedGroup: group,
                key: key,
                entry: payload
            }, 'removing group from user entry');
            client.set(key, payload, function(err) {
                redisErrHandler(self, err);
                cb(err);
            });
        });
    });
}

function add(self, changes, entry, cb) {
    var log = self.log;
    var objectclass = changes.objectclass[0];
    switch (objectclass) {
    case 'sdcperson':
        addUser(self, changes, entry, cb);
        break;
    case 'sdckey':
        addKey(self, changes, entry, cb);
        break;
    case 'groupofuniquenames':
        addGroup(self, changes, entry, cb);
        break;
    default:
        log.info('ignoring change with objectclass %s', objectclass);
        cb();
        break;
    }

    function addUser(self, changes, entry, cb) {
        var log = self.log;
        log.info({
            changes: changes,
            changenumber: entry.object.changenumber
        }, 'adding user');
        var client = self.redisClient;
        var login = changes.login[0];

        // MANTA-1289 approved_for_provisioning gets serialized as an array.
        var approved = false;
        if (changes.approved_for_provisioning &&
            changes.approved_for_provisioning[0]) {
            // we want the bool value, not the string stored in redis
            if (changes.approved_for_provisioning[0] === 'true') {
                approved = true;
            }
        }
        var payload = {
            uuid: changes.uuid[0],
            // MANTA-1289
            approved_for_provisioning: approved
        };

        var key = sprintf('/login/%s', login);
        var payloadString = JSON.stringify(payload);
        var uuidKey = sprintf('/uuid/%s', payload.uuid);
        log.info('begin addUser %s redis transaction', key);
        log.info('adding user entry %s, key %s', key, payloadString);
        log.info('adding reverse index uuid %s, key %s', uuidKey, login);
        log.info('adding key %s to login set', login);
        log.info('adding key %s to uuid set', payload.uuid);
        // persist the user and reverse index of login to uuid also add login and
        // uuid to their respective sets wrap in a transation for atomicity.
        client.multi()
            .set(key, payloadString)
            .set(uuidKey, login)
            .sadd('uuid', payload.uuid)
            .sadd('login', login)
            .exec(function(err, replies) {
                redisErrHandler(self, err);
                log.info('finished addUser transaction');
                cb(err);
        });
    }

    function addKey(self, changes, entry, cb) {
        var log = self.log;
        log.info({
            changes: changes,
            changenumber: entry.object.changenumber
        }, 'adding key');
        // like fingerprint=foo, uuid=bar, ou=users, o=smartdc
        var myDn = entry.object.targetdn;

        // skip the , and space in fingerprint=foo, uuid=
        var firstIndex = myDn.indexOf(',') + 2;
        var secondIndex = myDn.indexOf(',', firstIndex + 1);
        var userUuid = myDn.substr(firstIndex, secondIndex - firstIndex);
        // strip out uuid= from uuid=foo
        userUuid = userUuid.substr(userUuid.indexOf('=') + 1);

        var client = self.redisClient;

        // get the login
        var loginKey = sprintf('/uuid/%s', userUuid);
        log.info('looking up corresponding login for uuid %s', loginKey);
        client.get(loginKey, function(err, login) {
            redisErrHandler(self, err);
            if (err) {
                cb(err);
                return;
            }
            log.info('got login %s from uuid %s', login, loginKey);
            var fingerprint = changes.fingerprint[0];
            var pkcs = changes.pkcs[0];
            var key = sprintf('/login/%s', login);

            client.get(key, function(err, payload) {
                redisErrHandler(self, err);
                if (err) {
                    cb(err);
                    return;
                }
                payload = JSON.parse(payload) || {};
                if (!payload.keys) {
                    payload.keys = {};
                }
                payload.keys[fingerprint] = pkcs;
                payload = JSON.stringify(payload);
                log.info({
                    newKeyFingerPrint: fingerprint,
                    key: key,
                    payload: payload
                }, 'adding key entry');

                client.set(key, payload, function(err) {
                    redisErrHandler(self, err);
                    log.info('key added');
                    cb(err);
                });
            });
        });
    }

    function addGroup(self, changes, entry, cb) {
        var log = self.log;
        log.info({
            changes: changes,
            chnagenumber: entry.object.changenumber,
            entry: entry.object
        }, 'adding group');

        /*
         * MANTA-1194: add group entries may not contain members, in this case
         * we just skip it -- since there will be entries whenever a user is
         * added to a group, and that is the changelog mahi will parse and use.
         */
        if (!changes.uniquemember) {
            log.info('no uniquemembers in group, exiting addgroup');
            cb();
            return;
        }
        // like uuid=930896af-bf8c-48d4-885c-6573a94b1853, ou=users, o=smartdc
        // multiple members

        var m = 0;
        function updateNext() {
            var userdn = changes.uniquemember[m];

            if (!userdn) {
                cb();
                return;
            }

            addGroupMember(self, userdn, entry.object.targetdn, function (err) {
                if (err) {
                    cb(err);
                    return;
                }
                ++m;
                updateNext();
            });
        }

        updateNext();
    }
}

function del(self, changes, entry, cb) {
    var log = self.log;
    var objectclass = changes.objectclass[0];

    switch (objectclass) {
    case 'sdcperson':
        delUser(self, changes, entry, cb);
        break;
    case 'sdckey':
        delKey(self, changes, entry, cb);
        break;
    case 'groupofuniquenames':
        delGroup(self, changes, entry, cb);
        break;
    default:
        cb(new Error('default case invoked.'));
        break;
    }

    function delKey(self, changes, entry, cb) {
        log.info({
            changes: changes,
            changenumber: entry.object.changenumber
        }, 'deleting key');
        // like fingerprint=foo, uuid=bar, ou=users, o=smartdc
        var myDn = entry.object.targetdn;

        // skip the , and space in fingerprint=foo, uuid=
        var firstIndex = myDn.indexOf(',') + 2;
        var secondIndex = myDn.indexOf(',', firstIndex + 1);
        var userUuid = myDn.substr(firstIndex, secondIndex - firstIndex);
        // stripout uuid= from uuid=foo
        userUuid = userUuid.substr(userUuid.indexOf('=') + 1);

        var client = self.redisClient;

        // get the login
        var loginKey = sprintf('/uuid/%s', userUuid);
        log.info('getting login for uuid %s', loginKey);
        client.get(loginKey, function(err, login) {
            redisErrHandler(self, err);
            if (err) {
                cb(err);
                return;
            }
            log.info('got login %s for uuid %s', login, loginKey);
            var fingerprint = changes.fingerprint[0];
            var key = sprintf('/login/%s', login);

            client.get(key, function(err, payload) {
                redisErrHandler(self, err);
                if (err) {
                    cb(err);
                    return;
                }
                log.info({
                    sshKeyPayload: payload,
                    key: key
                }, 'got payload');
                payload = JSON.parse(payload);
                log.info({
                    sshKeyPayload: payload
                }, 'json parsed sshKeyPayload');
                delete payload.keys[fingerprint];
                payload = JSON.stringify(payload);
                log.info({
                    key: key,
                    sshKeyPayload: payload
                }, 'removed key entry');
                client.set(key, payload, function(err) {
                    redisErrHandler(self, err);
                    cb(err);
                });
            });
        });
    }

    function delUser(self, changes, entry, cb) {
        var log = self.log;
        log.info({
            changes: changes,
            changenumber: entry.object.changenumber
        }, 'deleting user');
        var client = self.redisClient;
        var login = changes.login[0];
        var key = sprintf('/login/%s', login);
        var uuidKey = sprintf('/uuid/%s', changes.uuid);

        log.info('begin delUser %s redis transaction', key);
        log.info('del user entry %s', key);
        log.info('del reverse index uuid %s', uuidKey);
        // wrap in a transation for atomicity.
        client.multi()
            .del(key)
            .del(uuidKey)
            .srem('uuid', changes.uuid)
            .srem('login', login)
            .exec(function(err, replies) {
                redisErrHandler(self, err);
                log.info('finished delUser transaction user %s', key);
                cb(err);
        });
    }

    function delGroup(self, changes, entry, cb) {
        var log = self.log;
        log.info({
            changes: changes,
            changenumber: entry.object.changenumber,
            groupEntry: entry.object
        }, 'deleting group');
        var users = changes.uniquemember;
        // for each user UUID, delete the group name entry from the user's entry

        // like uuid=930896af-bf8c-48d4-885c-6573a94b1853, ou=users, o=smartdc
        // like cn=operators, ou=users, o=smartdc
        var groupdn = entry.object.targetdn;

        var u = 0;
        function updateNext() {
            var userdn = users[u];

            if (!userdn) {
                cb();
                return;
            }

            removeGroupMember(self, userdn, groupdn, function (err) {
                if (err) {
                    cb(err);
                    return;
                }
                ++u;
                updateNext();
            });
        }

        updateNext();
    }
}

function sort(a, b) {
    a = parseInt(a.object.changenumber, 10);
    b = parseInt(b.object.changenumber, 10);

    return a - b;
}

function redisErrHandler(self, err) {
    var log = self.log;
    if (err) {
        log.error({err: err}, 'redis error');
        self.emit('error', err);
    }
}
