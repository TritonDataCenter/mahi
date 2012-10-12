/*
 * Copyright (c) 2012, Joyent, Inc. All rights reserved.
 *
 * The authentication cache.
 */
var assert = require('./assert');
var EventEmitter = require('events').EventEmitter;
var ldap = require('ldapjs');
var parseDN = ldap.parseDN;
var redis = require('redis');
var sprintf = require('util').format;
var util = require('util');
var vasync = require('vasync');


var assertArray = assert.assertArray;
var assertFunction = assert.assertFunction;
var assertNumber = assert.assertNumber;
var assertObject = assert.assertObject;
var assertString = assert.assertString;

var CHANGELOG = 'cn=changelog';
var USER_DN = 'ou=users, o=smartdc';
var GROUP_DN = 'ou=groups, o=smartdc';

/**
 * Redis Schema:
 * login : {
 *      uuid,
 *      keys : {
 *      $fp: publickey
 *      },
 *      groups: {
 *        $groupname
 *      }
 * }
 */
function AuthCache(options) {
  assertObject('options', options);
  assertObject('options.log', options.log);
  assertObject('options.ldapCfg', options.ldapCfg);
  assertNumber('options.pollInterval', options.pollInterval);

  EventEmitter.call(this);
  this.log = options.log;
  var ldapCfg = options.ldapCfg;
  var self = this;
  var log = self.log;

  log.info('new auth cache with options', options);

  /**
  * redis client
  */
  this.redisClient = redis.createClient(options.redisCfg.port,
                                        options.redisCfg.host,
                                        options.redisCfg);

  /**
  * Indicates whether we are already polling ldap
  */
  this.currPolling = false;

  /**
  * The interval to poll UFDS
  */
  this.pollInterval = options.pollInterval;

  /**
  * The serial entry queue, ensure entries are processed serially.
  */
  this.queue = vasync.queue(parseEntry, 1);

  /**
  * The latest consumed changenumber.
  */
  this.changenumber = 0;

  /**
  * ldap client
  */
  this.ldapClient = ldap.createClient(ldapCfg);

  self.ldapClient.on('error', function(err) {
    log.error({err: err}, 'ldap client error');
  });

  self.ldapClient.on('connect', function() {
    log.info('ldap client connected');
    var dn = ldapCfg.bindDN;
    var pw = ldapCfg.bindCredentials;
    self.ldapClient.bind(dn, pw, function(err) {
      if (err) {
        log.error({err: err}, 'unable to bind to ldap');
        self.emit('error', err);
      }
      log.info('ldap client bound!');
      self.redisClient.get('changenumber', function(err, res) {
        redisErrHandler(self, err);
        if (!res) {
          self.changenumber = 0;
        } else {
          self.changenumber = parseInt(res, 10);
        }

        log.info('created auth client', self);
        log.info('start polling');
        setInterval(tryPoll, self.pollInterval, self);
        tryPoll(self);
      });
    });
  });
}

module.exports = AuthCache;
util.inherits(AuthCache, EventEmitter);

function tryPoll(self) {
  try {
    poll(self);
  } catch (e) {
    self.log.error({e: e});
    throw e;
  }
}

function poll(self) {
  var log = self.log;
  if (self.currPolling) {
    return;
  }

  self.currPolling = true;

  var start = parseInt(self.changenumber, 10);
  var max = start + 100;
  var filter = sprintf('(&(changenumber>=%s)(|(targetdn=*ou=users*)(targetdn=*ou=groups*))(!(targetdn=vm*)))', start);
  var opts = {
    scope: 'sub',
    filter: filter
  };

  log.info('searching %s with opts %j', CHANGELOG, opts);
  var entries = [];
  var latestChangenumber = self.changenumber;
  self.ldapClient.search(CHANGELOG, opts, function(err, res, count) {
    ldapErrHandler(self, err);

    // save the matching entries and sort.
    res.on('searchEntry', function(entry) {
      log.debug('search entry', entry.object.targetdn,
               entry.object.changenumber, entry.object.changetype);
      // cache the changenumber if it's bigger, in case none of the entries
      // match
      var changenumber = parseInt(entry.object.changenumber, 10);
      if (entry.object.changenumber > changenumber) {
        latestChangenumber = changenumber;
      }

      var targetdn = parseDN(entry.object.targetdn);
      var changes = JSON.parse(entry.object.changes);

      // dn has to match
      if (targetdn.childOf(USER_DN) || targetdn.childOf(GROUP_DN)) {
        log.debug('dn matches', entry.object);
        // object class has to match if exists
        if (changes && changes.objectclass) {
          var objectclass = changes.objectclass[0];
          if (objectclass === 'sdcperson' || objectclass === 'sdckey' ||
              objectclass === 'groupofuniquenames') {
            entry.parsedChanges = changes;
            log.info('pusing entry', targetdn, entry.object.changenumber);
            entries.push(entry);
          }
        } else if (targetdn.childOf(GROUP_DN) &&
              entry.object.changetype === 'modify') {
          // Only care about mods of groups as that indicates add/rm user from
          // the group.
          // Only check objectclass once we're sure we have a mod entry
          var objectclass = JSON.parse(entry.object.entry).objectclass[0];
          if (objectclass === 'groupofuniquenames') {
            log.info('pusing entry', targetdn, entry.object.changenumber);
            entry.parsedChanges = changes;
            entries.push(entry);
          }
        }
      }

    });

    res.on('err', function(err) {
      ldapErrHander(self, err);
    });

    res.on('end', function(res) {
      log.info('search ended sorting entries');
      if (entries.length === 0) {
        log.info('no new entries');
        if (self.changenumber < latestChangenumber) {
          self.changenumber = latestChangenumber + 1;
          log.info('updating cn to %s', self.changenumber);

          /*
           * if there are no entries, update the cn in redis to the latest one
           * seen during this round of searches. Otherwise, the cn doesn't get
           * updated, which causes mahi to continue searching from the old cn.
           */
          var client = self.redisClient;
          client.set('changenumber', self.changenumber, function(err) {
            redisErrHandler(self, err);
          self.currPolling = false;

          });
        } else {
          self.currPolling = false;
        }
      }
      entries.sort(sort);

      entries.forEach(function(entry, index) {
        log.info('changes', entry.object.changenumber, entry.object.changes);
        try {
          entry.self = self;
          self.queue.push(entry);
        } catch (e) {
          log.error({err: err});
          throw e;
        }

        if (index === entries.length - 1) {
          log.info('finished pushing changelogs up to %s', self.changenumber);
          self.currPolling = false;
        }
      });
    });
  });
}

function parseEntry(entry, cb) {
  var self = entry.self;
  var log = self.log;
  var changetype = entry.object.changetype;

  var changenumber = entry.object.changenumber;
  log.info('parsing entry', changenumber);
  switch (changetype) {
  case 'add':
    add(self, entry.parsedChanges, entry, updateChangenumber);
    break;
  case 'modify':
    // only for group updates
    // modifies don't contain the object class in the change field
    mod(self, entry.parsedChanges, entry, updateChangenumber);
    break;
  case 'delete':
    del(self, entry.parsedChanges, entry, updateChangenumber);
    break;
  default:
    throw new Error('default case invoked.');
  }

  // update to changenumber + 1 since the filter is >=changenumber
  // thankyou LDAP spec!
  function updateChangenumber() {
    log.info('updating changenumber to', changenumber);
    self.changenumber = parseInt(entry.object.changenumber, 10) + 1;
    var client = self.redisClient;
    client.set('changenumber', self.changenumber, function(err) {
      redisErrHandler(self, err);
      return cb();
    });
  }
}

// only process objectclass=groupofuniquenames which is for groups
function mod(self, changes, entry, cb) {
  var log = self.log;
  changes.forEach(function(change, index) {
    log.info('change', change);
    if (change.modification.type === 'uniquemember') {
      var userdn = change.modification.vals[0];
      var groupdn = entry.object.targetdn;
      switch (change.operation) {
        case 'add':
          //var user = change.modification.vals[0];
          //var groupdn = entry.object.targetdn;
          addGroupMember(self, userdn, groupdn, function() {
          });
          break;
        case 'delete':
          removeGroupMember(self, userdn, groupdn, function() {
          });
          break;
        default:
          throw new Error('default case invoked');
      }
    }
    log.info('changes', change);
  });

  return cb();
}

function addGroupMember(self, userdn, groupdn, cb) {
  var log = self.log;

  var client = self.redisClient;
  var group = groupdn.substring(groupdn.indexOf('=') + 1, groupdn.indexOf(','));
  var userUuid = userdn.substring(userdn.indexOf('=') + 1, userdn.indexOf(','));
  // get the login from uuid
  var loginKey = sprintf('/uuid/%s', userUuid);
  log.info('loginkey', loginKey);
  var client = self.redisClient;

  client.get(loginKey, function(err, login) {
    redisErrHandler(self, err);
    log.info('result', login);
    var key = sprintf('/login/%s', login);

    client.get(key, function(err, payload) {
      redisErrHandler(self, err);
      log.info('got user entry', payload);
      payload = JSON.parse(payload);
      if (!payload.groups) {
        payload.groups = {};
      }

      payload.groups[group] = group;
      payload = JSON.stringify(payload);
      log.info('adding group entry', key, payload);
      client.set(key, payload, function(err) {
        redisErrHandler(self, err);
        return cb();
      });
    });
  });
}

// remove a group member
function removeGroupMember(self, userdn, groupdn, cb) {
  var log = self.log;
  log.info('removing user %s from group %s', userdn, groupdn);
  var client = self.redisClient;
  var group = groupdn.substring(groupdn.indexOf('=') + 1, groupdn.indexOf(','));
  var userUuid = userdn.substring(userdn.indexOf('=') + 1, userdn.indexOf(','));
  // get the login from uuid
  var loginKey = sprintf('/uuid/%s', userUuid);
  log.info('loginkey', loginKey);
  var client = self.redisClient;
  // get the login from uuid
  var loginKey = sprintf('/uuid/%s', userUuid);
  log.info('loginkey', loginKey);
  var client = self.redisClient;

  client.get(loginKey, function(err, login) {
    redisErrHandler(self, err);
    log.info('result', login);
    var key = sprintf('/login/%s', login);

    client.get(key, function(err, payload) {
      redisErrHandler(self, err);
      log.info('got user entry', payload);
      payload = JSON.parse(payload);
      delete payload.groups[group];
      payload = JSON.stringify(payload);
      log.info('removinggroup entry', key, payload);
      client.set(key, payload, function(err) {
        redisErrHandler(self, err);
        return cb();
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
      //log.info('changes', changes);
      break;
    case 'sdckey':
      addKey(self, changes, entry, cb);
      //log.info('changes', changes);
      break;
    case 'groupofuniquenames':
      addGroup(self, changes, entry, cb);
      //log.info('changes', changes);
      break;
    default:
      log.debug('ignoring change with objectclass %s', objectclass);
      break;
  }

  function addUser(self, changes, entry, cb) {
    var log = self.log;
    log.debug('adding user', changes, entry.object.changenumber);
    var client = self.redisClient;
    var login = changes.login[0];

    var payload = {
      uuid: changes.uuid[0]
    };

    var key = sprintf('/login/%s', login);
    var payloadString = JSON.stringify(payload);
    log.info('adding user entry', key, payloadString);
    // persist the user and reverse index of login to uuid
    client.set(key, payloadString, function(err) {
      redisErrHandler(self, err);
      var uuidKey = sprintf('/uuid/%s', payload.uuid);
      log.info('adding reverse index', uuidKey, login);
      client.set(uuidKey, login, function(err) {
        redisErrHandler(self, err);
        return cb();
      });
    });
  }

  function addKey(self, changes, entry, cb) {
    var log = self.log;
    log.debug('adding key', changes, entry.object.changenumber);
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
    client.get(loginKey, function(err, login) {
      redisErrHandler(self, err);
      log.info('result', login);
      var fingerprint = changes.fingerprint[0];
      var pkcs = changes.pkcs[0];
      var key = sprintf('/login/%s', login);

      client.get(key, function(err, payload) {
        redisErrHandler(self, err);
        payload = JSON.parse(payload);
        if (!payload.keys) {
          payload.keys = {};
        }
        payload.keys[fingerprint] = pkcs;
        payload = JSON.stringify(payload);
        log.info('adding key entry', key, payload);

        client.set(key, payload, function(err) {
          redisErrHandler(self, err);
          log.info('key added');
          return cb();
        });
      });
    });
  }

  function addGroup(self, changes, entry, cb) {
    var log = self.log;
    log.info('adding grouuup', changes, entry.object.changenumber);
    log.info('group entry', entry.object);
    // like uuid=930896af-bf8c-48d4-885c-6573a94b1853, ou=users, o=smartdc
    // multiple members
    changes.uniquemember.forEach(function(userdn, index) {
      addGroupMember(self, userdn, entry.object.targetdn, function() {
        if (index === changes.uniquemember.length - 1) {
          log.info('finished adding all users to group');
          return cb();
        }
      });
    });
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
      throw new Error('default case invokded.');
  }

  function delKey(self, changes, entry, cb) {
    var log = self.log;
    log.debug('deleting key', changes, entry.object.changenumber);
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
    client.get(loginKey, function(err, login) {
      redisErrHandler(self, err);
      log.info('result', login);
      var fingerprint = changes.fingerprint[0];
      var pkcs = changes.pkcs[0];
      var key = sprintf('/login/%s', login);

      client.get(key, function(err, payload) {
        redisErrHandler(self, err);
        log.info('got payload', payload, key);
        payload = JSON.parse(payload);
        log.info('got payload', payload);
        delete payload.keys[fingerprint];
        payload = JSON.stringify(payload);
        log.info('removed key entry', key, payload);
        client.set(key, payload, function(err) {
          redisErrHandler(self, err);
          return cb();
        });
      });
    });
  }

  function delUser(self, changes, entry, cb) {
    var log = self.log;
    log.info('deleting user', changes, entry.object.changenumber);
    var client = self.redisClient;
    var login = changes.login[0];

    var key = sprintf('/login/%s', login);
    client.del(key, function(err) {
      redisErrHandler(self, err);
      log.info('deleted, login key', key);
      var uuidKey = sprintf('/uuid/%s', changes.uuid);

      client.del(uuidKey, function(err) {
        redisErrHandler(self, err);
        log.info('deleted uuid key', uuidKey);
        return cb();
      });
    });
  }

  function delGroup(self, changes, entry, cb) {
    var log = self.log;
    log.info('deleting group', changes, entry.object.changenumber);
    log.info('group entry', entry.object);
    var users = changes.uniquemember;
    // for each user UUID, delete the group name entry from the user's entry

    // like uuid=930896af-bf8c-48d4-885c-6573a94b1853, ou=users, o=smartdc
    // like cn=operators, ou=users, o=smartdc
    var groupdn = entry.object.targetdn;

    users.forEach(function(userdn, index) {
      removeGroupMember(self, userdn, groupdn, function() {
        if (index === users.length - 1) {
          return cb();
        }
      });
    });
  }
}

function sort(a, b) {
  a = parseInt(a.object.changenumber, 10);
  b = parseInt(b.object.changenumber, 10);

  return a - b;
}

function ldapErrHandler(self, err) {
  var log = self.log;
  if (err) {
    log.error({err: err}, 'ldap error');
    //self.emit('error', err);
  }
}

function redisErrHandler(self, err) {
  var log = self.log;
  if (err) {
    log.error({err: err}, 'redis error');
    self.emit('error', err);
  }
}
