/*
* Copyright (c) 2012, Joyent, Inc. All rights reserved.
*/
var assert = require('assert');
var AuthCache = require('../lib/index.js');
var ldap = require('ldapjs');
var Logger = require('bunyan');
var moray = require('moray-client');
var parseDN = ldap.parseDN;
var tap = require('tap');
var test = require('tap').test;
var redis = require('redis');
var spawn = require('child_process').spawn;

var LOG = new Logger({
  name: 'authcache-test',
  src: true,
  level: 'trace'
});

var LDAP_CLIENT;
var SUFFIX = process.env.UFDS_SUFFIX || 'o=smartdc';
var DN_FMT = 'uuid=%s, ' + SUFFIX;
var USER_1 = {
  dn: 'uuid=930896af-bf8c-48d4-885c-6573a94b1853, ou=users, o=smartdc',
  login: 'admin',
  uuid: '930896af-bf8c-48d4-885c-6573a94b1853',
  userpassword: 'joypass123',
  email: 'nobody@joyent.com',
  cn: 'admin',
  sn: 'user',
  company: 'Joyent',
  address: 'Joyent, Inc.',
  address: '345 California Street, Suite 2000',
  city: 'San Francisco',
  state: 'CA',
  postalCode: '94104',
  country: 'USA',
  phone: '+1 415 400 0600',
  objectclass: 'sdcPerson'
};

var USER_2 = {
  dn: 'uuid=a820621a-5007-4a2a-9636-edde809106de, ou=users, o=smartdc',
  changetype: 'add',
  login: 'unpermixed',
  uuid: 'a820621a-5007-4a2a-9636-edde809106de',
  userpassword: 'FL8xhO',
  email: 'postdisseizor@superexist.com',
  cn: 'Judophobism',
  sn: 'popgun',
  company: 'butterflylike',
  address: 'liltingly, Inc.',
  address: '6165 pyrophyllite Street',
  city: 'benzoylation concoctive',
  state: 'SP',
  postalCode: '4967',
  country: 'BAT',
  phone: '+1 891 657 5818',
  objectclass: 'sdcPerson'
};

var KEY = {
  dn: 'fingerprint=db:e1:88:bb:a9:ee:ab:be:2f:9c:5b:2f:d9:01:ac:d9, uuid=a820621a-5007-4a2a-9636-edde809106de, ou=users, o=smartdc',
  changetype: 'add',
  name: 'flashlight',
  fingerprint: 'db:e1:88:bb:a9:ee:ab:be:2f:9c:5b:2f:d9:01:ac:d9',
  openssh: 'ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAIEA1UeAFVU5WaJJwe+rPjN7MbostuTX5P2NOn4c07ymxnFEHSH4LJZkVrMdVQRHf3uHLaTyIpCSZfm5onx0s2DoRpLreH0GYxRNNhmsfGcav0teeC6jSzHjJnn+pLnCDVvyunSFs5/AJGU27KPU4RRF7vNaccPUdB+q4nGJ1H1/+YE= tetartoconid@valvulotomy',
  objectclass: 'sdcKey'

}

var AUTH_CACHE;

test('setup redis client', function(t) {
  REDIS_CLIENT = redis.createClient();
  t.ok(REDIS_CLIENT);
  REDIS_CLIENT.flushdb();
  t.end();
});

test('bootstrap authcache', function(t) {
  AUTH_CACHE = AuthCache.createAuthCache({
    log: LOG,
    ldapCfg: {
      url: 'ldap://localhost:1389',
      maxConnections: 10,
      bindDN: 'cn=root',
      bindCredentials: 'secret'
    },
    redisCfg: {},
    pollInterval: 1000
  });
  t.ok(AUTH_CACHE);
  t.end();
});

test('add ldap bootstrap data', function(t) {
  var msg = '';
  var ldapadd = spawn('ldapadd', ['-x', '-H', 'ldap://localhost:1389', '-D',
    'cn=root', '-w', 'secret', '-f', './test/data/bootstrap.ldif']);

  ldapadd.stdout.on('data', function(data) {
    LOG.debug('ldapadd stdout: ', data.toString());
  });

  ldapadd.stderr.on('data', function(data) {
    var dataStr = data.toString();
    LOG.error('ldapadd stderr: ', dataStr);
    if (msg) {
      msg += dataStr;
    } else {
      msg = dataStr;
    }
    msg += data;
  });

  ldapadd.on('exit', function(code) {
    if (code != 0) {
      var err = {
        msg: msg,
        code: code
      };
      LOG.error('couldn\'t add LDAP bootstrap data');
      t.fail(err);
    }
    t.end();
  });
});

test('pause', function(t) {
  // pause for auth-cache to catch up
  setTimeout(function() {t.end();}, 2000);
});

test('verify user1', function(t) {
  REDIS_CLIENT.get('/login/admin', function(err, res) {
    var RESPONSE = '{"uuid":"930896af-bf8c-48d4-885c-6573a94b1853","groups":{"operators":"operators"}}';
    t.ifError(err);
    t.ok(res);
    t.equal(res, RESPONSE);
    REDIS_CLIENT.get('/uuid/930896af-bf8c-48d4-885c-6573a94b1853', function(err, res) {
      var RESPONSE = USER_1.login;
      t.ifError(err);
      t.ok(res);
      t.equal(res, RESPONSE);
      t.end();
    });
  });
});

test('verify user 2', function(t) {
  REDIS_CLIENT.get('/login/unpermixed', function(err, res) {
    var RESPONSE = '{"uuid":"a820621a-5007-4a2a-9636-edde809106de","groups":{"operators":"operators"}}';
    t.ifError(err);
    t.ok(res);
    t.equal(res, RESPONSE);
    REDIS_CLIENT.get('/uuid/a820621a-5007-4a2a-9636-edde809106de', function(err, res) {
      var RESPONSE = USER_2.login;
      t.ifError(err);
      t.ok(res);
      t.equal(res, RESPONSE);
      t.end();
    });
  });
});

test('remove user1 from group', function(t) {
  var msg = '';
  var ldapmodify = spawn('ldapmodify', ['-x', '-H', 'ldap://localhost:1389',
    '-D', 'cn=root', '-w', 'secret', '-f', './test/data/delgroup.ldif']);

  ldapmodify.stdout.on('data', function(data) {
    LOG.debug('ldapmodify stdout: ', data.toString());
  });

  ldapmodify.stderr.on('data', function(data) {
    var dataStr = data.toString();
    LOG.error('ldapmodify stderr: ', dataStr);
    if (msg) {
      msg += dataStr;
    } else {
      msg = dataStr;
    }
    msg += data;
  });

  ldapmodify.on('exit', function(code) {
    if (code != 0) {
      var err = {
        msg: msg,
        code: code
      };
      LOG.error('couldn\'t add LDAP bootstrap data');
      t.fail(err);
    }
    t.end();
  });
});

test('pause', function(t) {
  // pause for auth-cache to catch up
  setTimeout(function() {t.end();}, 2000);
});

test('verify remove user 1 from group', function(t) {
  REDIS_CLIENT.get('/login/admin', function(err, res) {
    var RESPONSE = '{"uuid":"930896af-bf8c-48d4-885c-6573a94b1853","groups":{}}';
    t.ifError(err);
    t.ok(res);
    t.equal(res, RESPONSE, 'removed user1 from group');
    REDIS_CLIENT.get('/uuid/930896af-bf8c-48d4-885c-6573a94b1853', function(err, res) {
      var RESPONSE = USER_1.login;
      t.ifError(err);
      t.ok(res);
      t.equal(res, RESPONSE);
      t.end();
    });
  });
});

test('add keys to user 2', function(t) {
  var msg = '';
  var ldapadd = spawn('ldapadd', ['-x', '-H', 'ldap://localhost:1389', '-D',
    'cn=root', '-w', 'secret', '-f', './test/data/userkey.ldif']);

  ldapadd.stdout.on('data', function(data) {
    LOG.debug('ldapadd stdout: ', data.toString());
  });

  ldapadd.stderr.on('data', function(data) {
    var dataStr = data.toString();
    LOG.error('ldapadd stderr: ', dataStr);
    if (msg) {
      msg += dataStr;
    } else {
      msg = dataStr;
    }
    msg += data;
  });

  ldapadd.on('exit', function(code) {
    if (code != 0) {
      var err = {
        msg: msg,
        code: code
      };
      LOG.error('couldn\'t add LDAP bootstrap data');
      t.fail(err);
    }
    t.end();
  });
});

test('pause', function(t) {
  // pause for auth-cache to catch up
  setTimeout(function() {t.end();}, 2000);
});

test('verify user 2 keys', function(t) {
  REDIS_CLIENT.get('/login/unpermixed', function(err, res) {
    t.ifError(err);
    t.ok(res);
    var resObj = JSON.parse(res);
    t.equal(resObj.uuid, 'a820621a-5007-4a2a-9636-edde809106de');
    var expectedKey = '-----BEGIN PUBLIC KEY-----\nMIGdMA0GCSqGSIb3DQEBAQUAA4GLADCBhwKBgQDVR4AVVTlZoknB76s+M3sxuiy2\n5Nfk/Y06fhzTvKbGcUQdIfgslmRWsx1VBEd/e4ctpPIikJJl+bmifHSzYOhGkut4\nfQZjFE02Gax8Zxq/S154LqNLMeMmef6kucINW/K6dIWzn8AkZTbso9ThFEXu81px\nw9R0H6ricYnUfX/5gQIBIw==\n-----END PUBLIC KEY-----\n';
    t.equal(resObj.keys['db:e1:88:bb:a9:ee:ab:be:2f:9c:5b:2f:d9:01:ac:d9'], expectedKey);
    REDIS_CLIENT.get('/uuid/a820621a-5007-4a2a-9636-edde809106de', function(err, res) {
      var RESPONSE = USER_2.login;
      t.ifError(err);
      t.ok(res);
      t.equal(res, RESPONSE);
      t.end();
    });
  });
});

test('delete user_1', function(t) {
  var msg = '';
  var ldapdelete = spawn('ldapdelete', ['-x', '-H', 'ldap://localhost:1389', '-D',
    'cn=root', '-w', 'secret', USER_1.dn]);

  ldapdelete.stdout.on('data', function(data) {
    LOG.debug('ldapdelete stdout: ', data.toString());
  });

  ldapdelete.stderr.on('data', function(data) {
    var dataStr = data.toString();
    LOG.error('ldapdelete stderr: ', dataStr);
    if (msg) {
      msg += dataStr;
    } else {
      msg = dataStr;
    }
    msg += data;
  });

  ldapdelete.on('exit', function(code) {
    if (code != 0) {
      var err = {
        msg: msg,
        code: code
      };
      LOG.error('couldn\'t add LDAP bootstrap data');
      t.fail(err);
    }
    t.end();
  });
});

test('pause', function(t) {
  // pause for auth-cache to catch up
  setTimeout(function() {t.end();}, 1000);
});

test('verify user1 dne', function(t) {
  REDIS_CLIENT.get('/login/admin', function(err, res) {
    t.ifError(err);
    t.notOk(res);
    REDIS_CLIENT.get('/uuid/930896af-bf8c-48d4-885c-6573a94b1853', function(err, res) {
      t.ifError(err);
      t.notOk(res);
      t.end();
    });
  });
});

test('delete key', function(t) {
  var msg = '';
  var ldapdelete = spawn('ldapdelete', ['-x', '-H', 'ldap://localhost:1389',
  '-D', 'cn=root', '-w', 'secret', KEY.dn]);

  ldapdelete.stdout.on('data', function(data) {
    LOG.debug('ldapdelete stdout: ', data.toString());
  });

  ldapdelete.stderr.on('data', function(data) {
    var dataStr = data.toString();
    LOG.error('ldapdelete stderr: ', dataStr);
    if (msg) {
      msg += dataStr;
    } else {
      msg = dataStr;
    }
    msg += data;
  });

  ldapdelete.on('exit', function(code) {
    if (code != 0) {
      var err = {
        msg: msg,
        code: code
      };
      LOG.error('couldn\'t add LDAP bootstrap data');
      t.fail(err);
    }
    t.end();
  });
});

test('pause', function(t) {
  // pause for auth-cache to catch up
  setTimeout(function() {t.end();}, 2000);
});

test('verify key dne', function(t) {
  REDIS_CLIENT.get('/login/unpermixed', function(err, res) {
    var RESPONSE = '{"uuid":"a820621a-5007-4a2a-9636-edde809106de","groups":{"operators":"operators"},"keys":{}}';
    t.ifError(err);
    t.ok(res);
    t.equal(res, RESPONSE);
    REDIS_CLIENT.get('/uuid/a820621a-5007-4a2a-9636-edde809106de', function(err, res) {
      var RESPONSE = USER_2.login;
      t.ifError(err);
      t.ok(res);
      t.equal(res, RESPONSE);
      t.end();
    });
  });
});

tap.tearDown(function() {
  process.exit(tap.output.results.fail);
});
