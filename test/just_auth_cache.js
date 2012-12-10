var AuthCache = require('../lib/index.js');
var Logger = require('bunyan');
var redis = require('redis');

var LOG = new Logger({
  name: 'authcache-test',
  src: true,
  level: 'trace'
});

var REDIS_CFG = {
        host: 'localhost',
        port: 6379,
        log: LOG,
        options: {}
};

var REDIS_CLIENT = redis.createClient();
REDIS_CLIENT.flushdb();

AuthCache.createAuthCache({
  log: LOG,
  ldapCfg: {
    url: 'ldap://localhost:1389',
    maxConnections: 10,
    bindDN: 'cn=root',
    bindCredentials: 'secret'
  },
  redisCfg: REDIS_CFG,
  pollInterval: 1000
});

