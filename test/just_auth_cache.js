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

var LDAP_URL = 'ldaps://10.99.99.14:636';
//var LDAP_URL = 'ldap://localhost:1389';
var REDIS_CLIENT = redis.createClient();
REDIS_CLIENT.flushdb();
AuthCache.createAuthCache({
    log: LOG,
    ldapCfg: {
      url: LDAP_URL,
      maxConnections: 2,
      bindDN: 'cn=root',
      bindCredentials: 'secret',
      timeout: 500
    },
    redisCfg: REDIS_CFG,
    pollInterval: 1000
});
