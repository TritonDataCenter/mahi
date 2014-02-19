/*
 * Test suite for authentication server
 */

var server = require('../lib/server/server.js');

var redis = require('fakeredis');
var restify = require('restify');
var sprintf = require('util').format;
var vasync = require('vasync');

var nodeunit = require('nodeunit-plus');
var before = nodeunit.before;
var after = nodeunit.after;
var test = nodeunit.test;

before(function (cb) {
    this.log = nodeunit.createLogger('server', process.stderr);

    this.redis = redis.createClient({
        host: 'localhost',
        port: 6379
    });

    this.client = restify.createJsonClient({
        url: 'http://localhost:8080'
    });

    /*
    server.start({
         port: 8080,
         log: this.log,
         redis: this.redis
    });
    */
    cb();
});

after(function (cb) {
    this.client.close();
    cb();
});

test('setup', function (t) {
    t.end();
});

test('getAccount', function (t) {
    this.client.get('/info/account/bmc', function (err, req, res, obj) {
        console.log(err);
        console.log(obj);
        t.end();
    });
});
