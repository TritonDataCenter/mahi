// Copyright (c) 2014, Joyent, Inc. All rights reserved.

var Server = require('../lib/server/server.js').Server;

var Transform = require('../lib/replicator/transform.js');
var jsonstream = require('./jsonparsestream.js');
var fs = require('fs');
var bunyan = require('bunyan');
var path = require('path');
var redis = require('fakeredis');
var restify = require('restify');

var nodeunit = require('nodeunit-plus');
var after = nodeunit.after;
var before = nodeunit.before;
var test = nodeunit.test;


var REDIS = redis.createClient();

test('setup - populate redis', function (t) {
    var typeTable = {
        ip: 'ip'
    };
    var data = fs.createReadStream(path.resolve(__dirname,
        './data/test-nodeletes.json'));
    var json = new jsonstream();
    var transform = new Transform({
        redis: REDIS,
        log: bunyan.createLogger({
            name: 'transform',
            level: 'fatal'
        }),
        typeTable: typeTable
    });
    data.pipe(json).pipe(transform);
    transform.on('finish', function () {
        t.end();
    });
});

before(function (cb) {
    this.client = restify.createJsonClient({
        url: 'http://localhost:8080'
    });
    this.server = new Server({
        redis: REDIS,
        log: bunyan.createLogger({
            name: 'server',
            level: 'info'
        }),
        port: 8080
    });
    cb();
});

after(function (cb) {
    if (this.client) {
        this.client.close();
    }
    if (this.server) {
        this.server.close();
    }
    cb();
});

test('getAccount', function (t) {
    this.client.get('/account/banks', function (err, req, res, obj) {
        t.ok(obj.account);
        t.end();
    });
});

test('account dne', function (t) {
    this.client.get('/account/asdfkasdf', function (err, req, res, obj) {
        t.equal(err.restCode, 'AccountDoesNotExist');
        t.equal(obj.code, 'AccountDoesNotExist');
        t.end();
    });
});

test('getUser', function (t) {
    this.client.get('/user/banks/bankofamerica', function (err, req, res, obj) {
        console.log(obj);
        t.end();
    });
});

test('translate role', function (t) {
    var params = {
        account: 'banks',
        role: ['lender', 'borrower']
    };

    this.client.post('/translate', params, function (err, req, res, obj) {
        t.ok(obj.role.lender);
        t.ok(obj.role.borrower);
        t.end();
    });
});
