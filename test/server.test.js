/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright (c) 2017, Joyent, Inc.
 */

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

var DATA = path.resolve(__dirname, './data/test-nodeletes.json');
var REDIS = redis.createClient();

test('setup - populate redis', function (t) {
    var typeTable = {
        ip: 'ip'
    };
    var data = fs.createReadStream(DATA);
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
    var port = 8080;
    this.client = restify.createJsonClient({
        url: 'http://localhost:' + port
    });
    this.server = new Server({
        redis: REDIS,
        log: bunyan.createLogger({
            name: 'server',
            level: process.env.LOG_LEVEL || 'fatal'
        }),
        port: port
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

test('getAccount (old)', function (t) {
    this.client.get('/account/banks', function (err, req, res, obj) {
        t.ok(obj.account);
        t.end();
    });
});

test('account not approved', function (t) {
    this.client.get('/account/oilandgas', function (err, req, res, obj) {
        t.ok(obj.account.approved_for_provisioning === false);
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

test('getUser (old)', function (t) {
    this.client.get('/user/banks/bankofamerica', function (err, req, res, obj) {
        t.ok(obj.user);
        t.end();
    });
});

test('translate account (old)', function (t) {
    var params = {
        account: 'banks'
    };

    this.client.post('/getUuid', params, function (err, req, res, obj) {
        t.ok(obj.account);
        t.end();
    });
});

test('translate role (old)', function (t) {
    var params = {
        account: 'banks',
        type: 'role',
        names: ['lender', 'borrower', 'noexist']
    };

    this.client.post('/getUuid', params, function (err, req, res, obj) {
        t.ok(obj.account);
        t.ok(obj.uuids.lender);
        t.ok(obj.uuids.borrower);
        t.end();
    });
});

test('translate uuid (old)', function (t) {
    var params = {
        uuids: ['bde5a308-9e5a-11e3-bbf2-1b6f3d02ff6f', 'noexist']
    };

    this.client.post('/getName', params, function (err, req, res, obj) {
        t.ok(obj['bde5a308-9e5a-11e3-bbf2-1b6f3d02ff6f']);
        t.end();
    });
});

test('get account by id', function (t) {
    var uuid = '2a05359a-9e64-11e3-816d-e7f87365cf40';
    this.client.get('/accounts/' + uuid, function (err, req, res, obj) {
        t.ok(obj.account);
        t.ok(obj.roles);
        t.end();
    });
});

test('get account by login', function (t) {
    this.client.get('/accounts?login=banks', function (err, req, res, obj) {
        t.ok(obj.account);
        t.ok(obj.roles);
        t.end();
    });
});

test('get account by id', function (t) {
    var uuid = '2a05359a-9e64-11e3-816d-e7f87365cf40';
    this.client.get('/accounts/' + uuid, function (err, req, res, obj) {
        t.ok(obj.account);
        t.ok(obj.roles);
        t.end();
    });
});

test('get account by login', function (t) {
    this.client.get('/accounts?login=banks', function (err, req, res, obj) {
        t.ok(obj.account);
        t.ok(obj.roles);
        t.end();
    });
});

test('get user by id', function (t) {
    var uuid = '3ffc7b4c-66a6-11e3-af09-8752d24e4669';
    this.client.get('/users/' + uuid, function (err, req, res, obj) {
        t.ok(obj.account);
        t.ok(obj.user);
        t.ok(obj.roles);
        t.end();
    });
});

test('get user by login', function (t) {
    var uuid = '3ffc7b4c-66a6-11e3-af09-8752d24e4669';
    this.client.get('/users/' + uuid, function (err, req, res, obj) {
        t.ok(obj.account);
        t.ok(obj.user);
        t.ok(obj.roles);
        t.end();
    });
});

test('cross-account roles', function (t) {
    var uuid = '2a05359a-9e64-11e3-816d-e7f87365cf40';
    this.client.get('/accounts/' + uuid, function (err, req, res, obj) {
        t.ok(obj.account);
        t.ok(obj.roles);
        t.deepEqual(obj.roles, {
            'fd4d1489-a2c4-4303-8b32-0396ca297447': {
                type: 'role',
                uuid: 'fd4d1489-a2c4-4303-8b32-0396ca297447',
                name: 'crossrole',
                account: 'bde5a308-9e5a-11e3-bbf2-1b6f3d02ff6f',
                assumerolepolicydocument: null,
                rules: []
            }
        });
        t.end();
    });
});

test('cross-account roles (none)', function (t) {
    var uuid = 'bde5a308-9e5a-11e3-bbf2-1b6f3d02ff6f';
    this.client.get('/accounts/' + uuid, function (err, req, res, obj) {
        t.ok(obj.account);
        t.ok(obj.roles);
        t.deepEqual(obj.roles, {});
        t.end();
    });
});

test('translate account', function (t) {
    this.client.get('/uuids?account=banks', function (err, req, res, obj) {
        t.ok(obj.account);
        t.end();
    });
});

test('translate role', function (t) {
    this.client.get('/uuids?account=banks&type=role&name=lender',
            function (err, req, res, obj) {
        t.ok(obj.account);
        t.ok(obj.uuids.lender);
        t.end();
    });
});

test('translate multiple roles', function (t) {
    this.client.get('/uuids?account=banks&type=role&name=lender&name=borrower' +
                    '&name=noexist',
            function (err, req, res, obj) {
        t.ok(obj.account);
        t.ok(obj.uuids.lender);
        t.ok(obj.uuids.borrower);
        t.end();
    });
});

test('translate uuid', function (t) {
    var uuid = 'bde5a308-9e5a-11e3-bbf2-1b6f3d02ff6f';
    this.client.get('/names?uuid=' + uuid, function (err, req, res, obj) {
        t.ok(obj[uuid]);
        t.end();
    });
});

test('translate multiple uuids', function (t) {
    var uuid1 = 'bde5a308-9e5a-11e3-bbf2-1b6f3d02ff6f';
    var uuid2 = '2a05359a-9e64-11e3-816d-e7f87365cf40';
    var q = '?uuid=' + uuid1 + '&uuid=' + uuid2 + '&uuid=noexist';
    this.client.get('/names' + q, function (err, req, res, obj) {
        t.ok(obj[uuid1]);
        t.ok(obj[uuid2]);
        t.end();
    });
});

test('generate lookup', function (t) {
    var expected = [
        ['bde5a308-9e5a-11e3-bbf2-1b6f3d02ff6f', true, 'banks'],
        ['1e77f528-9e64-11e3-8d12-838d40383bce', true, 'auto'],
        ['2a05359a-9e64-11e3-816d-e7f87365cf40', false, 'oilandgas']];
    this.client.get('/lookup', function (err, req, res, obj) {
        expected.forEach(function (tuple) {
            t.equal(obj[tuple[0]].approved, tuple[1]);
            t.equal(obj[tuple[0]].login, tuple[2]);
        });
        t.end();
    });
});

test('/accounts: missing arguments', function (t) {
    this.client.get('/accounts', function (err, req, res, obj) {
        t.equal(err.restCode, 'BadRequestError');
        t.equal(obj.code, 'BadRequestError');
        t.end();
    });
});

test('/users: missing argument (account)', function (t) {
    this.client.get('/users', function (err, req, res, obj) {
        t.equal(err.restCode, 'BadRequestError');
        t.equal(obj.code, 'BadRequestError');
        t.end();
    });
});

test('/users: missing argument (user)', function (t) {
    this.client.get('/users?account=banks', function (err, req, res, obj) {
        t.equal(err.restCode, 'BadRequestError');
        t.equal(obj.code, 'BadRequestError');
        t.end();
    });
});

test('/names: missing arguments', function (t) {
    this.client.get('/names', function (err, req, res, obj) {
        t.ok(!err);
        t.deepEqual(obj, {});
        t.end();
    });
});

test('/uuids: missing arguments', function (t) {
    this.client.get('/uuids', function (err, req, res, obj) {
        t.equal(err.restCode, 'BadRequestError');
        t.equal(obj.code, 'BadRequestError');
        t.end();
    });
});
