// Copyright (c) 2014, Joyent, Inc. All rights reserved.

var transform = require('../lib/replicator/transforms/' +
    'sdcaccountuser_sdcperson.js');

var redis = require('fakeredis');
var REDIS;

var nodeunit = require('nodeunit-plus');
var vasync = require('vasync');
var test = nodeunit.test;

var sprintf = require('util').format;

test('setup', function (t) {
    REDIS = redis.createClient();
    t.done();
});

test('add', function (t) {
    var entry = {
        'dn': 'changenumber=8, cn=changelog',
        'controls': [],
        'targetdn': 'uuid=3ffc7b4c-66a6-11e3-af09-8752d24e4669, ' +
            'uuid=390c229a-8c77-445f-b227-88e41c2bb3cf, ' +
            'ou=users, o=smartdc',
        'changetype': 'add',
        'objectclass': 'changeLogEntry',
        'changetime': '2013-12-19T00:58:05.316Z',
        'changes': {
        'email': [
            'subuser@example.com'
        ],
        'objectclass': [
            'sdcperson',
            'sdcaccountuser'
        ],
        'userpassword': [
            '9f27f013145a04e4cb07dad33600c327ca6db04c'
        ],
        'uuid': [
            '3ffc7b4c-66a6-11e3-af09-8752d24e4669'
        ],
        '_owner': [
            '390c229a-8c77-445f-b227-88e41c2bb3cf'
        ],
        'pwdchangedtime': [
            '1387414685290'
        ],
        'created_at': [
            '1387414685290'
        ],
        'updated_at': [
            '1387414685290'
        ],
        'approved_for_provisioning': [
            'false'
        ],
        '_salt': [
            'f0c4f54e6ed13c8b6a5caf30a273fc59ee72860'
        ],
        '_parent': [
            'uuid=390c229a-8c77-445f-b227-88e41c2bb3cf, ' +
                'ou=users, o=smartdc'
        ],
        'account': [
            '390c229a-8c77-445f-b227-88e41c2bb3cf'
        ],
        'alias': [
            'subuser'
        ],
        'login': [
            '390c229a-8c77-445f-b227-88e41c2bb3cf/subuser'
        ]
        },
        'changenumber': '8'
    };

    var args = {
        changes: entry.changes,
        entry: entry,
        log: this.log,
        redis: REDIS
    };

    var account = '390c229a-8c77-445f-b227-88e41c2bb3cf';
    var uuid = '3ffc7b4c-66a6-11e3-af09-8752d24e4669';
    var login = 'subuser';
    var key = '/uuid/' + uuid;
    var value = {
        type: 'user',
        uuid: uuid,
        account: account,
        login: login
    };

    transform.add(args, function (err, res) {
        t.strictEqual(4, res.queue.length);
        res.exec(function () {
            var barrier = vasync.barrier();
            barrier.start('user');
            barrier.start('uuid');
            barrier.start('set');
            barrier.on('drain', function () {
                t.done();
            });

            REDIS.get(key, function (err, res) {
                t.deepEqual(value, JSON.parse(res));
                barrier.done('uuid');
            });
            REDIS.get(sprintf('/user/%s/%s', account, login),
                function (err, res) {

                t.deepEqual(uuid, res);
                barrier.done('user');
            });
            REDIS.sismember('/set/users/' + account, uuid,
                function (err, res) {

                t.strictEqual(1, res);
                barrier.done('set');
            });
        });
    });
});

test('modify - rename', function (t) {
    var entry = {
        'dn': 'changenumber=15, cn=changelog',
        'controls': [],
        'targetdn': 'uuid=3ffc7b4c-66a6-11e3-af09-8752d24e4669, ' +
            'uuid=390c229a-8c77-445f-b227-88e41c2bb3cf, ' +
            'ou=users, o=smartdc',
        'changetype': 'modify',
        'objectclass': 'changeLogEntry',
        'changetime': '2013-12-19T00:58:05.520Z',
        'changes': [
            {
                'operation': 'replace',
                'modification': {
                    'type': 'login',
                    'vals': [
                        'subuser3'
                    ]
                }
            }
        ],
        'entry': JSON.stringify({
            'email': [
                'subuser@example.com'
            ],
            'objectclass': [
                'sdcperson',
                'sdcaccountuser'
            ],
            'userpassword': [
                '9f27f013145a04e4cb07dad33600c327ca6db04c'
            ],
            'uuid': [
                '3ffc7b4c-66a6-11e3-af09-8752d24e4669'
            ],
            '_owner': [
                '390c229a-8c77-445f-b227-88e41c2bb3cf'
            ],
            'pwdchangedtime': [
                '1387414685290'
            ],
            'created_at': [
                '1387414685290'
            ],
            'updated_at': [
                '1387414685519'
            ],
            'approved_for_provisioning': [
                'false'
            ],
            '_salt': [
                'f0c4f54e6ed13c8b6a5caf30a273fc59ee72860'
            ],
            '_parent': [
                'uuid=390c229a-8c77-445f-b227-88e41c2bb3cf, ' +
                    'ou=users, o=smartdc'
            ],
            'account': [
                '390c229a-8c77-445f-b227-88e41c2bb3cf'
            ],
            'alias': [
                'subuser3'
            ],
            'login': [
                '390c229a-8c77-445f-b227-88e41c2bb3cf/subuser3'
            ]
        })
    };

    var args = {
        changes: entry.changes,
        entry: entry,
        modEntry: JSON.parse(entry.entry),
        log: this.log,
        redis: REDIS
    };

    var account = '390c229a-8c77-445f-b227-88e41c2bb3cf';
    var uuid = '3ffc7b4c-66a6-11e3-af09-8752d24e4669';
    var login = 'subuser3';
    var oldlogin = 'subuser';
    var key = '/uuid/' + uuid;

    transform.modify(args, function (err, res) {
        t.strictEqual(4, res.queue.length);
        res.exec(function () {
            var barrier = vasync.barrier();
            barrier.start('newname');
            barrier.start('oldname');
            barrier.start('uuid');
            barrier.on('drain', function () {
                t.done();
            });
            REDIS.get(sprintf('/user/%s/%s', account, login),
                function (err, res) {

                t.deepEqual(uuid, res);
                barrier.done('newname');
            });
            REDIS.get(sprintf('/user/%s/%s', account, oldlogin),
                function (err, res) {

                t.strictEqual(null, res);
                barrier.done('oldname');
            });
            REDIS.get(key, function (err, res) {
                t.deepEqual(JSON.parse(res).login, login);
                barrier.done('uuid');
            });
        });
    });
});

test('delete', function (t) {
    var entry = {
        'dn': 'changenumber=34, cn=changelog',
        'controls': [],
        'targetdn': 'uuid=3ffc7b4c-66a6-11e3-af09-8752d24e4669, ' +
            'uuid=390c229a-8c77-445f-b227-88e41c2bb3cf, ' +
            'ou=users, o=smartdc',
        'changetype': 'delete',
        'objectclass': 'changeLogEntry',
        'changetime': '2013-12-19T00:58:06.650Z',
        'changes': {
            'email': [
                'subuser@example.com'
            ],
            'objectclass': [
                'sdcperson',
                'sdcaccountuser'
            ],
            'userpassword': [
                '9f27f013145a04e4cb07dad33600c327ca6db04c'
            ],
            'uuid': [
                '3ffc7b4c-66a6-11e3-af09-8752d24e4669'
            ],
            '_owner': [
                '390c229a-8c77-445f-b227-88e41c2bb3cf'
            ],
            'pwdchangedtime': [
                '1387414685290'
            ],
            'created_at': [
                '1387414685290'
            ],
            'updated_at': [
                '1387414685519'
            ],
            'approved_for_provisioning': [
                'false'
            ],
            '_salt': [
                'f0c4f54e6ed13c8b6a5caf30a273fc59ee72860'
            ],
            '_parent': [
                'uuid=390c229a-8c77-445f-b227-88e41c2bb3cf, ou=users, o=smartdc'
            ],
            'account': [
                '390c229a-8c77-445f-b227-88e41c2bb3cf'
            ],
            'alias': [
                'subuser3'
            ],
            'login': [
                '390c229a-8c77-445f-b227-88e41c2bb3cf/subuser3'
            ]
        },
        'changenumber': '34'
    };

    var args = {
        changes: entry.changes,
        entry: entry,
        log: this.log,
        redis: REDIS
    };

    var account = '390c229a-8c77-445f-b227-88e41c2bb3cf';
    var uuid = '3ffc7b4c-66a6-11e3-af09-8752d24e4669';
    var login = '390c229a-8c77-445f-b227-88e41c2bb3cf/subuser3';
    var key = '/uuid/' + uuid;

    transform.delete(args, function (err, res) {
        t.strictEqual(4, res.queue.length);
        res.exec(function () {
            var barrier = vasync.barrier();
            barrier.start('uuid');
            barrier.start('set');
            barrier.start('user');
            barrier.on('drain', function () {
                t.done();
            });

            REDIS.get(key, function (err, res) {
                t.strictEqual(null, res);
                barrier.done('uuid');
            });
            REDIS.get(sprintf('/user/%s/%s', account, login),
                function (err, res) {
                t.strictEqual(null, res);
                barrier.done('user');
            });
            REDIS.sismember('/set/users/' + account, uuid,
                function (err, res) {
                t.strictEqual(0, res);
                barrier.done('set');
            });
        });
    });
});
