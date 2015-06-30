/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright (c) 2014, Joyent, Inc.
 */

var transform = require('../lib/replicator/transforms/sdcperson.js');

var redis = require('fakeredis');
var REDIS;

var nodeunit = require('nodeunit-plus');
var vasync = require('vasync');
var test = nodeunit.test;

test('setup', function (t) {
    REDIS = redis.createClient();
    t.done();
});

test('add', function (t) {
    var entry = {
        'dn': 'changenumber=6, cn=changelog',
        'controls': [],
        'targetdn': 'uuid=1a940615-65e9-4856-95f9-f4c530e86ca4, ' +
            'ou=users, o=smartdc',
        'changetype': 'add',
        'objectclass': 'changeLogEntry',
        'changetime': '2013-12-11T21:05:03.499Z',
        'changes': {
            'cn': [
                'Bryan',
                'Cantrill'
            ],
            'email': [
                'bcantrill@acm.org'
            ],
            'login': [
                'bcantrill'
            ],
            'objectclass': [
                'sdcperson'
            ],
            'userpassword': [
                '20ce672f319c31eba1cbdea8e5d46b081e1f2506'
            ],
            'uuid': [
                '1a940615-65e9-4856-95f9-f4c530e86ca4'
            ],
            '_owner': [
                '1a940615-65e9-4856-95f9-f4c530e86ca4'
            ],
            'pwdchangedtime': [
                '1386795903462'
            ],
            'created_at': [
                '1386795903462'
            ],
            'updated_at': [
                '1386795903462'
            ],
            'approved_for_provisioning': [
                'false'
            ],
            '_salt': [
                '477ea5c58f134c44598f566f75156c6e790c9be'
            ],
            '_parent': [
                'ou=users, o=smartdc'
            ]
        },
        'changenumber': '6'
    };

    var args = {
        changes: entry.changes,
        entry: entry,
        log: this.log,
        redis: REDIS
    };

    var uuid = '1a940615-65e9-4856-95f9-f4c530e86ca4';
    var key = '/uuid/' + uuid;
    var value = {
        type: 'account',
        uuid: '1a940615-65e9-4856-95f9-f4c530e86ca4',
        login: 'bcantrill',
        groups: [],
        approved_for_provisioning: false
    };

    transform.add(args, function (err, res) {
        t.strictEqual(4, res.queue.length);
        res.exec(function () {
            var barrier = vasync.barrier();
            barrier.start('account');
            barrier.start('uuid');
            barrier.start('set');
            barrier.on('drain', function () {
                t.done();
            });
            REDIS.get('/account/bcantrill', function (err, res) {
                t.strictEqual(uuid, res);
                barrier.done('account');
            });
            REDIS.get(key, function (err, res) {
                t.deepEqual(value, JSON.parse(res));
                barrier.done('uuid');
            });
            REDIS.sismember('/set/accounts', uuid,
                function (err, res) {

                t.strictEqual(1, res);
                barrier.done('set');
            });
        });
    });
});

test('modify - irrelevant change', function (t) {
    var entry = {
        'dn': 'changenumber=13, cn=changelog',
        'controls': [],
        'targetdn': 'uuid=1a940615-65e9-4856-95f9-f4c530e86ca4, ' +
            'ou=users, o=smartdc',
        'changetype': 'modify',
        'objectclass': 'changeLogEntry',
        'changetime': '2013-12-11T21:05:04.027Z',
        'changes': [
            {
                'operation': 'replace',
                'modification': {
                    'type': 'company',
                    'vals': [
                        'Joy3nt'
                    ]
                }
            }
        ],
        'entry': JSON.stringify({
            'cn': [
                'Bryan',
                'Cantrill'
            ],
            'email': [
                'bcantrill@acm.org'
            ],
            'login': [
                'bmc'
            ],
            'objectclass': [
                'sdcperson'
            ],
            'userpassword': [
                '20ce672f319c31eba1cbdea8e5d46b081e1f2506'
            ],
            'uuid': [
                '1a940615-65e9-4856-95f9-f4c530e86ca4'
            ],
            '_owner': [
                '1a940615-65e9-4856-95f9-f4c530e86ca4'
            ],
            'pwdchangedtime': [
                '1386795903462'
            ],
            'created_at': [
                '1386795903462'
            ],
            'updated_at': [
                '1386795904026'
            ],
            '_salt': [
                '477ea5c58f134c44598f566f75156c6e790c9be'
            ],
            '_parent': [
                'ou=users, o=smartdc'
            ],
            'company': [
                'Joy3nt'
            ]
        }),
        'changenumber': '13'
    };

    var args = {
        changes: entry.changes,
        entry: entry,
        modEntry: JSON.parse(entry.entry),
        log: this.log,
        redis: REDIS
    };

    var key = '/uuid/1a940615-65e9-4856-95f9-f4c530e86ca4';
    var value = {
        type: 'account',
        uuid: '1a940615-65e9-4856-95f9-f4c530e86ca4',
        login: 'bcantrill',
        groups: [],
        approved_for_provisioning: false
    };

    transform.modify(args, function (err, res) {
        // irrelevant change, there should be nothing to do
        t.strictEqual(1, res.queue.length);
        res.exec(function () {
            REDIS.get(key, function (err, res) {
                t.deepEqual(value, JSON.parse(res));
                t.done();
            });
        });
    });
});

test('modify - approved for provisioning', function (t) {
    var entry = {
        'dn': 'changenumber=10, cn=changelog',
        'controls': [],
        'targetdn': 'uuid=1a940615-65e9-4856-95f9-f4c530e86ca4, ' +
            'ou=users, o=smartdc',
        'changetype': 'modify',
        'objectclass': 'changeLogEntry',
        'changetime': '2013-12-11T21:05:03.783Z',
        'changes': [
            {
                'operation': 'replace',
                'modification': {
                    'type': 'approved_for_provisioning',
                    'vals': [
                        'true'
                    ]
                }
            }
        ],
        entry: JSON.stringify({
            'cn': [
                'Bryan',
                'Cantrill'
            ],
            'email': [
                'bcantrill@acm.org'
            ],
            'login': [
                'bcantrill'
            ],
            'objectclass': [
                'sdcperson'
            ],
            'userpassword': [
                '20ce672f319c31eba1cbdea8e5d46b081e1f2506'
            ],
            'uuid': [
                '1a940615-65e9-4856-95f9-f4c530e86ca4'
            ],
            '_owner': [
                '1a940615-65e9-4856-95f9-f4c530e86ca4'
            ],
            'pwdchangedtime': [
                '1386795903462'
            ],
            'created_at': [
                '1386795903462'
            ],
            'updated_at': [
                '1386795903782'
            ],
            'approved_for_provisioning': [
                'true'
            ],
            '_salt': [
                '477ea5c58f134c44598f566f75156c6e790c9be'
            ],
            '_parent': [
                'ou=users, o=smartdc'
            ]
        }),
        'changenumber': '10'
    };

    var args = {
        changes: entry.changes,
        entry: entry,
        modEntry: JSON.parse(entry.entry),
        log: this.log,
        redis: REDIS
    };

    var key = '/uuid/1a940615-65e9-4856-95f9-f4c530e86ca4';
    var value = {
        type: 'account',
        uuid: '1a940615-65e9-4856-95f9-f4c530e86ca4',
        login: 'bcantrill',
        groups: [],
        approved_for_provisioning: true
    };

    transform.modify(args, function (err, res) {
        t.strictEqual(2, res.queue.length);
        res.exec(function () {
            REDIS.get(key, function (err, res) {
                t.deepEqual(value, JSON.parse(res));
                t.done();
            });
        });
    });
});

test('modify - rename', function (t) {
    var entry = {
        'dn': 'changenumber=12, cn=changelog',
        'controls': [],
        'targetdn': 'uuid=1a940615-65e9-4856-95f9-f4c530e86ca4, ' +
            'ou=users, o=smartdc',
        'changetype': 'modify',
        'objectclass': 'changeLogEntry',
        'changetime': '2013-12-11T21:05:03.954Z',
        'changes': [
            {
                'operation': 'replace',
                'modification': {
                    'type': 'login',
                    'vals': [
                        'bmc'
                    ]
                }
            }
        ],
        entry: JSON.stringify({
                'cn': [
                    'Bryan',
                    'Cantrill'
                ],
                'email': [
                    'bcantrill@acm.org'
                ],
                'login': [
                    'bmc'
                ],
                'objectclass': [
                    'sdcperson'
                ],
                'userpassword': [
                    '20ce672f319c31eba1cbdea8e5d46b081e1f2506'
                ],
                'uuid': [
                    '1a940615-65e9-4856-95f9-f4c530e86ca4'
                ],
                '_owner': [
                    '1a940615-65e9-4856-95f9-f4c530e86ca4'
                ],
                'pwdchangedtime': [
                    '1386795903462'
                ],
                'created_at': [
                    '1386795903462'
                ],
                'updated_at': [
                    '1386795903782'
                ],
                'approved_for_provisioning': [
                    'true'
                ],
                '_salt': [
                    '477ea5c58f134c44598f566f75156c6e790c9be'
                ],
                '_parent': [
                    'ou=users, o=smartdc'
                ]
        }),
        'changenumber': '12'
    };

    var args = {
        changes: entry.changes,
        entry: entry,
        modEntry: JSON.parse(entry.entry),
        log: this.log,
        redis: REDIS
    };

    var uuid = '1a940615-65e9-4856-95f9-f4c530e86ca4';
    var key = '/uuid/' + uuid;
    var value = {
        type: 'account',
        uuid: '1a940615-65e9-4856-95f9-f4c530e86ca4',
        login: 'bmc',
        groups: [],
        approved_for_provisioning: true
    };

    transform.modify(args, function (err, res) {
        t.strictEqual(4, res.queue.length);
        res.exec(function () {
            var barrier = vasync.barrier();
            barrier.start('uuid');
            barrier.start('del');
            barrier.start('add');
            barrier.start('set');
            barrier.on('drain', function () {
                t.done();
            });
            REDIS.get(key, function (err, res) {
                t.deepEqual(value, JSON.parse(res));
                barrier.done('uuid');
            });
            REDIS.get('/account/bcantrill', function (err, res) {
                t.deepEqual(null, res);
                barrier.done('del');
            });
            REDIS.get('/account/bmc', function (err, res) {
                t.deepEqual(uuid, res);
                barrier.done('add');
            });
            REDIS.sismember('/set/accounts', uuid,
                function (err, res) {
                t.strictEqual(1, res);
                barrier.done('set');
            });
        });
    });
});

test('delete', function (t) {
    var entry = {
        'dn': 'changenumber=14, cn=changelog',
        'controls': [],
        'targetdn': 'uuid=1a940615-65e9-4856-95f9-f4c530e86ca4, ' +
            'ou=users, o=smartdc',
        'changetype': 'delete',
        'objectclass': 'changeLogEntry',
        'changetime': '2013-12-13T18:24:22.103Z',
        'changes': {
            'cn': [
                'Bryan',
                'Cantrill'
            ],
            'email': [
                'bcantrill@acm.org'
            ],
            'login': [
                'bmc'
            ],
            'objectclass': [
                'sdcperson'
            ],
            'userpassword': [
                '0119b6df04da7383b230e190d4ff414b8ee2b6eb'
            ],
            'uuid': [
                '1a940615-65e9-4856-95f9-f4c530e86ca4'
            ],
            '_owner': [
                '1a940615-65e9-4856-95f9-f4c530e86ca4'
            ],
            'pwdchangedtime': [
                '1386959061471'
            ],
            'created_at': [
                '1386959061471'
            ],
            'updated_at': [
                '1386959062013'
            ],
            '_salt': [
                '1eae3c3bb8e6a518289c19b43ad7bb3119c8a9c'
            ],
            '_parent': [
                'ou=users, o=smartdc'
            ],
            'company': [
                'Joy3nt'
            ]
        },
        'changenumber': '14'
    };

    var args = {
        changes: entry.changes,
        entry: entry,
        log: this.log,
        redis: REDIS
    };

    var uuid = '1a940615-65e9-4856-95f9-f4c530e86ca4';
    var key = '/uuid/' + uuid;

    transform.delete(args, function (err, res) {
        t.strictEqual(7, res.queue.length);
        res.exec(function () {
            var barrier = vasync.barrier();
            barrier.start('uuid');
            barrier.start('account');
            barrier.start('set');
            barrier.start('subusers');
            barrier.start('policies');
            barrier.start('subroles');
            barrier.on('drain', function () {
                t.done();
            });
            REDIS.get(key, function (err, res) {
                t.strictEqual(null, res);
                barrier.done('uuid');
            });
            REDIS.get('/account/bmc', function (err, res) {
                t.strictEqual(null, res);
                barrier.done('account');
            });
            REDIS.sismember('/set/accounts', uuid,
                function (err, res) {
                t.strictEqual(0, res);
                barrier.done('set');
            });
            REDIS.scard('/set/users/' + uuid, function (err, res) {
                t.strictEqual(0, res);
                barrier.done('subusers');
            });
            REDIS.scard('/set/roles/' + uuid, function (err, res) {
                t.strictEqual(0, res);
                barrier.done('subroles');
            });
            REDIS.scard('/set/policies/' + uuid,
                function (err, res) {
                t.strictEqual(0, res);
                barrier.done('policies');
            });
        });
    });
});
