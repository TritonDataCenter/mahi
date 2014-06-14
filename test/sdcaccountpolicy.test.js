// Copyright (c) 2014, Joyent, Inc. All rights reserved.

var transform = require('../lib/replicator/transforms/sdcaccountpolicy.js');

var redis = require('fakeredis');
var REDIS, PARSER;

var aperture = require('aperture');
var nodeunit = require('nodeunit-plus');
var vasync = require('vasync');
var test = nodeunit.test;

var sprintf = require('util').format;

test('setup', function (t) {
    REDIS = redis.createClient();
    PARSER = aperture.createParser({
        types: aperture.types,
        typeTable: {
            'ip': 'ip'
        }
    });
    t.done();
});

test('add', function (t) {
    var entry = {
      'dn': 'changenumber=20, cn=changelog',
      'controls': [],
      'targetdn': 'policy-uuid=b4301b32-66b4-11e3-ac31-6b349ce5dc45, ' +
        'uuid=390c229a-8c77-445f-b227-88e41c2bb3cf, ' +
        'ou=users, o=smartdc',
      'changetype': 'add',
      'objectclass': 'changeLogEntry',
      'changetime': '2014-02-06T21:36:42.353Z',
      'changes': {
        'account': [
          '390c229a-8c77-445f-b227-88e41c2bb3cf'
        ],
        'name': [
          'developer_read'
        ],
        'objectclass': [
          'sdcaccountpolicy'
        ],
        'rule': [
          'Can read foo and bar when ip = 10.0.0.0/8',
          'Can read red and blue when ip = 10.0.0.0/16'
        ],
        'uuid': [
          'b4301b32-66b4-11e3-ac31-6b349ce5dc45'
        ],
        '_owner': [
          '390c229a-8c77-445f-b227-88e41c2bb3cf'
        ],
        '_parent': [
          'uuid=390c229a-8c77-445f-b227-88e41c2bb3cf, ' +
          'ou=users, o=smartdc'
        ]
      },
      'changenumber': '20'
    };

    var args = {
        changes: entry.changes,
        entry: entry,
        log: this.log,
        parser: PARSER,
        redis: REDIS
    };

    var uuid = 'b4301b32-66b4-11e3-ac31-6b349ce5dc45';
    var account = '390c229a-8c77-445f-b227-88e41c2bb3cf';
    var name = 'developer_read';
    var policy1 = ['Can read foo and bar when ip = 10.0.0.0/8',
        PARSER.parse('Can read foo and bar when ip = 10.0.0.0/8')];
    var policy2 = ['Can read red and blue when ip = 10.0.0.0/16',
        PARSER.parse(
            'Can read red and blue when ip = 10.0.0.0/16')];

    var expected = {
        type: 'policy',
        uuid: uuid,
        name: 'developer_read',
        rules: [
            policy1, policy2
        ],
        account: account
    };

    transform.add(args, function (err, res) {
        t.strictEqual(4, res.queue.length);
        res.exec(function () {
            var barrier = vasync.barrier();
            barrier.start('uuid');
            barrier.start('set');
            barrier.start('policy');
            barrier.on('drain', function () {
                t.done();
            });
            REDIS.get('/uuidv2/' + uuid, function (err, res) {
                t.deepEqual(JSON.parse(res), expected);
                barrier.done('uuid');
            });
            REDIS.sismember('/set/policies/' + account, uuid,
                function (err, res) {
                t.strictEqual(1, res);
                barrier.done('set');
            });
            REDIS.get(sprintf('/policy/%s/%s', account, name),
                function (err, res) {
                t.strictEqual(uuid, res);
                barrier.done('policy');
            });
        });
    });
});

test('modify - rename', function (t) {
    var entry = {
        'dn': 'changenumber=29, cn=changelog',
        'controls': [],
        'targetdn': 'policy-uuid=b4301b32-66b4-11e3-ac31-6b349ce5dc45, ' +
            'uuid=390c229a-8c77-445f-b227-88e41c2bb3cf, ' +
            'ou=users, o=smartdc',
        'changetype': 'modify',
        'objectclass': 'changeLogEntry',
        'changetime': '2014-02-07T18:07:21.401Z',
        'changes': [
            {
                'operation': 'replace',
                'modification': {
                    'type': 'name',
                    'vals': [
                        'newname'
                    ]
                }
            }
        ],
        'entry': JSON.stringify({
            'account': [
                '390c229a-8c77-445f-b227-88e41c2bb3cf'
            ],
            'name': [
                'newname'
            ],
            'objectclass': [
                'sdcaccountpolicy'
            ],
            'rule': [
                'Can read foo and bar when ip = 10.0.0.0/8',
                'Can read red and blue when ip = 10.0.0.0/16'
            ],
            'uuid': [
                'b4301b32-66b4-11e3-ac31-6b349ce5dc45'
            ],
            '_owner': [
                '390c229a-8c77-445f-b227-88e41c2bb3cf'
            ],
            '_parent': [
                'uuid=390c229a-8c77-445f-b227-88e41c2bb3cf, ' +
                    'ou=users, o=smartdc'
            ]
        }),
        'changenumber': '29'
    };

    var args = {
        changes: entry.changes,
        entry: entry,
        modEntry: JSON.parse(entry.entry),
        log: this.log,
        parser: PARSER,
        redis: REDIS
    };

    var uuid = 'b4301b32-66b4-11e3-ac31-6b349ce5dc45';
    var account = '390c229a-8c77-445f-b227-88e41c2bb3cf';
    var oldname = 'developer_read';
    var name = 'newname';

    transform.modify(args, function (err, res) {
        t.strictEqual(4, res.queue.length);
        res.exec(function () {
            var barrier = vasync.barrier();
            barrier.start('oldname');
            barrier.start('newname');
            barrier.start('uuid');
            barrier.on('drain', function () {
                t.done();
            });
            REDIS.get(sprintf('/policy/%s/%s', account, name),
                function (err, res) {

                t.strictEqual(uuid, res);
                barrier.done('newname');
            });
            REDIS.get(sprintf('/policy/%s/%s', account, oldname),
                function (err, res) {

                t.strictEqual(null, res);
                barrier.done('oldname');
            });
            REDIS.get('/uuidv2/' + uuid, function (err, res) {
                t.strictEqual(JSON.parse(res).name, name);
                barrier.done('uuid');
            });
        });
    });
});

test('modify - add policy', function (t) {
    var entry = {
        'dn': 'changenumber=27, cn=changelog',
        'controls': [],
        'targetdn': 'policy-uuid=b4301b32-66b4-11e3-ac31-6b349ce5dc45, ' +
            'uuid=390c229a-8c77-445f-b227-88e41c2bb3cf, ' +
            'ou=users, o=smartdc',
        'changetype': 'modify',
        'objectclass': 'changeLogEntry',
        'changetime': '2014-02-07T18:16:42.246Z',
        'changes': [
            {
                'operation': 'add',
                'modification': {
                    'type': 'rule',
                    'vals': [
                        'Can read x and y when ip = 10.0.0.0/32'
                    ]
                }
            }
        ],
        'entry': JSON.stringify({
            'account': [
                '390c229a-8c77-445f-b227-88e41c2bb3cf'
            ],
            'name': [
                'newname'
            ],
            'objectclass': [
                'sdcaccountpolicy'
            ],
            'rule': [
                'Can read foo and bar when ip = 10.0.0.0/8',
                'Can read red and blue when ip = 10.0.0.0/16',
                'Can read x and y when ip = 10.0.0.0/32'
            ],
            'uuid': [
                'b4301b32-66b4-11e3-ac31-6b349ce5dc45'
            ],
            '_owner': [
                '390c229a-8c77-445f-b227-88e41c2bb3cf'
            ],
            '_parent': [
                'uuid=390c229a-8c77-445f-b227-88e41c2bb3cf, ' +
                    'ou=users, o=smartdc'
            ]
        }),
        'changenumber': '27'
    };

    var args = {
        changes: entry.changes,
        entry: entry,
        modEntry: JSON.parse(entry.entry),
        log: this.log,
        parser: PARSER,
        redis: REDIS
    };

    var uuid = 'b4301b32-66b4-11e3-ac31-6b349ce5dc45';
    var rule = 'Can read x and y when ip = 10.0.0.0/32';

    transform.modify(args, function (err, res) {
        t.strictEqual(res.queue.length, 2);
        res.exec(function () {
            REDIS.get('/uuidv2/' + uuid, function (err, res) {
                t.ok(JSON.parse(res).rules.some(function (r) {
                    return (r[0] === rule);
                }));
                t.done();
            });
        });
    });
});

test('modify - delete policy', function (t) {
    var entry = {
        'dn': 'changenumber=28, cn=changelog',
        'controls': [],
        'targetdn': 'policy-uuid=b4301b32-66b4-11e3-ac31-6b349ce5dc45, ' +
            'uuid=390c229a-8c77-445f-b227-88e41c2bb3cf, ' +
            'ou=users, o=smartdc',
        'changetype': 'modify',
        'objectclass': 'changeLogEntry',
        'changetime': '2014-02-07T18:16:42.315Z',
        'changes': [
            {
                'operation': 'delete',
                'modification': {
                    'type': 'rule',
                    'vals': [
                        'Can read x and y when ip = 10.0.0.0/32'
                    ]
                }
            }
        ],
        'entry': JSON.stringify({
            'account': [
                '390c229a-8c77-445f-b227-88e41c2bb3cf'
            ],
            'name': [
                'newname'
            ],
            'objectclass': [
                'sdcaccountpolicy'
            ],
            'rule': [
                'Can read foo and bar when ip = 10.0.0.0/8',
                'Can read red and blue when ip = 10.0.0.0/16'
            ],
            'uuid': [
                'b4301b32-66b4-11e3-ac31-6b349ce5dc45'
            ],
            '_owner': [
                '390c229a-8c77-445f-b227-88e41c2bb3cf'
            ],
            '_parent': [
                'uuid=390c229a-8c77-445f-b227-88e41c2bb3cf, ' +
                    'ou=users, o=smartdc'
            ]
        }),
        'changenumber': '28'
    };

    var args = {
        changes: entry.changes,
        entry: entry,
        modEntry: JSON.parse(entry.entry),
        log: this.log,
        parser: PARSER,
        redis: REDIS
    };

    var uuid = 'b4301b32-66b4-11e3-ac31-6b349ce5dc45';
    var rule = 'Can read x and y when ip = 10.0.0.0/32';

    transform.modify(args, function (err, res) {
        t.strictEqual(res.queue.length, 2);
        res.exec(function () {
            REDIS.get('/uuidv2/' + uuid, function (err, res) {
                t.notOk(JSON.parse(res).rules.some(function (r) {
                    return (r[0] === rule);
                }));
                t.done();
            });
        });
    });
});

test('modify - replace policy', function (t) {
    var entry = {
        'dn': 'changenumber=28, cn=changelog',
        'controls': [],
        'targetdn': 'policy-uuid=b4301b32-66b4-11e3-ac31-6b349ce5dc45, ' +
            'uuid=390c229a-8c77-445f-b227-88e41c2bb3cf, ' +
            'ou=users, o=smartdc',
        'changetype': 'modify',
        'objectclass': 'changeLogEntry',
        'changetime': '2014-02-07T18:16:42.315Z',
        'changes': [
            {
                'operation': 'replace',
                'modification': {
                    'type': 'rule',
                    'vals': [
                        'Can read x and y when ip = 10.0.0.0/32'
                    ]
                }
            }
        ],
        'entry': JSON.stringify({
            'account': [
                '390c229a-8c77-445f-b227-88e41c2bb3cf'
            ],
            'name': [
                'newname'
            ],
            'objectclass': [
                'sdcaccountpolicy'
            ],
            'rule': [
                'Can read x and y when ip = 10.0.0.0/32'
            ],
            'uuid': [
                'b4301b32-66b4-11e3-ac31-6b349ce5dc45'
            ],
            '_owner': [
                '390c229a-8c77-445f-b227-88e41c2bb3cf'
            ],
            '_parent': [
                'uuid=390c229a-8c77-445f-b227-88e41c2bb3cf, ' +
                    'ou=users, o=smartdc'
            ]
        }),
        'changenumber': '28'
    };

    var args = {
        changes: entry.changes,
        entry: entry,
        modEntry: JSON.parse(entry.entry),
        log: this.log,
        parser: PARSER,
        redis: REDIS
    };

    var uuid = 'b4301b32-66b4-11e3-ac31-6b349ce5dc45';
    var rule = 'Can read x and y when ip = 10.0.0.0/32';

    transform.modify(args, function (err, res) {
        t.strictEqual(res.queue.length, 2);
        res.exec(function () {
            REDIS.get('/uuidv2/' + uuid, function (err, res) {
                t.equal(JSON.parse(res).rules[0][0], rule);
                t.done();
            });
        });
    });
});


test('delete', function (t) {
    var entry = {
        'dn': 'changenumber=30, cn=changelog',
        'controls': [],
        'targetdn': 'policy-uuid=b4301b32-66b4-11e3-ac31-6b349ce5dc45, ' +
            'uuid=390c229a-8c77-445f-b227-88e41c2bb3cf, ' +
            'ou=users, o=smartdc',
        'changetype': 'delete',
        'objectclass': 'changelogentry',
        'changetime': '2014-02-07t18:16:42.402z',
        'changes': {
            'account': [
                '390c229a-8c77-445f-b227-88e41c2bb3cf'
            ],
            'name': [
                'newname'
            ],
            'objectclass': [
                'sdcaccountpolicy'
            ],
            'rule': [
                'can read x and y when ip = 10.0.0.0/24'
            ],
            'uuid': [
                'b4301b32-66b4-11e3-ac31-6b349ce5dc45'
            ],
            '_owner': [
                '390c229a-8c77-445f-b227-88e41c2bb3cf'
            ],
            '_parent': [
                'uuid=390c229a-8c77-445f-b227-88e41c2bb3cf, ' +
                    'ou=users, o=smartdc'
            ]
        },
        'changenumber': '30'
    };

    var args = {
        changes: entry.changes,
        entry: entry,
        log: this.log,
        redis: REDIS
    };
    var uuid = 'b4301b32-66b4-11e3-ac31-6b349ce5dc45';
    var account = '390c229a-8c77-445f-b227-88e41c2bb3cf';
    var name = 'newname';

    transform.delete(args, function (err, res) {
        t.strictEqual(res.queue.length, 4);
        res.exec(function () {
            var barrier = vasync.barrier();
            barrier.start('uuid');
            barrier.start('set');
            barrier.start('policy');
            barrier.on('drain', function () {
                t.done();
            });
            REDIS.get('/uuidv2/' + uuid, function (err, res) {
                t.strictEqual(null, res);
                barrier.done('uuid');
            });
            REDIS.sismember('/set/policies/' + account, uuid,
                function (err, res) {

                t.strictEqual(0, res);
                barrier.done('set');
            });
            REDIS.get(sprintf('/policy/%s/%s', account, name),
                function (err, res) {
                t.strictEqual(null, res);
                barrier.done('policy');
            });
        });
    });
});
