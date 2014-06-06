// Copyright (c) 2014, Joyent, Inc. All rights reserved.

var transform = require('../lib/replicator/transforms/sdcaccountrole.js');

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
        'dn': 'changenumber=17, cn=changelog',
        'controls': [],
        'targetdn': 'group-uuid=5d0049f4-67b3-11e3-8059-273f883b3fb6, ' +
            'uuid=390c229a-8c77-445f-b227-88e41c2bb3cf, ' +
            'ou=users, o=smartdc',
        'changetype': 'add',
        'objectclass': 'changeLogEntry',
        'changetime': '2014-02-24T17:22:18.474Z',
        'changes': {
            'account': [
                '390c229a-8c77-445f-b227-88e41c2bb3cf'
            ],
            'name': [
                'devread'
            ],
            'objectclass': [
                'sdcaccountrole'
            ],
            'uniquemember': [
                'uuid=3ffc7b4c-66a6-11e3-af09-8752d24e4669, ' +
                    'uuid=390c229a-8c77-445f-b227-88e41c2bb3cf, ' +
                    'ou=users, o=smartdc'
            ],
            'uniquememberdefault': [
                'uuid=3ffc7b4c-66a6-11e3-af09-8752d24e4669, ' +
                    'uuid=390c229a-8c77-445f-b227-88e41c2bb3cf, ' +
                    'ou=users, o=smartdc'
            ],
            'uuid': [
                '5d0049f4-67b3-11e3-8059-273f883b3fb6'
            ],
            '_owner': [
                '390c229a-8c77-445f-b227-88e41c2bb3cf'
            ],
            '_parent': [
                'uuid=390c229a-8c77-445f-b227-88e41c2bb3cf, ' +
                    'ou=users, o=smartdc'
            ]
        },
        'changenumber': '17'
    };

    var args = {
        changes: entry.changes,
        entry: entry,
        log: this.log,
        redis: REDIS
    };

    var uuid = '5d0049f4-67b3-11e3-8059-273f883b3fb6';
    var name = 'devread';
    var account = '390c229a-8c77-445f-b227-88e41c2bb3cf';
    var key = '/uuidv2/' + uuid;
    var value = {
        type: 'role',
        name: name,
        uuid: uuid,
        account: account
    };

    transform.add(args, function (err, res) {
        t.strictEqual(5, res.queue.length);
        res.exec(function () {
            var barrier = vasync.barrier();
            barrier.start('role');
            barrier.start('uuid');
            barrier.start('set');
            barrier.start('user');
            barrier.on('drain', function () {
                t.done();
            });
            REDIS.get(key, function (err, res) {
                t.deepEqual(value, JSON.parse(res));
                barrier.done('uuid');
            });
            REDIS.get(sprintf('/role/%s/%s', account, name),
                function (err, res) {

                t.strictEqual(res, uuid);
                barrier.done('role');
            });
            REDIS.sismember('/set/roles/' + account, uuid,
                function (err, res) {

                t.strictEqual(1, res);
                barrier.done('set');
            });
            REDIS.get('/uuidv2/3ffc7b4c-66a6-11e3-af09-8752d24e4669',
                function (err, res) {

                t.ok(JSON.parse(res).roles.indexOf(uuid) >= 0);
                t.ok(JSON.parse(res).defaultRoles.indexOf(uuid) >= 0);
                barrier.done('user');
            });
        });
    });
});

test('modify - add member', function (t) {
    var entry = {
        'dn': 'changenumber=26, cn=changelog',
        'controls': [],
        'targetdn': 'group-uuid=5d0049f4-67b3-11e3-8059-273f883b3fb6, ' +
            'uuid=390c229a-8c77-445f-b227-88e41c2bb3cf, ' +
            'ou=users, o=smartdc',
        'changetype': 'modify',
        'objectclass': 'changeLogEntry',
        'changetime': '2013-12-19T00:58:06.209Z',
        'changes': [
            {
                'operation': 'add',
                'modification': {
                    'type': 'uniquemember',
                    'vals': [
                        'uuid=3ffc7b4c-66a6-11e3-af09-8752d24e4669, ' +
                            'uuid=390c229a-8c77-445f-b227-88e41c2bb3cf, ' +
                            'ou=users, o=smartdc'
                    ]
                }
            }
        ],
        'entry': JSON.stringify({
            'account': [
                '390c229a-8c77-445f-b227-88e41c2bb3cf'
            ],
            'name': [
                'devread'
            ],
            'memberpolicy': [
                'policy-uuid=b4301b32-66b4-11e3-ac31-6b349ce5dc45, ' +
                    'uuid=390c229a-8c77-445f-b227-88e41c2bb3cf, ' +
                    'ou=users, o=smartdc'
            ],
            'objectclass': [
                'sdcaccountrole'
            ],
            'uuid': [
                '5d0049f4-67b3-11e3-8059-273f883b3fb6'
            ],
            '_owner': [
                '390c229a-8c77-445f-b227-88e41c2bb3cf'
            ],
            '_parent': [
                'uuid=390c229a-8c77-445f-b227-88e41c2bb3cf, ' +
                    'ou=users, o=smartdc'
            ],
            'uniquemember': [
                'uuid=3ffc7b4c-66a6-11e3-af09-8752d24e4669, ' +
                    'uuid=390c229a-8c77-445f-b227-88e41c2bb3cf, ' +
                    'ou=users, o=smartdc'
            ]
        }),
        'changenumber': '26'
    };

    var args = {
        changes: entry.changes,
        entry: entry,
        modEntry: JSON.parse(entry.entry),
        log: this.log,
        redis: REDIS
    };

    var uuid = '5d0049f4-67b3-11e3-8059-273f883b3fb6';
    var user = '3ffc7b4c-66a6-11e3-af09-8752d24e4669';
    var key = '/uuidv2/' + user;
    transform.modify(args, function (err, res) {
        t.strictEqual(2, res.queue.length);
        res.exec(function () {
            REDIS.get(key, function (err, res) {
                t.ok(JSON.parse(res).roles.indexOf(uuid) > -1);
                t.done();
            });
        });
    });
});

test('modify - delete member', function (t) {
    var entry = {
        'dn': 'changenumber=27, cn=changelog',
        'controls': [],
        'targetdn': 'group-uuid=5d0049f4-67b3-11e3-8059-273f883b3fb6, ' +
            'uuid=390c229a-8c77-445f-b227-88e41c2bb3cf, ' +
            'ou=users, o=smartdc',
        'changetype': 'modify',
        'objectclass': 'changeLogEntry',
        'changetime': '2013-12-19T00:58:06.226Z',
        'changes': [
            {
                'operation': 'delete',
                'modification': {
                    'type': 'uniquemember',
                    'vals': [
                        'uuid=3ffc7b4c-66a6-11e3-af09-8752d24e4669, ' +
                            'uuid=390c229a-8c77-445f-b227-88e41c2bb3cf, ' +
                            'ou=users, o=smartdc'
                    ]
                }
            }
        ],
        'entry': JSON.stringify({
            'account': [
                '390c229a-8c77-445f-b227-88e41c2bb3cf'
            ],
            'name': [
                'devread'
            ],
            'memberpolicy': [
                'policy-uuid=b4301b32-66b4-11e3-ac31-6b349ce5dc45, ' +
                    'uuid=390c229a-8c77-445f-b227-88e41c2bb3cf, ' +
                    'ou=users, o=smartdc'
            ],
            'objectclass': [
                'sdcaccountrole'
            ],
            'uuid': [
                '5d0049f4-67b3-11e3-8059-273f883b3fb6'
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
        redis: REDIS
    };

    var uuid = '5d0049f4-67b3-11e3-8059-273f883b3fb6';
    var user = '3ffc7b4c-66a6-11e3-af09-8752d24e4669';
    var key = '/uuidv2/' + user;
    transform.modify(args, function (err, res) {
        t.strictEqual(2, res.queue.length);
        res.exec(function () {
            REDIS.get(key, function (err, res) {
                t.strictEqual(JSON.parse(res).roles.indexOf(uuid), -1);
                t.done();
            });
        });
    });
});

test('modify - add policy', function (t) {
    var entry = {
        'dn': 'changenumber=28, cn=changelog',
        'controls': [],
        'targetdn': 'group-uuid=5d0049f4-67b3-11e3-8059-273f883b3fb6, ' +
            'uuid=390c229a-8c77-445f-b227-88e41c2bb3cf, ' +
            'ou=users, o=smartdc',
        'changetype': 'modify',
        'objectclass': 'changeLogEntry',
        'changetime': '2013-12-19T00:58:06.296Z',
        'changes': [
            {
                'operation': 'add',
                'modification': {
                    'type': 'memberpolicy',
                    'vals': [
                        'role-uuid=b4301b32-66b4-11e3-ac31-6b349ce5dc45, ' +
                            'uuid=390c229a-8c77-445f-b227-88e41c2bb3cf, ' +
                            'ou=users, o=smartdc'
                    ]
                }
            }
        ],
        'entry': JSON.stringify({
            'account': [
                '390c229a-8c77-445f-b227-88e41c2bb3cf'
            ],
            'name': [
                'devread'
            ],
            'memberpolicy': [
                'group-uuid=b4301b32-66b4-11e3-ac31-6b349ce5dc45, ' +
                    'uuid=390c229a-8c77-445f-b227-88e41c2bb3cf, ' +
                    'ou=users, o=smartdc'
            ],
            'objectclass': [
                'sdcaccountrole'
            ],
            'uuid': [
                '5d0049f4-67b3-11e3-8059-273f883b3fb6'
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
        redis: REDIS
    };

    var uuid = '5d0049f4-67b3-11e3-8059-273f883b3fb6';
    var role = 'b4301b32-66b4-11e3-ac31-6b349ce5dc45';
    var key = '/uuidv2/' + uuid;
    transform.modify(args, function (err, res) {
        t.strictEqual(2, res.queue.length);
        res.exec(function () {
            REDIS.get(key, function (err, res) {
                t.ok(JSON.parse(res).policies.indexOf(role) > -1);
                t.done();
            });
        });
    });
});

test('modify - delete policy', function (t) {
    var entry = {
        'dn': 'changenumber=29, cn=changelog',
        'controls': [],
        'targetdn': 'group-uuid=5d0049f4-67b3-11e3-8059-273f883b3fb6, ' +
            'uuid=390c229a-8c77-445f-b227-88e41c2bb3cf, ' +
            'ou=users, o=smartdc',
        'changetype': 'modify',
        'objectclass': 'changeLogEntry',
        'changetime': '2013-12-19T00:58:06.310Z',
        'changes': [
            {
                'operation': 'delete',
                'modification': {
                    'type': 'memberpolicy',
                    'vals': [
                        'policy-uuid=b4301b32-66b4-11e3-ac31-6b349ce5dc45, ' +
                            'uuid=390c229a-8c77-445f-b227-88e41c2bb3cf, ' +
                            'ou=users, o=smartdc'
                    ]
                }
            }
        ],
        'entry': JSON.stringify({
            'account': [
                '390c229a-8c77-445f-b227-88e41c2bb3cf'
            ],
            'name': [
                'devread'
            ],
            'objectclass': [
                'sdcaccountrole'
            ],
            'uuid': [
                '5d0049f4-67b3-11e3-8059-273f883b3fb6'
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
        redis: REDIS
    };
    var uuid = '5d0049f4-67b3-11e3-8059-273f883b3fb6';
    var role = 'b4301b32-66b4-11e3-ac31-6b349ce5dc45';
    var key = '/uuidv2/' + uuid;
    transform.modify(args, function (err, res) {
        t.strictEqual(2, res.queue.length);
        res.exec(function () {
            REDIS.get(key, function (err, res) {
                t.strictEqual(JSON.parse(res).policies.indexOf(role), -1);
                t.done();
            });
        });
    });
});

test('modify - add default member', function (t) {
    var entry = {
        'dn': 'changenumber=130, cn=changelog',
        'controls': [],
        'targetdn': 'group-uuid=5d0049f4-67b3-11e3-8059-273f883b3fb6, ' +
            'uuid=390c229a-8c77-445f-b227-88e41c2bb3cf, ' +
            'ou=users, o=smartdc',
        'changetype': 'modify',
        'objectclass': 'changeLogEntry',
        'changetime': '2014-04-09T21:02:42.133Z',
        'changes': [
            {
              'operation': 'add',
              'modification': {
                'type': 'uniquememberdefault',
                'vals': [
                    'uuid=3ffc7b4c-66a6-11e3-af09-8752d24e4669, ' +
                        'uuid=390c229a-8c77-445f-b227-88e41c2bb3cf, ' +
                        'ou=users, o=smartdc'
                ]
              }
            }
        ],
        'entry': JSON.stringify({
              'account': [
                'bde5a308-9e5a-11e3-bbf2-1b6f3d02ff6f'
              ],
              'name': [
                'borrower'
              ],
              'objectclass': [
                'sdcaccountrole'
              ],
              'uniquemember': [
                'uuid=3ffc7b4c-66a6-11e3-af09-8752d24e4669, ' +
                    'uuid=bde5a308-9e5a-11e3-bbf2-1b6f3d02ff6f, ' +
                    'ou=users, o=smartdc'
              ],
              'uuid': [
                '5d0049f4-67b3-11e3-8059-273f883b3fb6'
              ],
              '_owner': [
                'bde5a308-9e5a-11e3-bbf2-1b6f3d02ff6f'
              ],
              '_parent': [
                'uuid=390c229a-8c77-445f-b227-88e41c2bb3cf, ou=users, o=smartdc'
              ],
              'memberpolicy': [
                'policy-uuid=b4301b32-66b4-11e3-ac31-6b349ce5dc45, ' +
                    'uuid=bde5a308-9e5a-11e3-bbf2-1b6f3d02ff6f, ' +
                    'ou=users, o=smartdc'
              ],
              'uniquememberdefault': [
                'uuid=3ffc7b4c-66a6-11e3-af09-8752d24e4669, ' +
                    'uuid=390c229a-8c77-445f-b227-88e41c2bb3cf, ' +
                    'ou=users, o=smartdc'
              ]
        }),
        'changenumber': '130'
    };

    var args = {
        changes: entry.changes,
        entry: entry,
        modEntry: JSON.parse(entry.entry),
        log: this.log,
        redis: REDIS
    };

    var uuid = '5d0049f4-67b3-11e3-8059-273f883b3fb6';
    var user = '3ffc7b4c-66a6-11e3-af09-8752d24e4669';
    var key = '/uuidv2/' + user;
    transform.modify(args, function (err, res) {
        t.strictEqual(2, res.queue.length);
        res.exec(function () {
            REDIS.get(key, function (err, res) {
                t.ok(JSON.parse(res).defaultRoles.indexOf(uuid) > -1);
                t.done();
            });
        });
    });
});

test('modify - delete default member', function (t) {
    var entry = {
        'dn': 'changenumber=130, cn=changelog',
        'controls': [],
        'targetdn': 'group-uuid=5d0049f4-67b3-11e3-8059-273f883b3fb6, ' +
            'uuid=390c229a-8c77-445f-b227-88e41c2bb3cf, ' +
            'ou=users, o=smartdc',
        'changetype': 'modify',
        'objectclass': 'changeLogEntry',
        'changetime': '2014-04-09T21:02:42.133Z',
        'changes': [
            {
              'operation': 'delete',
              'modification': {
                'type': 'uniquememberdefault',
                'vals': [
                    'uuid=3ffc7b4c-66a6-11e3-af09-8752d24e4669, ' +
                        'uuid=390c229a-8c77-445f-b227-88e41c2bb3cf, ' +
                        'ou=users, o=smartdc'
                ]
              }
            }
        ],
        'entry': JSON.stringify({
              'account': [
                'bde5a308-9e5a-11e3-bbf2-1b6f3d02ff6f'
              ],
              'name': [
                'borrower'
              ],
              'objectclass': [
                'sdcaccountrole'
              ],
              'uniquemember': [
                'uuid=3ffc7b4c-66a6-11e3-af09-8752d24e4669, ' +
                    'uuid=bde5a308-9e5a-11e3-bbf2-1b6f3d02ff6f, ' +
                    'ou=users, o=smartdc'
              ],
              'uuid': [
                '5d0049f4-67b3-11e3-8059-273f883b3fb6'
              ],
              '_owner': [
                'bde5a308-9e5a-11e3-bbf2-1b6f3d02ff6f'
              ],
              '_parent': [
                'uuid=390c229a-8c77-445f-b227-88e41c2bb3cf, ou=users, o=smartdc'
              ],
              'memberpolicy': [
                'policy-uuid=b4301b32-66b4-11e3-ac31-6b349ce5dc45, ' +
                    'uuid=bde5a308-9e5a-11e3-bbf2-1b6f3d02ff6f, ' +
                    'ou=users, o=smartdc'
              ],
              'uniquememberdefault': []
        }),
        'changenumber': '130'
    };

    var args = {
        changes: entry.changes,
        entry: entry,
        modEntry: JSON.parse(entry.entry),
        log: this.log,
        redis: REDIS
    };

    var uuid = '5d0049f4-67b3-11e3-8059-273f883b3fb6';
    var user = '3ffc7b4c-66a6-11e3-af09-8752d24e4669';
    var key = '/uuidv2/' + user;
    transform.modify(args, function (err, res) {
        t.strictEqual(2, res.queue.length);
        res.exec(function () {
            REDIS.get(key, function (err, res) {
                t.ok(JSON.parse(res).defaultRoles.indexOf(uuid) === -1);
                t.done();
            });
        });
    });
});

test('delete', function (t) {
    var entry = {
        'dn': 'changenumber=32, cn=changelog',
        'controls': [],
        'targetdn': 'group-uuid=5d0049f4-67b3-11e3-8059-273f883b3fb6, ' +
            'uuid=390c229a-8c77-445f-b227-88e41c2bb3cf, ' +
            'ou=users, o=smartdc',
        'changetype': 'delete',
        'objectclass': 'changeLogEntry',
        'changetime': '2013-12-19T00:58:06.584Z',
        'changes': {
            'account': [
                '390c229a-8c77-445f-b227-88e41c2bb3cf'
            ],
            'name': [
                'devread'
            ],
            'objectclass': [
                'sdcaccountrole'
            ],
            'uuid': [
                '5d0049f4-67b3-11e3-8059-273f883b3fb6'
            ],
            '_owner': [
                '390c229a-8c77-445f-b227-88e41c2bb3cf'
            ],
            '_parent': [
                'uuid=390c229a-8c77-445f-b227-88e41c2bb3cf, ' +
                    'ou=users, o=smartdc'
            ],
            'uniquemember': [
                'uuid=3ffc7b4c-66a6-11e3-af09-8752d24e4669, ' +
                    'uuid=390c229a-8c77-445f-b227-88e41c2bb3cf, ' +
                    'ou=users, o=smartdc'
            ],
            'uniquememberdefault': [
                'uuid=3ffc7b4c-66a6-11e3-af09-8752d24e4669, ' +
                    'uuid=390c229a-8c77-445f-b227-88e41c2bb3cf, ' +
                    'ou=users, o=smartdc'
            ],
            'memberrole': []
        },
        'changenumber': '32'
    };

    var args = {
        changes: entry.changes,
        entry: entry,
        log: this.log,
        redis: REDIS
    };

    var uuid = '5d0049f4-67b3-11e3-8059-273f883b3fb6';
    var account = '390c229a-8c77-445f-b227-88e41c2bb3cf';
    var name = 'devread';
    var key = '/uuidv2/' + uuid;

    transform.delete(args, function (err, res) {
        t.strictEqual(5, res.queue.length);
        res.exec(function () {
            var barrier = vasync.barrier();
            barrier.start('uuid');
            barrier.start('group');
            barrier.start('set');
            barrier.start('user');
            barrier.on('drain', function () {
                t.done();
            });
            REDIS.get(key, function (err, res) {
                t.strictEqual(res, null);
                barrier.done('uuid');
            });
            REDIS.get(sprintf('/roles/%s/%s', account, name),
                function (err, res) {
                t.strictEqual(res, null);
                barrier.done('group');
            });
            REDIS.sismember('/set/roles/' + account, uuid,
                function (err, res) {

                t.strictEqual(0, res);
                barrier.done('set');
            });
            REDIS.get('/uuidv2/3ffc7b4c-66a6-11e3-af09-8752d24e4669',
                function (err, res) {

                t.ok(JSON.parse(res).roles.indexOf(uuid) < 0);
                t.ok(JSON.parse(res).defaultRoles.indexOf(uuid) < 0);
                barrier.done('user');
            });
        });
    });
});
