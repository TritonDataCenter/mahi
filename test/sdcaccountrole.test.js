/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright (c) 2014, Joyent, Inc.
 * Copyright 2025 Edgecast Cloud LLC.
 */

var transform = require('../lib/replicator/transforms/sdcaccountrole.js');

var bunyan = require('bunyan');
var redis = require('fakeredis');
var REDIS;

var nodeunit = require('nodeunit-plus');
var vasync = require('vasync');
var test = nodeunit.test;

var sprintf = require('util').format;

// Create a test logger
var LOG = bunyan.createLogger({
    name: 'sdcaccountrole-test',
    level: process.env.LOG_LEVEL || 'fatal'
});

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
        log: LOG,
        redis: REDIS
    };

    var uuid = '5d0049f4-67b3-11e3-8059-273f883b3fb6';
    var name = 'devread';
    var account = '390c229a-8c77-445f-b227-88e41c2bb3cf';
    var key = '/uuid/' + uuid;
    var value = {
        type: 'role',
        name: name,
        uuid: uuid,
        account: account,
        assumerolepolicydocument: null
    };

    transform.add(args, function (err, res) {
        t.strictEqual(8, res.queue.length);
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
            REDIS.get('/uuid/3ffc7b4c-66a6-11e3-af09-8752d24e4669',
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
        log: LOG,
        redis: REDIS
    };

    var uuid = '5d0049f4-67b3-11e3-8059-273f883b3fb6';
    var user = '3ffc7b4c-66a6-11e3-af09-8752d24e4669';
    var key = '/uuid/' + user;
    transform.modify(args, function (err, res) {
        t.strictEqual(3, res.queue.length);
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
        log: LOG,
        redis: REDIS
    };

    var uuid = '5d0049f4-67b3-11e3-8059-273f883b3fb6';
    var user = '3ffc7b4c-66a6-11e3-af09-8752d24e4669';
    var key = '/uuid/' + user;
    transform.modify(args, function (err, res) {
        t.strictEqual(3, res.queue.length);
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
        log: LOG,
        redis: REDIS
    };

    var uuid = '5d0049f4-67b3-11e3-8059-273f883b3fb6';
    var role = 'b4301b32-66b4-11e3-ac31-6b349ce5dc45';
    var key = '/uuid/' + uuid;
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
        log: LOG,
        redis: REDIS
    };
    var uuid = '5d0049f4-67b3-11e3-8059-273f883b3fb6';
    var role = 'b4301b32-66b4-11e3-ac31-6b349ce5dc45';
    var key = '/uuid/' + uuid;
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
        log: LOG,
        redis: REDIS
    };

    var uuid = '5d0049f4-67b3-11e3-8059-273f883b3fb6';
    var user = '3ffc7b4c-66a6-11e3-af09-8752d24e4669';
    var key = '/uuid/' + user;
    transform.modify(args, function (err, res) {
        t.strictEqual(3, res.queue.length);
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
        log: LOG,
        redis: REDIS
    };

    var uuid = '5d0049f4-67b3-11e3-8059-273f883b3fb6';
    var user = '3ffc7b4c-66a6-11e3-af09-8752d24e4669';
    var key = '/uuid/' + user;
    transform.modify(args, function (err, res) {
        t.strictEqual(3, res.queue.length);
        res.exec(function () {
            REDIS.get(key, function (err, res) {
                t.ok(JSON.parse(res).defaultRoles.indexOf(uuid) === -1);
                t.done();
            });
        });
    });
});

test('modify - add member and defaultmember', function (t) {
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
                        'uuid=4ffc7b4c-66a6-11e3-af09-8752d24e4669, ' +
                            'uuid=390c229a-8c77-445f-b227-88e41c2bb3cf, ' +
                            'ou=users, o=smartdc'
                    ]
                }
            },
            {
                'operation': 'add',
                'modification': {
                    'type': 'uniquememberdefault',
                    'vals': [
                        'uuid=4ffc7b4c-66a6-11e3-af09-8752d24e4669, ' +
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
                'uuid=4ffc7b4c-66a6-11e3-af09-8752d24e4669, ' +
                    'uuid=390c229a-8c77-445f-b227-88e41c2bb3cf, ' +
                    'ou=users, o=smartdc'
            ],
            'uniquememberdefault': [
                'uuid=4ffc7b4c-66a6-11e3-af09-8752d24e4669, ' +
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
        log: LOG,
        redis: REDIS
    };

    var uuid = '5d0049f4-67b3-11e3-8059-273f883b3fb6';
    var user = '4ffc7b4c-66a6-11e3-af09-8752d24e4669';
    var key = '/uuid/' + user;
    transform.modify(args, function (err, res) {
        t.strictEqual(5, res.queue.length);
        res.exec(function () {
            REDIS.get(key, function (err, res) {
                t.ok(JSON.parse(res).roles.indexOf(uuid) > -1);
                t.ok(JSON.parse(res).defaultRoles.indexOf(uuid) > -1);
                t.done();
            });
        });
    });
});


test('modify - rename', function (t) {
    var entry = {
        'dn': 'changenumber=1707160, cn=changelog',
        'controls': [],
        'targetdn': 'role-uuid=5d0049f4-67b3-11e3-8059-273f883b3fb6, ' +
            'uuid=390c229a-8c77-445f-b227-88e41c2bb3cf, ' +
            'ou=users, o=smartdc',
        'changetype': 'modify',
        'objectclass': 'changeLogEntry',
        'changetime': '2015-02-04T17:54:36.981Z',
        'changes': [
            {
                'operation': 'replace',
                'modification': {
                    'type': 'name',
                    'vals': [
                        'rename1'
                    ]
                }
            }
        ],
        'entry': JSON.stringify({
            '_owner': [
                '390c229a-8c77-445f-b227-88e41c2bb3cf'
            ],
            '_parent': [
                'uuid=5d0049f4-67b3-11e3-8059-273f883b3fb6, ou=users, o=smartdc'
            ],
            '_replicated': [
                'true'
            ],
            'account': [
                '390c229a-8c77-445f-b227-88e41c2bb3cf'
            ],
            'name': [
                'rename1'
            ],
            'objectclass': [
                'sdcaccountrole'
            ],
            'uuid': [
                '5d0049f4-67b3-11e3-8059-273f883b3fb6'
            ]
        }),
        'changenumber': '1707160'
    };

    var args = {
        changes: entry.changes,
        entry: entry,
        modEntry: JSON.parse(entry.entry),
        log: LOG,
        redis: REDIS
    };

    var uuid = '5d0049f4-67b3-11e3-8059-273f883b3fb6';
    var key = '/uuid/' + uuid;
    transform.modify(args, function (err, res) {
        t.strictEqual(4, res.queue.length);
        res.exec(function () {
            REDIS.get(key, function (err, res) {
                t.ok(JSON.parse(res).name === 'rename1');
                t.done();
            });
        });
    });
});

test('add - role with assumerolepolicydocument', function (t) {
    var trustPolicy = JSON.stringify({
        'Version': '2012-10-17',
        'Statement': [ {
            'Effect': 'Allow',
            'Principal': {'AWS': 'arn:aws:iam::123456789012:user/testuser'},
            'Action': 'sts:AssumeRole'
        }]
    });

    var entry = {
        'dn': 'changenumber=18, cn=changelog',
        'controls': [],
        'targetdn': 'group-uuid=6e00a9f4-67b3-11e3-8059-273f883b3fb6, ' +
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
                'sts-assumerole'
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
                '6e00a9f4-67b3-11e3-8059-273f883b3fb6'
            ],
            '_owner': [
                '390c229a-8c77-445f-b227-88e41c2bb3cf'
            ],
            '_parent': [
                'uuid=390c229a-8c77-445f-b227-88e41c2bb3cf, ' +
                    'ou=users, o=smartdc'
            ],
            'assumerolepolicydocument': [
                trustPolicy
            ]
        },
        'changenumber': '18'
    };

    var args = {
        changes: entry.changes,
        entry: entry,
        log: LOG,
        redis: REDIS
    };

    var uuid = '6e00a9f4-67b3-11e3-8059-273f883b3fb6';
    var name = 'sts-assumerole';
    var account = '390c229a-8c77-445f-b227-88e41c2bb3cf';
    var key = '/uuid/' + uuid;
    var value = {
        type: 'role',
        name: name,
        uuid: uuid,
        account: account,
        assumerolepolicydocument: trustPolicy
    };

    transform.add(args, function (err, res) {
        t.strictEqual(8, res.queue.length);
        res.exec(function () {
            var barrier = vasync.barrier();
            barrier.start('role');
            barrier.start('uuid');
            barrier.start('set');
            barrier.start('user');
            barrier.start('trustpolicy');
            barrier.on('drain', function () {
                t.done();
            });
            REDIS.get(key, function (err, res) {
                var roleData = JSON.parse(res);
                t.deepEqual(roleData.type, value.type);
                t.deepEqual(roleData.name, value.name);
                t.deepEqual(roleData.uuid, value.uuid);
                t.deepEqual(roleData.account, value.account);
                t.deepEqual(roleData.assumerolepolicydocument,
                           value.assumerolepolicydocument);
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
            REDIS.get('/uuid/3ffc7b4c-66a6-11e3-af09-8752d24e4669',
                function (err, res) {
                t.ok(JSON.parse(res).roles.indexOf(uuid) >= 0);
                t.ok(JSON.parse(res).defaultRoles.indexOf(uuid) >= 0);
                barrier.done('user');
            });
            // Verify trust policy is stored correctly
            REDIS.get(key, function (err, res) {
                var parsed = JSON.parse(res);
                var trustPolicyObj = JSON.parse(
                    parsed.assumerolepolicydocument);
                t.strictEqual(trustPolicyObj.Version, '2012-10-17');
                t.ok(trustPolicyObj.Statement);
                t.ok(trustPolicyObj.Statement.length > 0);
                t.strictEqual(trustPolicyObj.Statement[0].Effect, 'Allow');
                t.strictEqual(trustPolicyObj.Statement[0].Action,
                             'sts:AssumeRole');
                barrier.done('trustpolicy');
            });
        });
    });
});

test('modify - add assumerolepolicydocument', function (t) {
    var newTrustPolicy = JSON.stringify({
        'Version': '2012-10-17',
        'Statement': [
            {
                'Effect': 'Allow',
                'Principal': {
                    'AWS': 'arn:aws:iam::123456789012:user/newuser'
                },
                'Action': 'sts:AssumeRole'
            }
        ]
    });

    var entry = {
        'dn': 'changenumber=30, cn=changelog',
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
                    'type': 'assumerolepolicydocument',
                    'vals': [
                        newTrustPolicy
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
            ],
            'assumerolepolicydocument': [
                newTrustPolicy
            ]
        }),
        'changenumber': '30'
    };

    var args = {
        changes: entry.changes,
        entry: entry,
        modEntry: JSON.parse(entry.entry),
        log: LOG,
        redis: REDIS
    };

    var uuid = '5d0049f4-67b3-11e3-8059-273f883b3fb6';
    var key = '/uuid/' + uuid;

    transform.modify(args, function (err, res) {
        t.strictEqual(2, res.queue.length);
        res.exec(function () {
            REDIS.get(key, function (err, res) {
                var roleData = JSON.parse(res);
                t.strictEqual(roleData.assumerolepolicydocument,
                             newTrustPolicy);
                // Validate trust policy structure
                var trustPolicyObj = JSON.parse(
                    roleData.assumerolepolicydocument);
                t.strictEqual(trustPolicyObj.Version, '2012-10-17');
                t.strictEqual(trustPolicyObj.Statement[0].Principal.AWS,
                    'arn:aws:iam::123456789012:user/newuser');
                t.done();
            });
        });
    });
});

test('modify - replace assumerolepolicydocument', function (t) {
    var updatedTrustPolicy = JSON.stringify({
        'Version': '2012-10-17',
        'Statement': [
            {
                'Effect': 'Allow',
                'Principal': {
                    'Service': 'lambda.amazonaws.com'
                },
                'Action': 'sts:AssumeRole'
            },
            {
                'Effect': 'Deny',
                'Principal': {
                    'AWS': 'arn:aws:iam::123456789012:user/denieduser'
                },
                'Action': 'sts:AssumeRole'
            }
        ]
    });

    var entry = {
        'dn': 'changenumber=31, cn=changelog',
        'controls': [],
        'targetdn': 'group-uuid=5d0049f4-67b3-11e3-8059-273f883b3fb6, ' +
            'uuid=390c229a-8c77-445f-b227-88e41c2bb3cf, ' +
            'ou=users, o=smartdc',
        'changetype': 'modify',
        'objectclass': 'changeLogEntry',
        'changetime': '2013-12-19T00:58:07.100Z',
        'changes': [
            {
                'operation': 'replace',
                'modification': {
                    'type': 'assumerolepolicydocument',
                    'vals': [
                        updatedTrustPolicy
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
            ],
            'assumerolepolicydocument': [
                updatedTrustPolicy
            ]
        }),
        'changenumber': '31'
    };

    var args = {
        changes: entry.changes,
        entry: entry,
        modEntry: JSON.parse(entry.entry),
        log: LOG,
        redis: REDIS
    };

    var uuid = '5d0049f4-67b3-11e3-8059-273f883b3fb6';
    var key = '/uuid/' + uuid;

    transform.modify(args, function (err, res) {
        t.strictEqual(2, res.queue.length);
        res.exec(function () {
            REDIS.get(key, function (err, res) {
                var roleData = JSON.parse(res);
                t.strictEqual(roleData.assumerolepolicydocument,
                             updatedTrustPolicy);
                // Validate complex trust policy with multiple statements
                var trustPolicyObj = JSON.parse(
                    roleData.assumerolepolicydocument);
                t.strictEqual(trustPolicyObj.Statement.length, 2);
                t.strictEqual(trustPolicyObj.Statement[0].Effect, 'Allow');
                t.strictEqual(trustPolicyObj.Statement[0].Principal.Service,
                             'lambda.amazonaws.com');
                t.strictEqual(trustPolicyObj.Statement[1].Effect, 'Deny');
                t.strictEqual(trustPolicyObj.Statement[1].Principal.AWS,
                    'arn:aws:iam::123456789012:user/denieduser');
                t.done();
            });
        });
    });
});

test('add - role without assumerolepolicydocument', function (t) {
    var entry = {
        'dn': 'changenumber=19, cn=changelog',
        'controls': [],
        'targetdn': 'group-uuid=7f00b9f4-67b3-11e3-8059-273f883b3fb6, ' +
            'uuid=390c229a-8c77-445f-b227-88e41c2bb3cf, ' +
            'ou=users, o=smartdc',
        'changetype': 'add',
        'objectclass': 'changeLogEntry',
        'changetime': '2014-02-24T17:22:19.000Z',
        'changes': {
            'account': [
                '390c229a-8c77-445f-b227-88e41c2bb3cf'
            ],
            'name': [
                'legacy-role'
            ],
            'objectclass': [
                'sdcaccountrole'
            ],
            'uuid': [
                '7f00b9f4-67b3-11e3-8059-273f883b3fb6'
            ],
            '_owner': [
                '390c229a-8c77-445f-b227-88e41c2bb3cf'
            ],
            '_parent': [
                'uuid=390c229a-8c77-445f-b227-88e41c2bb3cf, ' +
                    'ou=users, o=smartdc'
            ]
            // No assumerolepolicydocument field
        },
        'changenumber': '19'
    };

    var args = {
        changes: entry.changes,
        entry: entry,
        log: LOG,
        redis: REDIS
    };

    var uuid = '7f00b9f4-67b3-11e3-8059-273f883b3fb6';
    var name = 'legacy-role';
    var account = '390c229a-8c77-445f-b227-88e41c2bb3cf';
    var key = '/uuid/' + uuid;

    transform.add(args, function (err, res) {
        t.ok(res.queue.length >= 3, 'Should have at least 3 operations');
        res.exec(function () {
            REDIS.get(key, function (err, res) {
                var roleData = JSON.parse(res);
                t.strictEqual(roleData.type, 'role');
                t.strictEqual(roleData.name, name);
                t.strictEqual(roleData.uuid, uuid);
                t.strictEqual(roleData.account, account);
                // Verify assumerolepolicydocument is null when not provided
                t.strictEqual(roleData.assumerolepolicydocument, null);
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
        log: LOG,
        redis: REDIS
    };

    var uuid = '5d0049f4-67b3-11e3-8059-273f883b3fb6';
    var account = '390c229a-8c77-445f-b227-88e41c2bb3cf';
    var name = 'devread';
    var key = '/uuid/' + uuid;

    transform.delete(args, function (err, res) {
        t.strictEqual(9, res.queue.length);
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
            REDIS.get('/uuid/3ffc7b4c-66a6-11e3-af09-8752d24e4669',
                function (err, res) {

                t.ok(JSON.parse(res).roles.indexOf(uuid) < 0);
                t.ok(JSON.parse(res).defaultRoles.indexOf(uuid) < 0);
                barrier.done('user');
            });
        });
    });
});
