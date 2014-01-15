/*
 * Test suite for transformer.js
 * Requires a redis instance
 */

var transformer = require('../lib/transformer.js');
var nodeunit = require('nodeunit-plus');
var vasync = require('vasync');
var sprintf = require('util').format;
var before = nodeunit.before;
var after = nodeunit.after;
var test = nodeunit.test;

test('getDNValue', function (t) {
    var dn = 'uuid=foo, ou=users, o=smartdc';
    t.equal(transformer.getDNValue(dn, 0), 'foo');
    t.equal(transformer.getDNValue(dn, 1), 'users');
    t.equal(transformer.getDNValue(dn, 2), 'smartdc');
    t.end();
});



before(function (cb) {
    this.log = nodeunit.createLogger('transformer', process.stderr);

    this.redis = require('redis').createClient({
        host: 'localhost',
        port: 6379
    });

    this.transformer = new transformer.Transformer({
        redis: this.redis,
        log: this.log
    });

    cb();
});

after(function (cb) {
    var self = this;
    self.redis.flushdb(function (err, res) {
        self.redis.quit();
        cb(err, res);
    });
});

test('groupofuniquenames', function (t) {
    var self = this;
    vasync.pipeline({funcs: [
        // postcondition:
        // 930896af-bf8c-48d4-885c-6573a94b1853: operators
        function putGroup(_, cb) {
            var entry = {
              'dn': 'changenumber=14, cn=changelog',
              'controls': [],
              'targetdn': 'cn=operators, ou=groups, o=smartdc',
              'changetype': 'add',
              'objectclass': 'changeLogEntry',
              'changetime': '2013-12-03T18:29:25.272Z',
              'changes': {
                'objectclass': [
                  'groupofuniquenames'
                ],
                'uniquemember': [
                  'uuid=930896af-bf8c-48d4-885c-6573a94b1853, ' +
                    'ou=users, o=smartdc'
                ],
                '_parent': [
                  'ou=groups, o=smartdc'
                ]
              },
              'changenumber': '14'
            };

            var args = {
                batch: self.redis.multi(),
                entry: entry,
                changes: entry.changes
            };

            var key = '/uuid/930896af-bf8c-48d4-885c-6573a94b1853';
            var value = JSON.stringify({'groups':{'operators':true}});

            self.transformer.transform(args, function (err, res) {
                t.equal(2, res.queue.length);
                t.deepEqual(res.queue[1], [
                    'set',
                    key,
                    value
                ]);
                res.exec(function () {
                    self.redis.get(key, function (redisErr, redisRes){
                        t.strictEqual(value, redisRes);
                        cb();
                    });
                });
            });
        },
        // postcondition
        // 930896af-bf8c-48d4-885c-6573a94b1853: operators, admins
        // 1a940615-65e9-4856-95f9-f4c530e86ca4: admins
        function putGroupMultiple(_, cb) {
            var entry = {
              'dn': 'changenumber=14, cn=changelog',
              'controls': [],
              'targetdn': 'cn=admins, ou=groups, o=smartdc',
              'changetype': 'add',
              'objectclass': 'changeLogEntry',
              'changetime': '2013-12-03T18:29:25.272Z',
              'changes': {
                'objectclass': [
                  'groupofuniquenames'
                ],
                'uniquemember': [
                  'uuid=930896af-bf8c-48d4-885c-6573a94b1853, ' +
                    'ou=users, o=smartdc',
                  'uuid=1a940615-65e9-4856-95f9-f4c530e86ca4, ' +
                    'ou=users, o=smartdc'
                ],
                '_parent': [
                  'ou=groups, o=smartdc'
                ]
              },
              'changenumber': '14'
            };

            var args = {
                batch: self.redis.multi(),
                entry: entry,
                changes: entry.changes
            };

            var key1 = '/uuid/930896af-bf8c-48d4-885c-6573a94b1853';
            var key2 = '/uuid/1a940615-65e9-4856-95f9-f4c530e86ca4';
            var value1 = JSON.stringify({
                'groups':{
                    'operators':true,
                    'admins': true
                }
            });
            var value2 = JSON.stringify({'groups':{'admins':true}});

            self.transformer.transform(args, function (err, res) {
                t.equal(3, res.queue.length);
                t.deepEqual(res.queue[1], [
                    'set',
                    key1,
                    value1
                ]);
                t.deepEqual(res.queue[2], [
                    'set',
                    key2,
                    value2
                ]);
                res.exec(function () {
                    self.redis.get(key1, function (redisErr, redisRes) {
                        t.strictEqual(value1, redisRes);
                        self.redis.get(key2, function (redisErr2, redisRes2) {
                            t.strictEqual(value2, redisRes2);
                            cb();
                        });
                    });
                });
            });
        },
        // postcondition
        // 930896af-bf8c-48d4-885c-6573a94b1853: operators, admins
        // 1a940615-65e9-4856-95f9-f4c530e86ca4: admins
        function putGroupEmpty(_, cb) {
            var entry = {
              'dn': 'changenumber=14, cn=changelog',
              'controls': [],
              'targetdn': 'cn=empty, ou=groups, o=smartdc',
              'changetype': 'add',
              'objectclass': 'changeLogEntry',
              'changetime': '2013-12-03T18:29:25.272Z',
              'changes': {
                'objectclass': [
                  'groupofuniquenames'
                ],
                '_parent': [
                  'ou=groups, o=smartdc'
                ]
              },
              'changenumber': '14'
            };

            var args = {
                batch: self.redis.multi(),
                entry: entry,
                changes: entry.changes
            };

            self.transformer.transform(args, function (err, res) {
                t.equal(1, res.queue.length); // only one element: 'MULTI'
                res.exec(function () {
                    cb();
                });
            });
        },
        // postcondition
        // 1a940615-65e9-4856-95f9-f4c530e86ca4: operators, admins
        // 930896af-bf8c-48d4-885c-6573a94b1853: operators, admins
        // a820621a-5007-4a2a-9636-edde809106de: operators
        function modGroup(_, cb) {
            var entry = {
              'dn': 'changenumber=15, cn=changelog',
              'controls': [],
              'targetdn': 'cn=operators, ou=groups, o=smartdc',
              'changetype': 'modify',
              'objectclass': 'changeLogEntry',
              'changetime': '2013-12-10T19:23:21.228Z',
              'changes': [
                {
                  'operation': 'add',
                  'modification': {
                    'type': 'uniquemember',
                    'vals': [
                      'uuid=a820621a-5007-4a2a-9636-edde809106de, ' +
                        'ou=users, o=smartdc',
                      'uuid=1a940615-65e9-4856-95f9-f4c530e86ca4, ' +
                        'ou=users, o=smartdc'
                    ]
                  }
                }
              ],
              'entry': JSON.stringify({
                  'objectclass': [
                    'groupofuniquenames'
                  ],
                  'uniquemember': [
                    'uuid=1a940615-65e9-4856-95f9-f4c530e86ca4, ' +
                        'ou=users, o=smartdc',
                    'uuid=930896af-bf8c-48d4-885c-6573a94b1853, ' +
                        'ou=users, o=smartdc',
                    'uuid=a820621a-5007-4a2a-9636-edde809106de, ' +
                        'ou=users, o=smartdc'
                  ],
                  '_parent': [
                    'ou=groups, o=smartdc'
                  ]
                }),
              'changenumber': '15'
            };

            var key1 = '/uuid/1a940615-65e9-4856-95f9-f4c530e86ca4';
            var key2 = '/uuid/930896af-bf8c-48d4-885c-6573a94b1853';
            var key3 = '/uuid/a820621a-5007-4a2a-9636-edde809106de';
            var args = {
                batch: self.redis.multi(),
                entry: entry,
                changes: entry.changes
            };

            self.transformer.transform(args, function (err, res) {
                t.strictEqual(3, res.queue.length);
                res.exec(function () {
                    var barrier = vasync.barrier();
                    barrier.start('1');
                    barrier.start('2');
                    barrier.start('3');
                    barrier.on('drain', function () {
                        cb();
                    });
                    self.redis.get(key1, function (redisErr, redisRes) {
                        t.ok(JSON.parse(redisRes).groups.operators);
                        t.ok(JSON.parse(redisRes).groups.admins);
                        barrier.done('1');
                    });
                    self.redis.get(key2, function (redisErr, redisRes) {
                        t.ok(JSON.parse(redisRes).groups.operators);
                        t.ok(JSON.parse(redisRes).groups.admins);
                        barrier.done('2');
                    });
                    self.redis.get(key3, function (redisErr, redisRes) {
                        t.ok(JSON.parse(redisRes).groups.operators);
                        barrier.done('3');
                    });
                });
            });
        },
        // postcondition
        // 1a940615-65e9-4856-95f9-f4c530e86ca4: admins
        // 930896af-bf8c-48d4-885c-6573a94b1853: admins
        // a820621a-5007-4a2a-9636-edde809106de: {}
        function delGroup(_, cb) {
            var entry = {
              'dn': 'changenumber=16, cn=changelog',
              'controls': [],
              'targetdn': 'cn=operators, ou=groups, o=smartdc',
              'changetype': 'delete',
              'objectclass': 'changeLogEntry',
              'changetime': '2013-12-10T19:25:23.214Z',
              'changes': {
                'objectclass': [
                  'groupofuniquenames'
                ],
                'uniquemember': [
                  'uuid=1a940615-65e9-4856-95f9-f4c530e86ca4, ' +
                    'ou=users, o=smartdc',
                  'uuid=930896af-bf8c-48d4-885c-6573a94b1853, ' +
                    'ou=users, o=smartdc',
                  'uuid=a820621a-5007-4a2a-9636-edde809106de, ' +
                    'ou=users, o=smartdc',
                  'uuid=f445c6e2-61e9-11e3-a740-03049cda7ff9, ' +
                    'ou=users, o=smartdc'
                ],
                '_parent': [
                  'ou=groups, o=smartdc'
                ]
              },
              'changenumber': '16'
            };

            var args = {
                batch: self.redis.multi(),
                entry: entry,
                changes: entry.changes
            };

            var key1 = '/uuid/1a940615-65e9-4856-95f9-f4c530e86ca4';
            var key2 = '/uuid/930896af-bf8c-48d4-885c-6573a94b1853';
            var key3 = '/uuid/a820621a-5007-4a2a-9636-edde809106de';
            var key4 = '/uuid/f445c6e2-61e9-11e3-a740-03049cda7ff9';
            var value = JSON.stringify({groups: {'admins': true}});

            self.transformer.transform(args, function (err, res) {
                t.equal(5, res.queue.length);
                t.deepEqual(res.queue[1],[
                    'set',
                    key1,
                    value
                ]);
                t.deepEqual(res.queue[2],[
                    'set',
                    key2,
                    value
                ]);
                res.exec(function () {
                    var barrier = vasync.barrier();
                    barrier.start('1');
                    barrier.start('2');
                    barrier.start('3');
                    barrier.start('4');
                    barrier.on('drain', function () {
                        cb();
                    });
                    self.redis.get(key1, function (redisErr, redisRes) {
                        t.strictEqual(redisRes, value);
                        barrier.done('1');
                    });
                    self.redis.get(key2, function (redisErr, redisRes) {
                        t.strictEqual(redisRes, value);
                        barrier.done('2');
                    });
                    self.redis.get(key3, function (redisErr, redisRes) {
                        t.strictEqual(redisRes, JSON.stringify({groups: {}}));
                        barrier.done('3');
                    });
                    self.redis.get(key4, function (redisErr, redisRes) {
                        t.strictEqual(redisRes, JSON.stringify({groups: {}}));
                        barrier.done('4');
                    });
                });
            });
        }
    ]}, function () {
        t.end();
    });
});


test('sdcaccountgroup', function (t) {
    var self = this;
    vasync.pipeline({funcs: [
        function putAccountGroup(_, cb) {
            var entry = {
              'dn': 'changenumber=24, cn=changelog',
              'controls': [],
              'targetdn': 'group-uuid=5d0049f4-67b3-11e3-8059-273f883b3fb6, ' +
                'uuid=390c229a-8c77-445f-b227-88e41c2bb3cf, ' +
                'ou=users, o=smartdc',
              'changetype': 'add',
              'objectclass': 'changeLogEntry',
              'changetime': '2013-12-19T00:58:06.125Z',
              'changes': {
                'account': [
                  '390c229a-8c77-445f-b227-88e41c2bb3cf'
                ],
                'cn': [
                  'devread'
                ],
                'memberrole': [
                  'role-uuid=b4301b32-66b4-11e3-ac31-6b349ce5dc45, ' +
                    'uuid=390c229a-8c77-445f-b227-88e41c2bb3cf, ' +
                    'ou=users, o=smartdc'
                ],
                'objectclass': [
                  'sdcaccountgroup'
                ],
                'uniquemember': [
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
              'changenumber': '24'
            };

            var args = {
                batch: self.redis.multi(),
                entry: entry,
                changes: entry.changes
            };
            var uuid = '5d0049f4-67b3-11e3-8059-273f883b3fb6';
            var name = 'devread';
            var account = '390c229a-8c77-445f-b227-88e41c2bb3cf';
            var key = '/uuid/' + uuid;
            var value = {
                type: 'group',
                name: name,
                account: account,
                roles: ['b4301b32-66b4-11e3-ac31-6b349ce5dc45']
            };

            self.transformer.transform(args, function (err, res) {
                t.strictEqual(5, res.queue.length);
                res.exec(function () {
                    var barrier = vasync.barrier();
                    barrier.start('group');
                    barrier.start('uuid');
                    barrier.start('set');
                    barrier.start('user');
                    barrier.on('drain', function () {
                        cb();
                    });
                    self.redis.get(key, function (err, res) {
                        t.deepEqual(value, JSON.parse(res));
                        barrier.done('uuid');
                    });
                    self.redis.get(sprintf('/group/%s/%s', account, name),
                        function (err, res) {

                        t.strictEqual(res, uuid);
                        barrier.done('group');
                    });
                    self.redis.sismember('/set/groups/' + account, uuid,
                        function (err, res) {

                        t.strictEqual(1, res);
                        barrier.done('set');
                    });
                    self.redis.get('/uuid/3ffc7b4c-66a6-11e3-af09-8752d24e4669',
                        function (err, res) {

                        t.ok(JSON.parse(res).groups.indexOf(uuid) >= 0);
                        barrier.done('user');
                    });
                });
            });
        },
        function addMember(_, cb) {
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
                'cn': [
                  'devread'
                ],
                'memberrole': [
                  'role-uuid=b4301b32-66b4-11e3-ac31-6b349ce5dc45, ' +
                    'uuid=390c229a-8c77-445f-b227-88e41c2bb3cf, ' +
                    'ou=users, o=smartdc'
                ],
                'objectclass': [
                  'sdcaccountgroup'
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
                batch: self.redis.multi(),
                entry: entry,
                changes: entry.changes
            };
            var uuid = '5d0049f4-67b3-11e3-8059-273f883b3fb6';
            var user = '3ffc7b4c-66a6-11e3-af09-8752d24e4669';
            var key = '/uuid/' + user;
            self.transformer.transform(args, function (err, res) {
                t.strictEqual(2, res.queue.length);
                self.redis.get(key, function (err, res) {
                    t.ok(JSON.parse(res).groups.indexOf(uuid) > -1);
                    cb();
                });
            });
        },
        function delMember(_, cb) {
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
                  'cn': [
                    'devread'
                  ],
                  'memberrole': [
                    'role-uuid=b4301b32-66b4-11e3-ac31-6b349ce5dc45, ' +
                    'uuid=390c229a-8c77-445f-b227-88e41c2bb3cf, ' +
                    'ou=users, o=smartdc'
                  ],
                  'objectclass': [
                    'sdcaccountgroup'
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
                batch: self.redis.multi(),
                entry: entry,
                changes: entry.changes
            };
            var uuid = '5d0049f4-67b3-11e3-8059-273f883b3fb6';
            var user = '3ffc7b4c-66a6-11e3-af09-8752d24e4669';
            var key = '/uuid/' + user;
            self.transformer.transform(args, function (err, res) {
                t.strictEqual(2, res.queue.length);
                res.exec(function () {
                    self.redis.get(key, function (err, res) {
                        t.strictEqual(JSON.parse(res).groups.indexOf(uuid), -1);
                        cb();
                    });
                });
            });
        },
        function addMemberRole(_, cb) {
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
                    'type': 'memberrole',
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
                  'cn': [
                    'devread'
                  ],
                  'memberrole': [
                    'role-uuid=b4301b32-66b4-11e3-ac31-6b349ce5dc45, ' +
                        'uuid=390c229a-8c77-445f-b227-88e41c2bb3cf, ' +
                        'ou=users, o=smartdc'
                  ],
                  'objectclass': [
                    'sdcaccountgroup'
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
                batch: self.redis.multi(),
                entry: entry,
                changes: entry.changes
            };
            var uuid = '5d0049f4-67b3-11e3-8059-273f883b3fb6';
            var role = 'b4301b32-66b4-11e3-ac31-6b349ce5dc45';
            var key = '/uuid/' + uuid;
            self.transformer.transform(args, function (err, res) {
                t.strictEqual(2, res.queue.length);
                res.exec(function () {
                    self.redis.get(key, function (err, res) {
                        t.ok(JSON.parse(res).roles.indexOf(role) > -1);
                        cb();
                    });
                });
            });
        },
        function delRoleMember(_, cb) {
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
                    'type': 'memberrole',
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
                      'cn': [
                        'devread'
                      ],
                      'objectclass': [
                        'sdcaccountgroup'
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
                batch: self.redis.multi(),
                entry: entry,
                changes: entry.changes
            };
            var uuid = '5d0049f4-67b3-11e3-8059-273f883b3fb6';
            var role = 'b4301b32-66b4-11e3-ac31-6b349ce5dc45';
            var key = '/uuid/' + uuid;
            self.transformer.transform(args, function (err, res) {
                t.strictEqual(2, res.queue.length);
                res.exec(function () {
                    self.redis.get(key, function (err, res) {
                        t.strictEqual(JSON.parse(res).roles.indexOf(role), -1);
                        cb();
                    });
                });
            });
        },
        function delAccountGroup(_, cb) {
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
                'cn': [
                  'devread'
                ],
                'objectclass': [
                  'sdcaccountgroup'
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
                'memberrole': []
              },
              'changenumber': '32'
            };
            var args = {
                batch: self.redis.multi(),
                entry: entry,
                changes: entry.changes
            };
            var uuid = '5d0049f4-67b3-11e3-8059-273f883b3fb6';
            var account = '390c229a-8c77-445f-b227-88e41c2bb3cf';
            var name = 'devread';
            var key = '/uuid/' + uuid;

            self.transformer.transform(args, function (err, res) {
                t.strictEqual(4, res.queue.length);
                res.exec(function () {
                    var barrier = vasync.barrier();
                    barrier.start('uuid');
                    barrier.start('group');
                    barrier.start('set');
                    barrier.on('drain', function () {
                        cb();
                    });
                    self.redis.get(key, function (err, res) {
                        t.strictEqual(res, null);
                        barrier.done('uuid');
                    });
                    self.redis.get(sprintf('/group/%s/%s', account, name),
                        function (err, res) {
                        t.strictEqual(res, null);
                        barrier.done('group');
                    });
                    self.redis.sismember('/set/groups/' + account, uuid,
                        function (err, res) {

                        t.strictEqual(0, res);
                        barrier.done('set');
                    });
                });
            });
        }
    ]}, function () {
        t.end();
    });
});


test('sdcaccountrole', function (t) {
    var self = this;
    vasync.pipeline({funcs: [
        function putRole(_, cb) {
            var entry = {
              'dn': 'changenumber=16, cn=changelog',
              'controls': [],
              'targetdn': 'role-uuid=b4301b32-66b4-11e3-ac31-6b349ce5dc45, ' +
                'uuid=390c229a-8c77-445f-b227-88e41c2bb3cf, ' +
                'ou=users, o=smartdc',
              'changetype': 'add',
              'objectclass': 'changeLogEntry',
              'changetime': '2013-12-19T00:58:05.608Z',
              'changes': {
                'account': [
                  '390c229a-8c77-445f-b227-88e41c2bb3cf'
                ],
                'objectclass': [
                  'sdcaccountrole'
                ],
                'policydocument': [
                  'Can read foo and bar when ip=10.0.0.0/8',
                  'Can read red and blue when ip=10.0.0.0/16'
                ],
                'role': [
                  'developer_read'
                ],
                'uniquemember': [
                  'uuid=3ffc7b4c-66a6-11e3-af09-8752d24e4669, ' +
                  'uuid=390c229a-8c77-445f-b227-88e41c2bb3cf, ' +
                  'ou=users, o=smartdc'
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
              'changenumber': '16'
            };
            var args = {
                batch: self.redis.multi(),
                entry: entry,
                changes: entry.changes
            };

            var uuid = 'b4301b32-66b4-11e3-ac31-6b349ce5dc45';
            var account = '390c229a-8c77-445f-b227-88e41c2bb3cf';
            var user = '3ffc7b4c-66a6-11e3-af09-8752d24e4669';
            var name = 'developer_read';

            var expected = {
                type: 'role',
                name: 'developer_read',
                policies: [
                  'Can read foo and bar when ip=10.0.0.0/8',
                  'Can read red and blue when ip=10.0.0.0/16'
                ],
                account: account
            };

            self.transformer.transform(args, function (err, res) {
                t.strictEqual(5, res.queue.length);
                res.exec(function () {
                    var barrier = vasync.barrier();
                    barrier.start('uuid');
                    barrier.start('user');
                    barrier.start('set');
                    barrier.start('role');
                    barrier.on('drain', function () {
                        cb();
                    });
                    self.redis.get('/uuid/' + uuid, function (err, res) {
                        t.deepEqual(JSON.parse(res), expected);
                        barrier.done('uuid');
                    });
                    self.redis.get(sprintf('/uuid/' + user),
                        function (err, res) {
                        t.ok(JSON.parse(res).roles.indexOf(uuid) > -1);
                        barrier.done('user');
                    });
                    self.redis.sismember('/set/roles/' + account, uuid,
                        function (err, res) {
                        t.strictEqual(1, res);
                        barrier.done('set');
                    });
                    self.redis.get(sprintf('/role/%s/%s', account, name),
                        function (err, res) {
                        t.strictEqual(uuid, res);
                        barrier.done('role');
                    });
                });
            });

        },
        function renameRole(_, cb) {
            var entry = {
              'dn': 'changenumber=20, cn=changelog',
              'controls': [],
              'targetdn': 'role-uuid=b4301b32-66b4-11e3-ac31-6b349ce5dc45, ' +
                'uuid=390c229a-8c77-445f-b227-88e41c2bb3cf, ' +
                'ou=users, o=smartdc',
              'changetype': 'modify',
              'objectclass': 'changeLogEntry',
              'changetime': '2013-12-19T00:58:05.921Z',
              'changes': [
                {
                  'operation': 'replace',
                  'modification': {
                    'type': 'role',
                    'vals': [
                      'roletoreplace'
                    ]
                  }
                }
              ],
              'entry': JSON.stringify({
                  'account': [
                    '390c229a-8c77-445f-b227-88e41c2bb3cf'
                  ],
                  'objectclass': [
                    'sdcaccountrole'
                  ],
                  'policydocument': [
                    'Can read foo and bar when ip=10.0.0.0/8',
                    'Can read red and blue when ip=10.0.0.0/16'
                  ],
                  'role': [
                    'roletoreplace'
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
              'changenumber': '20'
            };
            var args = {
                batch: self.redis.multi(),
                entry: entry,
                changes: entry.changes
            };
            var uuid = 'b4301b32-66b4-11e3-ac31-6b349ce5dc45';
            var account = '390c229a-8c77-445f-b227-88e41c2bb3cf';
            var oldname = 'developer_read';
            var name = 'roletoreplace';

            self.transformer.transform(args, function (err, res) {
                t.strictEqual(4, res.queue.length);
                res.exec(function () {
                    var barrier = vasync.barrier();
                    barrier.start('oldname');
                    barrier.start('newname');
                    barrier.start('uuid');
                    barrier.on('drain', function () {
                        cb();
                    });
                    self.redis.get(sprintf('/role/%s/%s', account, name),
                        function (err, res) {

                        t.strictEqual(uuid, res);
                        barrier.done('newname');
                    });
                    self.redis.get(sprintf('/role/%s/%s', account, oldname),
                        function (err, res) {

                        t.strictEqual(null, res);
                        barrier.done('oldname');
                    });
                    self.redis.get('/uuid/' + uuid, function (err, res) {
                        t.strictEqual(JSON.parse(res).name, name);
                        barrier.done('uuid');
                    });
                });
            });
        },
        function addMember(_, cb) {
            var entry = {
              'dn': 'changenumber=17, cn=changelog',
              'controls': [],
              'targetdn': 'role-uuid=b4301b32-66b4-11e3-ac31-6b349ce5dc45, ' +
                  'uuid=390c229a-8c77-445f-b227-88e41c2bb3cf, ' +
                  'ou=users, o=smartdc',
              'changetype': 'modify',
              'objectclass': 'changeLogEntry',
              'changetime': '2013-12-19T00:58:05.691Z',
              'changes': [
                {
                  'operation': 'add',
                  'modification': {
                    'type': 'uniquemember',
                    'vals': [
                      'uuid=cfcc7924-6823-11e3-a835-43e6162a87c8, ' +
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
                  'objectclass': [
                    'sdcaccountrole'
                  ],
                  'policydocument': [
                    'Can read foo and bar when ip=10.0.0.0/8',
                    'Can read red and blue when ip=10.0.0.0/16'
                  ],
                  'role': [
                    'developer_read'
                  ],
                  'uniquemember': [
                    'uuid=3ffc7b4c-66a6-11e3-af09-8752d24e4669, ' +
                        'uuid=390c229a-8c77-445f-b227-88e41c2bb3cf, ' +
                        'ou=users, o=smartdc',
                    'uuid=cfcc7924-6823-11e3-a835-43e6162a87c8, ' +
                        'uuid=390c229a-8c77-445f-b227-88e41c2bb3cf, ' +
                        'ou=users, o=smartdc'
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
              'changenumber': '17'
            };
            var args = {
                batch: self.redis.multi(),
                entry: entry,
                changes: entry.changes
            };
            var uuid = 'b4301b32-66b4-11e3-ac31-6b349ce5dc45';
            var user = 'cfcc7924-6823-11e3-a835-43e6162a87c8';

            self.transformer.transform(args, function (err, res) {
                t.strictEqual(res.queue.length, 2);
                res.exec(function () {
                    self.redis.get('/uuid/' + user, function (err, res) {
                        t.ok(JSON.parse(res).roles.indexOf(uuid) > -1);
                        cb();
                    });
                });
            });
        },
        function delMember(_, cb) {
            var entry = {
              'dn': 'changenumber=19, cn=changelog',
              'controls': [],
              'targetdn': 'role-uuid=b4301b32-66b4-11e3-ac31-6b349ce5dc45, ' +
                  'uuid=390c229a-8c77-445f-b227-88e41c2bb3cf, ' +
                  'ou=users, o=smartdc',
              'changetype': 'modify',
              'objectclass': 'changeLogEntry',
              'changetime': '2013-12-19T00:58:05.855Z',
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
                  'objectclass': [
                    'sdcaccountrole'
                  ],
                  'policydocument': [
                    'Can read foo and bar when ip=10.0.0.0/8',
                    'Can read red and blue when ip=10.0.0.0/16'
                  ],
                  'role': [
                    'developer_read'
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
              'changenumber': '19'
            };
            var args = {
                batch: self.redis.multi(),
                entry: entry,
                changes: entry.changes
            };
            var uuid = 'b4301b32-66b4-11e3-ac31-6b349ce5dc45';
            var user = '3ffc7b4c-66a6-11e3-af09-8752d24e4669';

            self.transformer.transform(args, function (err, res) {
                t.strictEqual(res.queue.length, 2);
                res.exec(function () {
                    self.redis.get('/uuid/' + user, function (err, res) {
                        t.ok(JSON.parse(res).roles.indexOf(uuid) === -1);
                        cb();
                    });
                });
            });
        },
        function addPolicy(_, cb) {
            var entry = {
              'dn': 'changenumber=21, cn=changelog',
              'controls': [],
              'targetdn': 'role-uuid=b4301b32-66b4-11e3-ac31-6b349ce5dc45, ' +
                  'uuid=390c229a-8c77-445f-b227-88e41c2bb3cf, ' +
                  'ou=users, o=smartdc',
              'changetype': 'modify',
              'objectclass': 'changeLogEntry',
              'changetime': '2013-12-19T00:58:06.004Z',
              'changes': [
                {
                  'operation': 'add',
                  'modification': {
                    'type': 'policydocument',
                    'vals': [
                      'Can read x and y when ip=10.0.0.0/32'
                    ]
                  }
                }
              ],
              'entry': JSON.stringify({
                  'account': [
                    '390c229a-8c77-445f-b227-88e41c2bb3cf'
                  ],
                  'objectclass': [
                    'sdcaccountrole'
                  ],
                  'policydocument': [
                    'Can read foo and bar when ip=10.0.0.0/8',
                    'Can read red and blue when ip=10.0.0.0/16',
                    'Can read x and y when ip=10.0.0.0/32'
                  ],
                  'role': [
                    'roletoreplace'
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
              'changenumber': '21'
            };
            var args = {
                batch: self.redis.multi(),
                entry: entry,
                changes: entry.changes
            };
            var uuid = 'b4301b32-66b4-11e3-ac31-6b349ce5dc45';
            var policy = 'Can read x and y when ip=10.0.0.0/32';

            self.transformer.transform(args, function (err, res) {
                t.strictEqual(res.queue.length, 2);
                res.exec(function () {
                    self.redis.get('/uuid/' + uuid, function (err, res) {
                        t.ok(JSON.parse(res).policies.indexOf(policy) > -1);
                        cb();
                    });
                });
            });
        },
        function delPolicy(_, cb) {
            var entry = {
              'dn': 'changenumber=22, cn=changelog',
              'controls': [],
              'targetdn': 'role-uuid=b4301b32-66b4-11e3-ac31-6b349ce5dc45, ' +
                  'uuid=390c229a-8c77-445f-b227-88e41c2bb3cf, ' +
                  'ou=users, o=smartdc',
              'changetype': 'modify',
              'objectclass': 'changeLogEntry',
              'changetime': '2013-12-19T00:58:06.017Z',
              'changes': [
                {
                  'operation': 'delete',
                  'modification': {
                    'type': 'policydocument',
                    'vals': [
                      'Can read x and y when ip=10.0.0.0/32'
                    ]
                  }
                }
              ],
              'entry': JSON.stringify({
                  'account': [
                    '390c229a-8c77-445f-b227-88e41c2bb3cf'
                  ],
                  'objectclass': [
                    'sdcaccountrole'
                  ],
                  'policydocument': [
                    'Can read foo and bar when ip=10.0.0.0/8',
                    'Can read red and blue when ip=10.0.0.0/16'
                  ],
                  'role': [
                    'roletoreplace'
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
              'changenumber': '22'
            };
            var args = {
                batch: self.redis.multi(),
                entry: entry,
                changes: entry.changes
            };
            var uuid = 'b4301b32-66b4-11e3-ac31-6b349ce5dc45';
            var policy = 'Can read x and y when ip=10.0.0.0/32';

            self.transformer.transform(args, function (err, res) {
                t.strictEqual(res.queue.length, 2);
                res.exec(function () {
                    self.redis.get('/uuid/' + uuid, function (err, res) {
                        t.ok(JSON.parse(res).policies.indexOf(policy) === -1);
                        cb();
                    });
                });
            });
        },
        function addMemberGroup(_, cb) {
            var entry = {
              'dn': 'changenumber=30, cn=changelog',
              'controls': [],
              'targetdn': 'role-uuid=b4301b32-66b4-11e3-ac31-6b349ce5dc45, ' +
                  'uuid=390c229a-8c77-445f-b227-88e41c2bb3cf, ' +
                  'ou=users, o=smartdc',
              'changetype': 'modify',
              'objectclass': 'changeLogEntry',
              'changetime': '2013-12-19T00:58:06.399Z',
              'changes': [
                {
                  'operation': 'add',
                  'modification': {
                    'type': 'membergroup',
                    'vals': [
                      'group-uuid=5d0049f4-67b3-11e3-8059-273f883b3fb6, ' +
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
                  'objectclass': [
                    'sdcaccountrole'
                  ],
                  'policydocument': [
                    'Can read x and y when ip=10.0.0.0/24'
                  ],
                  'role': [
                    'roletoreplace'
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
                  ],
                  'membergroup': [
                    'group-uuid=5d0049f4-67b3-11e3-8059-273f883b3fb6, ' +
                        'uuid=390c229a-8c77-445f-b227-88e41c2bb3cf, ' +
                        'ou=users, o=smartdc'
                  ]
              }),
              'changenumber': '30'
            };
            var args = {
                batch: self.redis.multi(),
                entry: entry,
                changes: entry.changes
            };
            var uuid = 'b4301b32-66b4-11e3-ac31-6b349ce5dc45';
            var group = '5d0049f4-67b3-11e3-8059-273f883b3fb6';

            self.transformer.transform(args, function (err, res) {
                t.strictEqual(res.queue.length, 2);
                res.exec(function () {
                    self.redis.get('/uuid/' + group, function (err, res) {
                        t.ok(JSON.parse(res).roles.indexOf(uuid) > -1);
                        cb();
                    });
                });
            });
        },
        function delMemberGroup(_, cb) {
            var entry = {
              'dn': 'changenumber=31, cn=changelog',
              'controls': [],
              'targetdn': 'role-uuid=b4301b32-66b4-11e3-ac31-6b349ce5dc45, ' +
                  'uuid=390c229a-8c77-445f-b227-88e41c2bb3cf, ' +
                  'ou=users, o=smartdc',
              'changetype': 'modify',
              'objectclass': 'changeLogEntry',
              'changetime': '2013-12-19T00:58:06.492Z',
              'changes': [
                {
                  'operation': 'delete',
                  'modification': {
                    'type': 'membergroup',
                    'vals': [
                      'group-uuid=5d0049f4-67b3-11e3-8059-273f883b3fb6, ' +
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
                  'objectclass': [
                    'sdcaccountrole'
                  ],
                  'policydocument': [
                    'Can read x and y when ip=10.0.0.0/24'
                  ],
                  'role': [
                    'roletoreplace'
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
              'changenumber': '31'
            };
            var args = {
                batch: self.redis.multi(),
                entry: entry,
                changes: entry.changes
            };
            var uuid = 'b4301b32-66b4-11e3-ac31-6b349ce5dc45';
            var group = '5d0049f4-67b3-11e3-8059-273f883b3fb6';

            self.transformer.transform(args, function (err, res) {
                t.strictEqual(res.queue.length, 2);
                res.exec(function () {
                    self.redis.get('/uuid/' + group, function (err, res) {
                        t.ok(JSON.parse(res).roles.indexOf(uuid) ===  -1);
                        cb();
                    });
                });
            });
        },
        function delRole(_, cb) {
            var entry = {
              'dn': 'changenumber=33, cn=changelog',
              'controls': [],
              'targetdn': 'role-uuid=b4301b32-66b4-11e3-ac31-6b349ce5dc45, ' +
                  'uuid=390c229a-8c77-445f-b227-88e41c2bb3cf, ' +
                  'ou=users, o=smartdc',
              'changetype': 'delete',
              'objectclass': 'changeLogEntry',
              'changetime': '2013-12-19T00:58:06.600Z',
              'changes': {
                'account': [
                  '390c229a-8c77-445f-b227-88e41c2bb3cf'
                ],
                'objectclass': [
                  'sdcaccountrole'
                ],
                'policydocument': [
                  'Can read x and y when ip=10.0.0.0/24'
                ],
                'role': [
                  'roletoreplace'
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
              'changenumber': '33'
            };
            var args = {
                batch: self.redis.multi(),
                entry: entry,
                changes: entry.changes
            };
            var uuid = 'b4301b32-66b4-11e3-ac31-6b349ce5dc45';
            var account = '390c229a-8c77-445f-b227-88e41c2bb3cf';
            var name = 'roletoreplace';

            self.transformer.transform(args, function (err, res) {
                t.strictEqual(res.queue.length, 4);
                res.exec(function () {
                    var barrier = vasync.barrier();
                    barrier.start('uuid');
                    barrier.start('set');
                    barrier.start('role');
                    barrier.on('drain', function () {
                        cb();
                    });
                    self.redis.get('/uuid/' + uuid, function (err, res) {
                        t.strictEqual(null, res);
                        barrier.done('uuid');
                    });
                    self.redis.sismember('/set/roles/' + account, uuid,
                        function (err, res) {

                        t.strictEqual(0, res);
                        barrier.done('set');
                    });
                    self.redis.get(sprintf('/role/%s/%s', account, name),
                        function (err, res) {
                        t.strictEqual(null, res);
                        barrier.done('role');
                    });
                });
            });
        }
    ]}, function () {
        t.end();
    });
});

test('sdcaccountuser', function (t) {
    var self = this;
    vasync.pipeline({funcs: [
        function addUser(_, cb) {
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
                'login': [
                  '390c229a-8c77-445f-b227-88e41c2bb3cf/subuser'
                ]
              },
              'changenumber': '8'
            };

            var args = {
                batch: self.redis.multi(),
                entry: entry,
                changes: entry.changes
            };

            var account = '390c229a-8c77-445f-b227-88e41c2bb3cf';
            var uuid = '3ffc7b4c-66a6-11e3-af09-8752d24e4669';
            var login = '390c229a-8c77-445f-b227-88e41c2bb3cf/subuser';
            var key = '/uuid/' + uuid;
            var value = {
                type: 'user',
                account: account,
                login: login
            };

            self.transformer.transform(args, function (err, res) {
                t.strictEqual(4, res.queue.length);
                res.exec(function () {
                    var barrier = vasync.barrier();
                    barrier.start('user');
                    barrier.start('uuid');
                    barrier.start('set');
                    barrier.on('drain', function () {
                        cb();
                    });

                    self.redis.get(key, function (err, res) {
                        t.deepEqual(value, JSON.parse(res));
                        barrier.done('uuid');
                    });
                    self.redis.get(sprintf('/user/%s/%s', account, login),
                        function (err, res) {

                        t.deepEqual(uuid, res);
                        barrier.done('user');
                    });
                    self.redis.sismember('/set/users/' + account, uuid,
                        function (err, res) {

                        t.strictEqual(1, res);
                        barrier.done('set');
                    });
                });
            });
        },
        function renameUser(_, cb) {
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
                },
                {
                  'operation': 'replace',
                  'modification': {
                    'type': 'updated_at',
                    'vals': [
                      '1387414685519'
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
                  'login': [
                    '390c229a-8c77-445f-b227-88e41c2bb3cf/subuser3'
                  ]
                })
            };

            var args = {
                batch: self.redis.multi(),
                entry: entry,
                changes: entry.changes
            };

            var account = '390c229a-8c77-445f-b227-88e41c2bb3cf';
            var uuid = '3ffc7b4c-66a6-11e3-af09-8752d24e4669';
            var login = '390c229a-8c77-445f-b227-88e41c2bb3cf/subuser3';
            var oldlogin = '390c229a-8c77-445f-b227-88e41c2bb3cf/subuser';
            var key = '/uuid/' + uuid;

            self.transformer.transform(args, function (err, res) {
                t.strictEqual(4, res.queue.length);
                res.exec(function () {
                    var barrier = vasync.barrier();
                    barrier.start('newname');
                    barrier.start('oldname');
                    barrier.start('uuid');
                    barrier.on('drain', function () {
                        cb();
                    });
                    self.redis.get(sprintf('/user/%s/%s', account, login),
                        function (err, res) {

                        t.deepEqual(uuid, res);
                        barrier.done('newname');
                    });
                    self.redis.get(sprintf('/user/%s/%s', account, oldlogin),
                        function (err, res) {

                        t.strictEqual(null, res);
                        barrier.done('oldname');
                    });
                    self.redis.get(key, function (err, res) {
                        t.deepEqual(JSON.parse(res).login, login);
                        barrier.done('uuid');
                    });
                });
            });

        },
        function delUser(_, cb) {
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
                'login': [
                  '390c229a-8c77-445f-b227-88e41c2bb3cf/subuser3'
                ]
              },
              'changenumber': '34'
            };
            var args = {
                batch: self.redis.multi(),
                entry: entry,
                changes: entry.changes
            };

            var account = '390c229a-8c77-445f-b227-88e41c2bb3cf';
            var uuid = '3ffc7b4c-66a6-11e3-af09-8752d24e4669';
            var login = '390c229a-8c77-445f-b227-88e41c2bb3cf/subuser3';
            var key = '/uuid/' + uuid;

            self.transformer.transform(args, function (err, res) {
                t.strictEqual(4, res.queue.length);
                res.exec(function () {
                    var barrier = vasync.barrier();
                    barrier.start('uuid');
                    barrier.start('set');
                    barrier.start('user');
                    barrier.on('drain', function () {
                        cb();
                    });

                    self.redis.get(key, function (err, res) {
                        t.strictEqual(null, res);
                        barrier.done('uuid');
                    });
                    self.redis.get(sprintf('/user/%s/%s', account, login),
                        function (err, res) {
                        t.strictEqual(null, res);
                        barrier.done('user');
                    });
                    self.redis.sismember('/set/users/' + account, uuid,
                        function (err, res) {
                        t.strictEqual(0, res);
                        barrier.done('set');
                    });
                });
            });
        }
    ]}, function () {
        t.end();
    });
});

test('sdckey', function (t) {
    var self = this;
    vasync.pipeline({funcs: [
        function addKey(_, cb) {
            var entry = {
              'dn': 'changenumber=14, cn=changelog',
              'controls': [],
              'targetdn': 'fingerprint=fp, ' +
                'uuid=1a940615-65e9-4856-95f9-f4c530e86ca4, ' +
                'ou=users, o=smartdc',
              'changetype': 'add',
              'objectclass': 'changeLogEntry',
              'changetime': '2013-12-11T20:28:22.273Z',
              'changes': {
                'name': [
                  ''
                ],
                'objectclass': [
                  'sdckey'
                ],
                'openssh': [
                  'elided-openssh'
                ],
                'pkcs': [
                  'elided-pkcs'
                ],
                'fingerprint': [
                  '7b:a4:7c:6c:c7:2f:d9:a6:bd:ec:1b:2f:e8:3d:40:18'
                ],
                '_owner': [
                  '1a940615-65e9-4856-95f9-f4c530e86ca4'
                ],
                '_parent': [
                  'uuid=1a940615-65e9-4856-95f9-f4c530e86ca4, ' +
                    'ou=users, o=smartdc'
                ]
              },
              'changenumber': '14'
            };

            var args = {
                batch: self.redis.multi(),
                entry: entry,
                changes: entry.changes
            };

            var key = '/uuid/1a940615-65e9-4856-95f9-f4c530e86ca4';
            var value = {
                keys: {
                    '7b:a4:7c:6c:c7:2f:d9:a6:bd:ec:1b:2f:e8:3d:40:18':
                        'elided-pkcs'
                }
            };

            self.transformer.transform(args, function (err, res) {
                t.strictEqual(2, res.queue.length);
                res.exec(function () {
                    self.redis.get(key, function (err, res) {
                        t.deepEqual(value, JSON.parse(res));
                        cb();
                    });
                });
            });
        },
        function delKey(_, cb) {
            var entry = {
              'dn': 'changenumber=37, cn=changelog',
              'controls': [],
              'targetdn': 'fingerprint=fp, ' +
                'uuid=1a940615-65e9-4856-95f9-f4c530e86ca4, ' +
                'ou=users, o=smartdc',
              'changetype': 'delete',
              'objectclass': 'changeLogEntry',
              'changetime': '2013-12-19T00:58:06.772Z',
              'changes': {
                'name': [
                  'newkeyname'
                ],
                'objectclass': [
                  'sdckey'
                ],
                'openssh': [
                  'elided-openssh'
                ],
                'pkcs': [
                  'elided-pkcs'
                ],
                'fingerprint': [
                  '7b:a4:7c:6c:c7:2f:d9:a6:bd:ec:1b:2f:e8:3d:40:18'
                ],
                '_owner': [
                  '1a940615-65e9-4856-95f9-f4c530e86ca4'
                ],
                '_parent': [
                  'uuid=1a940615-65e9-4856-95f9-f4c530e86ca4, ou=users, o=smartdc'
                ]
              },
              'changenumber': '37'
            };

            var args = {
                batch: self.redis.multi(),
                entry: entry,
                changes: entry.changes
            };

            var key = '/uuid/1a940615-65e9-4856-95f9-f4c530e86ca4';
            self.transformer.transform(args, function (err, res) {
                t.strictEqual(2, res.queue.length);
                res.exec(function () {
                    self.redis.get(key, function (err, res) {
                        t.equal(JSON.parse(res).keys.fp, undefined);
                        cb();
                    });
                });
            });
        }
    ]}, function () {
        t.end();
    });
});

test('sdcperson', function (t) {
    var self = this;

    vasync.pipeline({funcs: [
        // postcondition
        // login: bcantrill, approved? false
        function putAccount(_, cb) {
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
                batch: self.redis.multi(),
                entry: entry,
                changes: entry.changes
            };
            var uuid = '1a940615-65e9-4856-95f9-f4c530e86ca4';
            var key = '/uuid/' + uuid;
            var value = {
                type: 'account',
                login: 'bcantrill',
                approved_for_provisioning: false
            };

            self.transformer.transform(args, function (err, res) {
                t.strictEqual(4, res.queue.length);
                res.exec(function () {
                    var barrier = vasync.barrier();
                    barrier.start('account');
                    barrier.start('uuid');
                    barrier.start('set');
                    barrier.on('drain', function () {
                        cb();
                    });
                    self.redis.get('/account/bcantrill', function (err, res) {
                        t.strictEqual(uuid, res);
                        barrier.done('account');
                    });
                    self.redis.get(key, function (err, res) {
                        t.deepEqual(value, JSON.parse(res));
                        barrier.done('uuid');
                    });
                    self.redis.sismember('/set/accounts', uuid,
                        function (err, res) {

                        t.strictEqual(1, res);
                        barrier.done('set');
                    });
                });
            });
        },
        // postcondition
        // login: bcantrill, approved? false
        function modAccountIrrelevantChange(_, cb) {
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
                },
                {
                  'operation': 'replace',
                  'modification': {
                    'type': 'updated_at',
                    'vals': [
                      '1386795904026'
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
                batch: self.redis.multi(),
                entry: entry,
                changes: entry.changes
            };

            var key = '/uuid/1a940615-65e9-4856-95f9-f4c530e86ca4';
            var value = {
                type: 'account',
                login: 'bcantrill',
                approved_for_provisioning: false
            };

            self.transformer.transform(args, function (err, res) {
                // irrelevant change, there should be nothing to do
                t.strictEqual(1, res.queue.length);
                res.exec(function () {
                    self.redis.get(key, function (err, res) {
                        t.deepEqual(value, JSON.parse(res));
                        cb();
                    });
                });
            });
        },
        // precondition
        // login: bcantrill, approved? false
        // postcondition
        // login: bcantrill, approved? true
        function modAccountApprovedForProvisioning(_, cb) {
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
                },
                {
                  'operation': 'replace',
                  'modification': {
                    'type': 'updated_at',
                    'vals': [
                      '1386795903782'
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
                batch: self.redis.multi(),
                entry: entry,
                changes: entry.changes
            };

            var key = '/uuid/1a940615-65e9-4856-95f9-f4c530e86ca4';
            var value = {
                type: 'account',
                login: 'bcantrill',
                approved_for_provisioning: true
            };
            self.transformer.transform(args, function (err, res) {
                t.strictEqual(2, res.queue.length);
                res.exec(function () {
                    self.redis.get(key, function (err, res) {
                        t.deepEqual(value, JSON.parse(res));
                        cb();
                    });
                });
            });
        },
        // precondition
        // login: bcantrill, approved? true
        // postcondition
        // login: bcantrill, approved? false
        function modAccountApprovedForProvisioningDelete(_, cb) {
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
                  'operation': 'delete',
                  'modification': {
                    'type': 'approved_for_provisioning',
                    'vals': [
                      'false'
                    ]
                  }
                },
                {
                  'operation': 'replace',
                  'modification': {
                    'type': 'updated_at',
                    'vals': [
                      '1386795903782'
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
                  'false'
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
                batch: self.redis.multi(),
                entry: entry,
                changes: entry.changes
            };

            var key = '/uuid/1a940615-65e9-4856-95f9-f4c530e86ca4';
            var value = {
                type: 'account',
                login: 'bcantrill',
                approved_for_provisioning: false
            };
            self.transformer.transform(args, function (err, res) {
                t.strictEqual(2, res.queue.length);
                res.exec(function () {
                    self.redis.get(key, function (err, res) {
                        t.deepEqual(value, JSON.parse(res));
                        cb();
                    });
                });
            });
        },
        // precondition
        // login: bcantrill, approved? false
        // postcondition
        // login: bmc, approved? false
        function modAccountRename(_, cb) {
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
                },
                {
                  'operation': 'replace',
                  'modification': {
                    'type': 'updated_at',
                    'vals': [
                      '1386795903954'
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
                batch: self.redis.multi(),
                entry: entry,
                changes: entry.changes
            };

            var uuid = '1a940615-65e9-4856-95f9-f4c530e86ca4';
            var key = '/uuid/' + uuid;
            var value = {
                type: 'account',
                login: 'bmc',
                approved_for_provisioning: false
            };

            self.transformer.transform(args, function (err, res) {
                t.strictEqual(4, res.queue.length);
                res.exec(function () {
                    var barrier = vasync.barrier();
                    barrier.start('uuid');
                    barrier.start('del');
                    barrier.start('add');
                    barrier.start('set');
                    barrier.on('drain', function () {
                        cb();
                    });
                    self.redis.get(key, function (err, res) {
                        t.deepEqual(value, JSON.parse(res));
                        barrier.done('uuid');
                    });
                    self.redis.get('/account/bcantrill', function (err, res) {
                        t.deepEqual(null, res);
                        barrier.done('del');
                    });
                    self.redis.get('/account/bmc', function (err, res) {
                        t.deepEqual(uuid, res);
                        barrier.done('add');
                    });
                    self.redis.sismember('/set/accounts', uuid,
                        function  (err, res) {
                        t.strictEqual(1, res);
                        barrier.done('set');
                    });
                });
            });
        },
        // precondition
        // login: bmc, approved? true
        function delAccount(_, cb) {
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
                batch: self.redis.multi(),
                entry: entry,
                changes: entry.changes
            };

            var uuid = '1a940615-65e9-4856-95f9-f4c530e86ca4';
            var key = '/uuid/' + uuid;

            self.transformer.transform(args, function (err, res) {
                t.strictEqual(7, res.queue.length);
                res.exec(function () {
                    var barrier = vasync.barrier();
                    barrier.start('uuid');
                    barrier.start('account');
                    barrier.start('set');
                    barrier.start('subusers');
                    barrier.start('subgroups');
                    barrier.start('subroles');
                    barrier.on('drain', function () {
                        cb();
                    });
                    self.redis.get(key, function (err, res) {
                        t.strictEqual(null, res);
                        barrier.done('uuid');
                    });
                    self.redis.get('/account/bmc', function (err, res) {
                        t.strictEqual(null, res);
                        barrier.done('account');
                    });
                    self.redis.sismember('/set/accounts', uuid,
                        function  (err, res) {
                        t.strictEqual(0, res);
                        barrier.done('set');
                    });
                    self.redis.scard('/set/users/' + uuid, function (err, res) {
                        t.strictEqual(0, res);
                        barrier.done('subusers');
                    });
                    self.redis.scard('/set/roles/' + uuid, function (err, res) {
                        t.strictEqual(0, res);
                        barrier.done('subroles');
                    });
                    self.redis.scard('/set/groups/' + uuid,
                        function (err, res) {
                        t.strictEqual(0, res);
                        barrier.done('subgroups');
                    });
                });
            });
        }
    ]}, function () {
        t.end();
    });
});
