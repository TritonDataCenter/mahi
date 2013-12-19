/*
 * Test suite for transformer.js
 * Requires a redis instance
 */

var transformer = require('../lib/transformer.js');
var nodeunit = require('nodeunit-plus');
var vasync = require('vasync');
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
    this.log = nodeunit.createLogger('transformer', process.stdout);

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
                t.ifError(err);
                t.equal(2, res.queue.length);
                t.deepEqual(res.queue[1], [
                    'set',
                    key,
                    value
                ]);
                res.exec(function (execErr) {
                    t.ifError(execErr);
                    self.redis.get(key, function (redisErr, redisRes){
                        t.ifError(redisErr);
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
                t.ifError(err);
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
                res.exec(function (execErr) {
                    t.ifError(execErr);
                    self.redis.get(key1, function (redisErr, redisRes) {
                        t.ifError(redisErr);
                        t.strictEqual(value1, redisRes);
                        self.redis.get(key2, function (redisErr2, redisRes2) {
                            t.ifError(redisErr2);
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
                t.ifError(err);
                t.equal(1, res.queue.length); // only one element: 'MULTI'
                res.exec(function (execErr) {
                    t.ifError(execErr);
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
                res.exec(function (execErr) {
                    t.ifError(execErr);
                    var barrier = vasync.barrier();
                    barrier.start('1');
                    barrier.start('2');
                    barrier.start('3');
                    barrier.on('drain', function () {
                        cb();
                    });
                    self.redis.get(key1, function (redisErr, redisRes) {
                        t.ifError(redisErr);
                        t.ok(JSON.parse(redisRes).groups.operators);
                        t.ok(JSON.parse(redisRes).groups.admins);
                        barrier.done('1');
                    });
                    self.redis.get(key2, function (redisErr, redisRes) {
                        t.ifError(redisErr);
                        t.ok(JSON.parse(redisRes).groups.operators);
                        t.ok(JSON.parse(redisRes).groups.admins);
                        barrier.done('2');
                    });
                    self.redis.get(key3, function (redisErr, redisRes) {
                        t.ifError(redisErr);
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
            var value = JSON.stringify({groups: {'admins': true}});

            self.transformer.transform(args, function (err, res) {
                t.ifError(err);
                t.equal(4, res.queue.length);
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
                res.exec(function (execErr) {
                    t.ifError(execErr);
                    var barrier = vasync.barrier();
                    barrier.start('1');
                    barrier.start('2');
                    barrier.start('3');
                    barrier.on('drain', function () {
                        cb();
                    });
                    self.redis.get(key1, function (redisErr, redisRes) {
                        t.ifError(redisErr);
                        t.strictEqual(redisRes, value);
                        barrier.done('1');
                    });
                    self.redis.get(key2, function (redisErr, redisRes) {
                        t.ifError(redisErr);
                        t.strictEqual(redisRes, value);
                        barrier.done('2');
                    });
                    self.redis.get(key3, function (redisErr, redisRes) {
                        t.ifError(redisErr);
                        t.strictEqual(redisRes, JSON.stringify({groups: {}}));
                        barrier.done('3');
                    });
                });
            });
        }
    ]}, function () {
        t.end();
    });
});


test('sdcaccount', function (t) {
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
                uuid: uuid,
                login: 'bcantrill',
                approved_for_provisioning: false
            };

            self.transformer.transform(args, function (err, res) {
                t.ifError(err);
                t.strictEqual(4, res.queue.length);
                res.exec(function (err) {
                    t.ifError(err);
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
                uuid: '1a940615-65e9-4856-95f9-f4c530e86ca4',
                login: 'bcantrill',
                approved_for_provisioning: false
            };

            self.transformer.transform(args, function (err, res) {
                t.ifError(err);
                // irrelevant change, there should be nothing to do
                t.strictEqual(1, res.queue.length);
                res.exec(function (err) {
                    t.ifError(err);
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
                uuid: '1a940615-65e9-4856-95f9-f4c530e86ca4',
                login: 'bcantrill',
                approved_for_provisioning: true
            };
            self.transformer.transform(args, function (err, res) {
                t.ifError(err);
                t.strictEqual(2, res.queue.length);
                res.exec(function (err) {
                    t.ifError(err);
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
                uuid: '1a940615-65e9-4856-95f9-f4c530e86ca4',
                login: 'bcantrill',
                approved_for_provisioning: false
            };
            self.transformer.transform(args, function (err, res) {
                t.ifError(err);
                t.strictEqual(2, res.queue.length);
                res.exec(function (err) {
                    t.ifError(err);
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
                uuid: uuid,
                login: 'bmc',
                approved_for_provisioning: false
            };

            self.transformer.transform(args, function (err, res) {
                t.ifError(err);
                t.strictEqual(4, res.queue.length);
                res.exec(function (err) {
                    t.ifError(err);
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
                t.ifError(err);
                t.strictEqual(4, res.queue.length);
                res.exec(function (err) {
                    t.ifError(err);
                    var barrier = vasync.barrier();
                    barrier.start('uuid');
                    barrier.start('account');
                    barrier.start('set');
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
                  'uuid=1a940615-65e9-4856-95f9-f4c530e86ca4, ou=users, o=smartdc'
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
                t.ifError(err);
                t.strictEqual(2, res.queue.length);
                res.exec(function (err) {
                    t.ifError(err);
                    self.redis.get(key, function (err, res) {
                        t.deepEqual(value, JSON.parse(res));
                        cb();
                    });
                });
            });
        }
    ]}, function () {
        t.end();
    });


});

// sdcaccountgroup add/delete
// sdcaccountgroup modify
// -- add/delete/replace uniquemember
// sdcaccountrole add/delete
// sdcaccountrole modify
// -- add/delete/replace uniquemember
// -- add/delete/replace policydocument
/*
// sdcaccountuser add
{
  "dn": "changenumber=8, cn=changelog",
  "controls": [],
  "targetdn": "uuid=3ffc7b4c-66a6-11e3-af09-8752d24e4669, uuid=390c229a-8c77-445f-b227-88e41c2bb3cf, ou=users, o=smartdc",
  "changetype": "add",
  "objectclass": "changeLogEntry",
  "changetime": "2013-12-16T23:18:20.680Z",
  "changes": {
    "email": [
      "subuser@example.com"
    ],
    "objectclass": [
      "sdcperson",
      "sdcaccountuser"
    ],
    "userpassword": [
      "354fa25cd7ba5bce360b00422e08f94c93876833"
    ],
    "uuid": [
      "3ffc7b4c-66a6-11e3-af09-8752d24e4669"
    ],
    "_owner": [
      "390c229a-8c77-445f-b227-88e41c2bb3cf"
    ],
    "pwdchangedtime": [
      "1387235900650"
    ],
    "created_at": [
      "1387235900650"
    ],
    "updated_at": [
      "1387235900650"
    ],
    "approved_for_provisioning": [
      "false"
    ],
    "_salt": [
      "4034329d7f714d7ada4dff6fd011365b3af06081"
    ],
    "_parent": [
      "uuid=390c229a-8c77-445f-b227-88e41c2bb3cf, ou=users, o=smartdc"
    ],
    "account": [
      "390c229a-8c77-445f-b227-88e41c2bb3cf"
    ],
    "login": [
      "390c229a-8c77-445f-b227-88e41c2bb3cf/subuser"
    ]
  },
  "changenumber": "8"
}

// sdcaccountuser modify
{
  "dn": "changenumber=9, cn=changelog",
  "controls": [],
  "targetdn": "uuid=3ffc7b4c-66a6-11e3-af09-8752d24e4669, uuid=390c229a-8c77-445f-b227-88e41c2bb3cf, ou=users, o=smartdc",
  "changetype": "modify",
  "objectclass": "changeLogEntry",
  "changetime": "2013-12-17T00:10:45.281Z",
  "changes": [
    {
      "operation": "replace",
      "modification": {
        "type": "login",
        "vals": [
          "subuser2"
        ]
      }
    },
    {
      "operation": "replace",
      "modification": {
        "type": "updated_at",
        "vals": [
          "1387239045280"
        ]
      }
    }
  ],
  "entry": "{\"email\":[\"subuser@example.com\"],\"objectclass\":[\"sdcperson\",\"sdcaccountuser\"],\"userpassword\":[\"2d9ad93571b46907f05ea6e6b881cdd91e032cf6\"],\"uuid\":[\"3ffc7b4c-66a6-11e3-af09-8752d24e4669\"],\"_owner\":[\"390c229a-8c77-445f-b227-88e41c2bb3cf\"],\"pwdchangedtime\":[\"1387239045174\"],\"created_at\":[\"1387239045174\"],\"updated_at\":[\"1387239045280\"],\"approved_for_provisioning\":[\"false\"],\"_salt\":[\"5a6fff60b2accdeacb313d5c3782227c70f1c1e3\"],\"_parent\":[\"uuid=390c229a-8c77-445f-b227-88e41c2bb3cf, ou=users, o=smartdc\"],\"account\":[\"390c229a-8c77-445f-b227-88e41c2bb3cf\"],\"login\":[\"390c229a-8c77-445f-b227-88e41c2bb3cf/subuser2\"]}",
  "changenumber": "9"
}

// sdcaccountuser delete
{
  "dn": "changenumber=10, cn=changelog",
  "controls": [],
  "targetdn": "uuid=3ffc7b4c-66a6-11e3-af09-8752d24e4669, uuid=390c229a-8c77-445f-b227-88e41c2bb3cf, ou=users, o=smartdc",
  "changetype": "delete",
  "objectclass": "changeLogEntry",
  "changetime": "2013-12-17T00:10:45.351Z",
  "changes": {
    "email": [
      "subuser@example.com"
    ],
    "objectclass": [
      "sdcperson",
      "sdcaccountuser"
    ],
    "userpassword": [
      "2d9ad93571b46907f05ea6e6b881cdd91e032cf6"
    ],
    "uuid": [
      "3ffc7b4c-66a6-11e3-af09-8752d24e4669"
    ],
    "_owner": [
      "390c229a-8c77-445f-b227-88e41c2bb3cf"
    ],
    "pwdchangedtime": [
      "1387239045174"
    ],
    "created_at": [
      "1387239045174"
    ],
    "updated_at": [
      "1387239045280"
    ],
    "approved_for_provisioning": [
      "false"
    ],
    "_salt": [
      "5a6fff60b2accdeacb313d5c3782227c70f1c1e3"
    ],
    "_parent": [
      "uuid=390c229a-8c77-445f-b227-88e41c2bb3cf, ou=users, o=smartdc"
    ],
    "account": [
      "390c229a-8c77-445f-b227-88e41c2bb3cf"
    ],
    "login": [
      "390c229a-8c77-445f-b227-88e41c2bb3cf/subuser2"
    ]
  },
  "changenumber": "10"
}
*/
