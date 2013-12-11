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
            var batch = self.redis.multi();
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
                batch: batch,
                entry: entry,
                changes: entry.changes
            };

            var key = '/uuid/930896af-bf8c-48d4-885c-6573a94b1853';
            var value = JSON.stringify({'groups':{'operators':true}});

            self.transformer.putGroup(args, function (err, res) {
                t.ifError(err);
                t.strictEqual(res, batch);
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
            var batch = self.redis.multi();
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
                batch: batch,
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

            self.transformer.putGroup(args, function (err, res) {
                t.ifError(err);
                t.strictEqual(res, batch);
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
            var batch = self.redis.multi();
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
                batch: batch,
                entry: entry,
                changes: entry.changes
            };

            self.transformer.putGroup(args, function (err, res) {
                t.ifError(err);
                t.strictEqual(res, batch);
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
            var batch = self.redis.multi();
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
                batch: batch,
                entry: entry,
                changes: entry.changes
            };

            self.transformer.modGroup(args, function (err, res) {
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
                        console.log('redisRes: ' + redisRes);
                        console.log('redisRes: ' + JSON.parse(redisRes));
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

            var batch = self.redis.multi();
            var args = {
                batch: batch,
                entry: entry,
                changes: entry.changes
            };

            var key1 = '/uuid/1a940615-65e9-4856-95f9-f4c530e86ca4';
            var key2 = '/uuid/930896af-bf8c-48d4-885c-6573a94b1853';
            var key3 = '/uuid/a820621a-5007-4a2a-9636-edde809106de';
            var value = JSON.stringify({groups: {'admins': true}});

            self.transformer.delGroup(args, function (err, res) {
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


