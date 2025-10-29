/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2025 Edgecast Cloud LLC.
 */

var transform = require('../lib/replicator/transforms/accesskey.js');

var redis = require('fakeredis');
var REDIS;

var nodeunit = require('nodeunit-plus');
var test = nodeunit.test;

test('setup', function (t) {
        REDIS = redis.createClient();
        t.done();
});

test('add - account access key', function (t) {
    var entry = {
        'dn': 'changenumber=1, cn=changelog',
        'controls': [],
        'targetdn': 'accesskeyid=AKIA123456789EXAMPLE, ' +
            'uuid=550e8400-e29b-41d4-a716-446655440001, ' +
            'ou=users, o=smartdc',
        'changetype': 'add',
        'objectclass': 'changeLogEntry',
        'changetime': '2025-01-16T12:00:00.000Z',
        'changes': {
            'accesskeyid': [
                'AKIA123456789EXAMPLE'
            ],
            'accesskeysecret': [
                'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
            ],
            'created': [
                '1761762138761'
            ],
            'status': [
                'Active'
            ],
            'updated': [
                '1761762138761'
            ],
            'objectclass': [
                'accesskey'
            ],
            '_owner': [
                '550e8400-e29b-41d4-a716-446655440001'
            ],
            '_parent': [
                'uuid=550e8400-e29b-41d4-a716-446655440001, ' +
                    'ou=users, o=smartdc'
            ]
        },
        'changenumber': '1'
    };

    var args = {
        changes: entry.changes,
        entry: entry,
        log: this.log,
        redis: REDIS
    };

    var key = '/uuid/550e8400-e29b-41d4-a716-446655440001';
    var accessKeyLookupKey = '/accesskey/AKIA123456789EXAMPLE';
    transform.add(args, function (err, res) {
        t.ok(!err, 'add should not error');
        t.strictEqual(3, res.queue.length, 'should have 3 redis operations');
        res.exec(function (err) {
            t.ok(!err, 'exec should not error');
            // Check user record has access key
            REDIS.get(key, function (err, userRes) {
                t.ok(!err, 'redis get should not error');
                var userPayload = JSON.parse(userRes);
                t.ok(userPayload.accesskeys,
                    'user should have accesskeys object');
                t.equal(userPayload.accesskeys['AKIA123456789EXAMPLE'],
                    'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
                    'access key secret should be stored correctly');
                // Check reverse lookup
                REDIS.get(accessKeyLookupKey, function (err, lookupRes) {
                    t.ok(!err, 'reverse lookup should not error');
                    t.equal(lookupRes, '550e8400-e29b-41d4-a716-446655440001',
                        'reverse lookup should map to correct user UUID');
                    t.done();
                });
            });
        });
    });
});

test('add - sub-user access key', function (t) {
    var entry = {
        'dn': 'changenumber=2, cn=changelog',
        'controls': [],
        'targetdn': 'accesskeyid=AKIASUBUSER000000001, ' +
            'uuid=550e8400-e29b-41d4-a716-446655440003, ' +
            'uuid=550e8400-e29b-41d4-a716-446655440001, ' +
            'ou=users, o=smartdc',
        'changetype': 'add',
        'objectclass': 'changeLogEntry',
        'changetime': '2025-01-16T12:00:00.000Z',
        'changes': {
            'accesskeyid': [
                'AKIASUBUSER000000001'
            ],
            'accesskeysecret': [
                'subuserSecretKeyForTesting123456789abcdef'
            ],
            'created': [
                '1761762138761'
            ],
            'status': [
                'Active'
            ],
            'updated': [
                '1761762138761'
            ],
            'objectclass': [
                'accesskey'
            ],
            '_owner': [
                    '550e8400-e29b-41d4-a716-446655440003'
            ],
            '_parent': [
                'uuid=550e8400-e29b-41d4-a716-446655440003, ' +
                    'uuid=550e8400-e29b-41d4-a716-446655440001, ' +
                    'ou=users, o=smartdc'
            ]
        },
        'changenumber': '2'
    };

    var args = {
        changes: entry.changes,
        entry: entry,
        log: this.log,
        redis: REDIS
    };

    var key = '/uuid/550e8400-e29b-41d4-a716-446655440003';
    var accessKeyLookupKey = '/accesskey/AKIASUBUSER000000001';

    transform.add(args, function (err, res) {
        t.ok(!err, 'add should not error');
        t.strictEqual(3, res.queue.length, 'should have 3 redis operations');
        res.exec(function (err) {
            t.ok(!err, 'exec should not error');

            // Check sub-user record has access key
            REDIS.get(key, function (err, userRes) {
                t.ok(!err, 'redis get should not error');
                var userPayload = JSON.parse(userRes);
                t.ok(userPayload.accesskeys,
                      'sub-user should have accesskeys object');
                t.equal(userPayload.accesskeys['AKIASUBUSER000000001'],
                    'subuserSecretKeyForTesting123456789abcdef',
                    'sub-user access key secret should be stored correctly');

                // Check reverse lookup points to sub-user UUID
                REDIS.get(accessKeyLookupKey, function (err, lookupRes) {
                    t.ok(!err, 'reverse lookup should not error');
                    t.equal(lookupRes, '550e8400-e29b-41d4-a716-446655440003',
                        'reverse lookup should map to sub-user UUID');
                    t.done();
                });
            });
        });
    });
});

test('add - multiple access keys for same user', function (t) {
    var entry = {
        'dn': 'changenumber=3, cn=changelog',
        'controls': [],
        'targetdn': 'accesskeyid=AKIA987654321EXAMPLE, ' +
            'uuid=550e8400-e29b-41d4-a716-446655440001, ' +
            'ou=users, o=smartdc',
        'changetype': 'add',
        'objectclass': 'changeLogEntry',
        'changetime': '2025-01-16T12:00:00.000Z',
        'changes': {
            'accesskeyid': [
                'AKIA987654321EXAMPLE'
            ],
            'accesskeysecret': [
                'abcdefghijklmnopqrstuvwxyz1234567890ABCD'
            ],
            'created': [
                '1761762138761'
            ],
            'status': [
                'Active'
            ],
            'updated': [
                '1761762138761'
            ],
            'objectclass': [
                'accesskey'
            ],
            '_owner': [
                '550e8400-e29b-41d4-a716-446655440001'
            ],
            '_parent': [
                'uuid=550e8400-e29b-41d4-a716-446655440001, ' +
                    'ou=users, o=smartdc'
            ]
        },
        'changenumber': '3'
    };

    var args = {
        changes: entry.changes,
        entry: entry,
        log: this.log,
        redis: REDIS
    };

    var key = '/uuid/550e8400-e29b-41d4-a716-446655440001';

    transform.add(args, function (err, res) {
        t.ok(!err, 'add should not error');
        res.exec(function (err) {
            t.ok(!err, 'exec should not error');

            // Check user now has both access keys
            REDIS.get(key, function (err, userRes) {
                t.ok(!err, 'redis get should not error');
                var userPayload = JSON.parse(userRes);
                t.ok(userPayload.accesskeys,
                        'user should have accesskeys object');

                // Should have both keys
                t.equal(Object.keys(userPayload.accesskeys).length, 2,
                    'user should have 2 access keys');
                t.equal(userPayload.accesskeys['AKIA123456789EXAMPLE'],
                    'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
                    'first access key should still be present');
                t.equal(userPayload.accesskeys['AKIA987654321EXAMPLE'],
                    'abcdefghijklmnopqrstuvwxyz1234567890ABCD',
                    'second access key should be added');
                t.done();
            });
        });
    });
});

test('add - access key with special characters', function (t) {
    var entry = {
        'dn': 'changenumber=4, cn=changelog',
        'controls': [],
        'targetdn': 'accesskeyid=AKIASPECIALCHARS0001, ' +
            'uuid=550e8400-e29b-41d4-a716-446655440001, ' +
            'ou=users, o=smartdc',
        'changetype': 'add',
        'objectclass': 'changeLogEntry',
        'changetime': '2025-01-16T12:00:00.000Z',
        'changes': {
            'accesskeyid': [
                'AKIASPECIALCHARS0001'
            ],
            'accesskeysecret': [
                'special+/=Secret123!@#$%^&*()_+-=[]{};\':' +
                    '"|,.<>?'
            ],
            'created': [
                '1761762138761'
            ],
            'status': [
                'Active'
            ],
            'updated': [
                '1761762138761'
            ],
            'objectclass': [
                'accesskey'
            ],
            '_owner': [
                '550e8400-e29b-41d4-a716-446655440001'
            ],
            '_parent': [
                'uuid=550e8400-e29b-41d4-a716-446655440001, ' +
                    'ou=users, o=smartdc'
            ]
        },
        'changenumber': '4'
    };

    var args = {
        changes: entry.changes,
        entry: entry,
        log: this.log,
        redis: REDIS
    };

    var key = '/uuid/550e8400-e29b-41d4-a716-446655440001';
    var specialSecret = 'special+/=Secret123!@#$%^&*()_+-=[]{};\':' +
            '"|,.<>?';

    transform.add(args, function (err, res) {
        t.ok(!err, 'add should not error');
        res.exec(function (err) {
            t.ok(!err, 'exec should not error');

            REDIS.get(key, function (err, userRes) {
                t.ok(!err, 'redis get should not error');
                var userPayload = JSON.parse(userRes);
                t.equal(userPayload.accesskeys['AKIASPECIALCHARS0001'],
                    specialSecret,
                    'access key with special characters should be stored ' +
                    'correctly');
                t.done();
            });
        });
    });
});

test('modify - status update (Active to Inactive)', function (t) {
    var modEntry = {
        'accesskeyid': [
            'AKIA123456789EXAMPLE'
        ],
        'accesskeysecret': [
            'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
        ],
        'created': [
            '1761760834864'
        ],
        'objectclass': [
            'accesskey'
        ],
        'status': [
            'Inactive'
        ],
        'updated': [
            '1761760874472'
        ],
        '_owner': [
            '550e8400-e29b-41d4-a716-446655440001'
        ],
        '_parent': [
            'uuid=550e8400-e29b-41d4-a716-446655440001, ' +
                'ou=users, o=smartdc'
        ]
    };

    var changes = [
      {
        'operation': 'replace',
        'modification': {
          'type': 'status',
          'vals': [
            'Inactive'
          ]
        }
      },
      {
        'operation': 'replace',
        'modification': {
          'type': 'updated',
          'vals': [
            '1761760874472'
          ]
        }
      }
    ];

    var opts = {
        log: this.log,
        redis: REDIS,
        changes: changes,
        modEntry: modEntry
    };

    var key = '/uuid/550e8400-e29b-41d4-a716-446655440001';
    var accessKeyLookupKey = '/accesskey/AKIA123456789EXAMPLE';

    transform.modify(opts, function (err, res) {
        t.ok(!err, 'modify should not error');
        t.ok(res, 'modify should return a redis multi');

        t.strictEqual(3, res.queue.length, 'should have 3 redis operations');
        res.exec(function (err) {
            t.ok(!err, 'exec should not error');

            // Check access key is removed from user record
            REDIS.get(key, function (err, userRes) {
                t.ok(!err, 'redis get should not error');
                var userPayload = JSON.parse(userRes);
                t.ok(userPayload.accesskeys,
                        'user should still have accesskeys object');
                t.equal(userPayload.accesskeys['AKIA123456789EXAMPLE'],
                    undefined,
                    'deleted access key should be removed');

                // Other keys should still exist
                t.equal(Object.keys(userPayload.accesskeys).length, 2,
                        'user should have 2 remaining access keys');
                t.equal(userPayload.accesskeys['AKIA987654321EXAMPLE'],
                    'abcdefghijklmnopqrstuvwxyz1234567890ABCD',
                    'other access keys should remain');

                // Check reverse lookup is removed
                REDIS.get(accessKeyLookupKey, function (err, lookupRes) {
                    t.ok(!err, 'reverse lookup get should not error');
                    t.equal(lookupRes, null,
                        'reverse lookup should be removed');
                    t.done();
                });
            });
        });
    });
});

test('modify - status update (Inactive to Active)', function (t) {
    var modEntry = {
        'accesskeyid': [
            'AKIA123456789EXAMPLE'
        ],
        'accesskeysecret': [
            'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
        ],
        'created': [
            '1761760834864'
        ],
        'objectclass': [
            'accesskey'
        ],
        'status': [
            'Active'
        ],
        'updated': [
            '1761760874472'
        ],
        '_owner': [
            '550e8400-e29b-41d4-a716-446655440001'
        ],
        '_parent': [
            'uuid=550e8400-e29b-41d4-a716-446655440001, ' +
                'ou=users, o=smartdc'
        ]
    };

    var changes = [
      {
        'operation': 'replace',
        'modification': {
          'type': 'status',
          'vals': [
            'Active'
          ]
        }
      },
      {
        'operation': 'replace',
        'modification': {
          'type': 'updated',
          'vals': [
            '1761760874472'
          ]
        }
      }
    ];

    var opts = {
        log: this.log,
        redis: REDIS,
        changes: changes,
        modEntry: modEntry
    };

    var key = '/uuid/550e8400-e29b-41d4-a716-446655440001';
    var accessKeyLookupKey = '/accesskey/AKIA123456789EXAMPLE';

    transform.modify(opts, function (err, res) {
        t.ok(!err, 'add should not error');
        t.strictEqual(3, res.queue.length, 'should have 3 redis operations');
        res.exec(function (err) {
            t.ok(!err, 'exec should not error');
            // Check user record has access key
            REDIS.get(key, function (err, userRes) {
                t.ok(!err, 'redis get should not error');
                var userPayload = JSON.parse(userRes);
                t.ok(userPayload.accesskeys,
                    'user should have accesskeys object');
                t.equal(userPayload.accesskeys['AKIA123456789EXAMPLE'],
                    'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
                    'access key secret should be stored correctly');
                // Check reverse lookup
                REDIS.get(accessKeyLookupKey, function (err, lookupRes) {
                    t.ok(!err, 'reverse lookup should not error');
                    t.equal(lookupRes, '550e8400-e29b-41d4-a716-446655440001',
                        'reverse lookup should map to correct user UUID');
                    t.done();
                });
            });
        });
    });
});

test('delete - access key', function (t) {
    var entry = {
        'dn': 'changenumber=5, cn=changelog',
        'controls': [],
        'targetdn': 'accesskeyid=AKIA987654321EXAMPLE, ' +
            'uuid=550e8400-e29b-41d4-a716-446655440001, ' +
            'ou=users, o=smartdc',
        'changetype': 'delete',
        'objectclass': 'changeLogEntry',
        'changetime': '2025-01-16T12:00:00.000Z',
        'changes': {
            'accesskeyid': [
                'AKIA987654321EXAMPLE'
            ],
            'accesskeysecret': [
                'abcdefghijklmnopqrstuvwxyz1234567890ABCD'
            ],
            'objectclass': [
                'accesskey'
            ],
            '_owner': [
                '550e8400-e29b-41d4-a716-446655440001'
            ],
            '_parent': [
                'uuid=550e8400-e29b-41d4-a716-446655440001, ' +
                    'ou=users, o=smartdc'
            ]
        },
        'changenumber': '5'
    };

    var args = {
        changes: entry.changes,
        entry: entry,
        log: this.log,
        redis: REDIS
    };

    var key = '/uuid/550e8400-e29b-41d4-a716-446655440001';
    var accessKeyLookupKey = '/accesskey/AKIA987654321EXAMPLE';

    transform.delete(args, function (err, res) {
        t.ok(!err, 'delete should not error');
        t.strictEqual(3, res.queue.length, 'should have 3 redis operations');
        res.exec(function (err) {
            t.ok(!err, 'exec should not error');

            // Check access key is removed from user record
            REDIS.get(key, function (err, userRes) {
                t.ok(!err, 'redis get should not error');
                var userPayload = JSON.parse(userRes);
                t.ok(userPayload.accesskeys,
                        'user should still have accesskeys object');
                t.equal(userPayload.accesskeys['AKIA987654321EXAMPLE'],
                    undefined,
                    'deleted access key should be removed');

                // Other keys should still exist
                t.equal(Object.keys(userPayload.accesskeys).length, 2,
                        'user should have 2 remaining access keys');
                t.equal(userPayload.accesskeys['AKIA123456789EXAMPLE'],
                    'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
                    'other access keys should remain');

                // Check reverse lookup is removed
                REDIS.get(accessKeyLookupKey, function (err, lookupRes) {
                    t.ok(!err, 'reverse lookup get should not error');
                    t.equal(lookupRes, null,
                        'reverse lookup should be removed');
                    t.done();
                });
            });
        });
    });
});

test('delete - last access key', function (t) {
    // First delete the remaining keys to test empty state
    var deleteSpecialEntry = {
        'dn': 'changenumber=6, cn=changelog',
        'controls': [],
        'targetdn': 'accesskeyid=AKIASPECIALCHARS0001, ' +
                'uuid=550e8400-e29b-41d4-a716-446655440001, ' +
                'ou=users, o=smartdc',
        'changetype': 'delete',
        'objectclass': 'changeLogEntry',
        'changetime': '2025-01-16T12:00:00.000Z',
        'changes': {
            'accesskeyid': [
                'AKIASPECIALCHARS0001'
            ],
            'accesskeysecret': [
                'special+/=Secret123!@#$%^&*()_+-=[]{};\':' +
                '"|,.<>?'
            ],
            'objectclass': [
                'accesskey'
            ],
            '_owner': [
                '550e8400-e29b-41d4-a716-446655440001'
            ],
            '_parent': [
                'uuid=550e8400-e29b-41d4-a716-446655440001, ' +
                    'ou=users, o=smartdc'
            ]
        },
        'changenumber': '6'
    };

    var deleteLastEntry = {
        'dn': 'changenumber=7, cn=changelog',
        'controls': [],
        'targetdn': 'accesskeyid=AKIA123456789EXAMPLE, ' +
            'uuid=550e8400-e29b-41d4-a716-446655440001, ' +
            'ou=users, o=smartdc',
        'changetype': 'delete',
        'objectclass': 'changeLogEntry',
        'changetime': '2025-01-16T12:00:00.000Z',
        'changes': {
            'accesskeyid': [
                'AKIA123456789EXAMPLE'
            ],
            'accesskeysecret': [
                'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
            ],
            'objectclass': [
                'accesskey'
            ],
            '_owner': [
                '550e8400-e29b-41d4-a716-446655440001'
            ],
            '_parent': [
                'uuid=550e8400-e29b-41d4-a716-446655440001, ' +
                    'ou=users, o=smartdc'
            ]
        },
        'changenumber': '7'
    };

    var key = '/uuid/550e8400-e29b-41d4-a716-446655440001';
    var log = this.log;

    // Delete second-to-last key
    transform.delete({
        changes: deleteSpecialEntry.changes,
        entry: deleteSpecialEntry,
        log: log,
        redis: REDIS
    }, function (err, res) {
        t.ok(!err, 'delete should not error');
        res.exec(function (err) {
            t.ok(!err, 'exec should not error');

            // Delete last key
            transform.delete({
                changes: deleteLastEntry.changes,
                entry: deleteLastEntry,
                log: log,
                redis: REDIS
            }, function (err, res) {
                t.ok(!err, 'delete should not error');
                res.exec(function (err) {
                    t.ok(!err, 'exec should not error');

                    // Check user has empty accesskeys object
                    REDIS.get(key, function (err, userRes) {
                        t.ok(!err, 'redis get should not error');
                        var userPayload = JSON.parse(userRes);
                        t.ok(userPayload.accesskeys,
                            'user should still have accesskeys object');
                        t.equal(Object.keys(userPayload.accesskeys).length,
                            0, 'user should have no access keys');
                        t.done();
                    });
                });
            });
        });
    });
});

test('delete - nonexistent access key', function (t) {
    var entry = {
        'dn': 'changenumber=8, cn=changelog',
        'controls': [],
        'targetdn': 'accesskeyid=AKIANONEXISTENT0001, ' +
            'uuid=550e8400-e29b-41d4-a716-446655440001, ' +
            'ou=users, o=smartdc',
        'changetype': 'delete',
        'objectclass': 'changeLogEntry',
        'changetime': '2025-01-16T12:00:00.000Z',
        'changes': {
            'accesskeyid': [
                'AKIANONEXISTENT0001'
            ],
            'accesskeysecret': [
                'nonexistentsecret'
            ],
            'objectclass': [
                'accesskey'
            ],
            '_owner': [
                '550e8400-e29b-41d4-a716-446655440001'
            ],
            '_parent': [
                'uuid=550e8400-e29b-41d4-a716-446655440001, ' +
                    'ou=users, o=smartdc'
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

    var key = '/uuid/550e8400-e29b-41d4-a716-446655440001';

    transform.delete(args, function (err, res) {
        t.ok(!err, 'delete should not error even for nonexistent key');
        res.exec(function (err) {
            t.ok(!err, 'exec should not error');

            // User record should be unchanged
            REDIS.get(key, function (err, userRes) {
                t.ok(!err, 'redis get should not error');
                var userPayload = JSON.parse(userRes);
                t.ok(userPayload.accesskeys,
                    'user should still have accesskeys object');
                t.equal(Object.keys(userPayload.accesskeys).length, 0,
                    'user should still have no access keys');
                t.done();
            });
        });
    });
});

test('modify - subuser status update (Inactive to Active)', function (t) {
    var modEntry = {
        'accesskeyid': [
            'AKIASUBUSER000000001'
        ],
        'accesskeysecret': [
            'subuserSecretKeyForTesting123456789abcdef'
        ],
        'created': [
            '1761760834864'
        ],
        'objectclass': [
            'accesskey'
        ],
        'status': [
            'Active'
        ],
        'updated': [
            '1761760874472'
        ],
        '_owner': [
            '550e8400-e29b-41d4-a716-446655440003'
        ],
        '_parent': [
            'uuid=550e8400-e29b-41d4-a716-446655440003, ' +
            'uuid=550e8400-e29b-41d4-a716-446655440001, ' +
            'ou=users, o=smartdc'
        ]
    };

    var changes = [
      {
        'operation': 'replace',
        'modification': {
          'type': 'status',
          'vals': [
            'Active'
          ]
        }
      },
      {
        'operation': 'replace',
        'modification': {
          'type': 'updated',
          'vals': [
            '1761760874472'
          ]
        }
      }
    ];

    var opts = {
        log: this.log,
        redis: REDIS,
        changes: changes,
        modEntry: modEntry
    };

    var key = '/uuid/550e8400-e29b-41d4-a716-446655440003';
    var accessKeyLookupKey = '/accesskey/AKIASUBUSER000000001';

    transform.modify(opts, function (err, res) {
        t.ok(!err, 'modify should not error');
        t.ok(res, 'modify should return a redis multi');

        t.strictEqual(3, res.queue.length, 'should have 3 redis operations');
        res.exec(function (err) {
            t.ok(!err, 'exec should not error');

            // Check sub-user record has access key
            REDIS.get(key, function (err, userRes) {
                t.ok(!err, 'redis get should not error');
                var userPayload = JSON.parse(userRes);
                t.ok(userPayload.accesskeys,
                      'sub-user should have accesskeys object');
                t.equal(userPayload.accesskeys['AKIASUBUSER000000001'],
                    'subuserSecretKeyForTesting123456789abcdef',
                    'sub-user access key secret should be stored correctly');

                // Check reverse lookup points to sub-user UUID
                REDIS.get(accessKeyLookupKey, function (err, lookupRes) {
                    t.ok(!err, 'reverse lookup should not error');
                    t.equal(lookupRes, '550e8400-e29b-41d4-a716-446655440003',
                        'reverse lookup should map to sub-user UUID');
                    t.done();
                });
            });
        });
    });
});

test('modify - subuser status update (Active to Inactive)', function (t) {
    var modEntry = {
        'accesskeyid': [
            'AKIASUBUSER000000001'
        ],
        'accesskeysecret': [
            'subuserSecretKeyForTesting123456789abcdef'
        ],
        'created': [
            '1761760834864'
        ],
        'objectclass': [
            'accesskey'
        ],
        'status': [
            'Inactive'
        ],
        'updated': [
            '1761760874472'
        ],
        '_owner': [
            '550e8400-e29b-41d4-a716-446655440003'
        ],
        '_parent': [
            'uuid=550e8400-e29b-41d4-a716-446655440003, ' +
            'uuid=550e8400-e29b-41d4-a716-446655440001, ' +
            'ou=users, o=smartdc'
        ]
    };

    var changes = [
      {
        'operation': 'replace',
        'modification': {
          'type': 'status',
          'vals': [
            'Inactive'
          ]
        }
      },
      {
        'operation': 'replace',
        'modification': {
          'type': 'updated',
          'vals': [
            '1761760874472'
          ]
        }
      }
    ];

    var opts = {
        log: this.log,
        redis: REDIS,
        changes: changes,
        modEntry: modEntry
    };

    var key = '/uuid/550e8400-e29b-41d4-a716-446655440003';
    var accessKeyLookupKey = '/accesskey/AKIASUBUSER000000001';

    transform.modify(opts, function (err, res) {
        t.ok(!err, 'modify should not error');
        t.ok(res, 'modify should return a redis multi');

        t.strictEqual(3, res.queue.length, 'should have 3 redis operations');
        res.exec(function (err) {
            t.ok(!err, 'exec should not error');

            // Check access key is removed from user record
            REDIS.get(key, function (err, userRes) {
                t.ok(!err, 'redis get should not error');
                var userPayload = JSON.parse(userRes);
                t.equal(userPayload.accesskeys['AKIASUBUSER000000001'],
                    undefined,
                    'deleted access key should be removed');

                // Check reverse lookup is removed
                REDIS.get(accessKeyLookupKey, function (err, lookupRes) {
                    t.ok(!err, 'reverse lookup get should not error');
                    t.equal(lookupRes, null,
                        'reverse lookup should be removed');
                    t.done();
                });
            });
        });
    });
});

test('modify - description update (NOP)', function (t) {
    var modEntry = {
        'accesskeyid': [
            'AKIASUBUSER000000001'
        ],
        'accesskeysecret': [
            'subuserSecretKeyForTesting123456789abcdef'
        ],
        'created': [
            '1761760834864'
        ],
        'objectclass': [
            'accesskey'
        ],
        'status': [
            'Inactive'
        ],
        'updated': [
            '1761760874472'
        ],
        '_owner': [
            '550e8400-e29b-41d4-a716-446655440003'
        ],
        '_parent': [
            'uuid=550e8400-e29b-41d4-a716-446655440003, ' +
            'uuid=550e8400-e29b-41d4-a716-446655440001, ' +
            'ou=users, o=smartdc'
        ]
    };

    var changes = [
      {
        'operation': 'replace',
        'modification': {
          'type': 'description',
          'vals': [
            'Ignore Me'
          ]
        }
      },
      {
        'operation': 'replace',
        'modification': {
          'type': 'updated',
          'vals': [
            '1761760874472'
          ]
        }
      }
    ];

    var opts = {
        log: this.log,
        redis: REDIS,
        changes: changes,
        modEntry: modEntry
    };

    var key = '/uuid/550e8400-e29b-41d4-a716-446655440003';
    var accessKeyLookupKey = '/accesskey/AKIASUBUSER000000001';

    transform.modify(opts, function (err, res) {
        t.ok(!err, 'modify should not error');
        t.ok(res, 'modify should return a redis multi');

        t.strictEqual(1, res.queue.length, 'should have 1   redis operations');
        res.exec(function (err) {
            t.ok(!err, 'exec should not error');
            // Check sub-user record
            REDIS.get(key, function (err, userRes) {
                t.ok(!err, 'redis get should not error');
                var userPayload = JSON.parse(userRes);
                t.ok(userPayload.accesskeys,
                      'sub-user should have accesskeys object');
                t.equal(Object.keys(userPayload.accesskeys).length, 0,
                    'sub-user should still have no keys');

                // Check reverse lookup is still absent
                REDIS.get(accessKeyLookupKey, function (err, lookupRes) {
                    t.ok(!err, 'reverse lookup get should not error');
                    t.equal(lookupRes, null,
                        'reverse lookup should be removed');
                    t.done();
                });
            });
        });
    });
});

// Test edge cases and error scenarios
test('error handling - missing owner', function (t) {
    var entry = {
        'dn': 'changenumber=9, cn=changelog',
        'controls': [],
        'targetdn': 'accesskeyid=AKIAMISSINGOWNER01, ' +
            'ou=users, o=smartdc',
        'changetype': 'add',
        'objectclass': 'changeLogEntry',
        'changetime': '2025-01-16T12:00:00.000Z',
        'changes': {
            'accesskeyid': [
                'AKIAMISSINGOWNER01'
            ],
            'accesskeysecret': [
                'secretwithoutowner'
            ],
            'created': [
                '1761762138761'
            ],
            'status': [
                'Active'
            ],
            'updated': [
                '1761762138761'
            ],
            'objectclass': [
                'accesskey'
            ]
            // Missing _owner field
        },
        'changenumber': '9'
    };

    var args = {
        changes: entry.changes,
        entry: entry,
        log: this.log,
        redis: REDIS
    };

    transform.add(args, function (err, res) {
        t.ok(err, 'add should error when _owner is missing');
        t.done();
    });
});

test('error handling - redis error', function (t) {
    // Create a redis client that will error
    var errorRedis = {
        get: function (key, cb) {
            cb(new Error('Redis connection failed'));
        },
        multi: function () {
            return {
                queue: [],
                exec: function (cb) { cb(); }
            };
        }
    };

    var entry = {
        'dn': 'changenumber=10, cn=changelog',
        'controls': [],
        'targetdn': 'accesskeyid=AKIAREDISTEQTEST01, ' +
            'uuid=550e8400-e29b-41d4-a716-446655440001, ' +
            'ou=users, o=smartdc',
        'changetype': 'add',
        'objectclass': 'changeLogEntry',
        'changetime': '2025-01-16T12:00:00.000Z',
        'changes': {
            'accesskeyid': [
                'AKIAREDISTEQTEST01'
            ],
            'accesskeysecret': [
                'testrediserror'
            ],
            'created': [
                '1761762138761'
            ],
            'status': [
                'Active'
            ],
            'updated': [
                '1761762138761'
            ],
            'objectclass': [
                'accesskey'
            ],
            '_owner': [
                '550e8400-e29b-41d4-a716-446655440001'
            ]
        },
        'changenumber': '10'
    };

    var args = {
        changes: entry.changes,
        entry: entry,
        log: this.log,
        redis: errorRedis
    };

    transform.add(args, function (err, res) {
        t.ok(err, 'add should propagate redis errors');
        t.equal(err.message, 'Redis connection failed',
            'error message should be preserved');
        t.done();
    });
});
