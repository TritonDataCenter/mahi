/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2026 Edgecast Cloud LLC.
 */

/*
 * Unit tests for per-bucket access key scope support across:
 *   - Replicator transforms (add, modify, delete scoped keys)
 *   - SigV4 verification (scoped permanent + temporary credentials)
 *   - STS helper functions (scope inheritance)
 */

var transform = require('../lib/replicator/transforms/accesskey.js');
var sigv4 = require('../lib/server/sigv4');
var sts = require('../lib/server/sts.js');
var SigV4Helper = require('./lib/sigv4-helper');
var crypto = require('crypto');
var bunyan = require('bunyan');

var redis = require('fakeredis');
var REDIS;

var nodeunit = require('nodeunit-plus');
var test = nodeunit.test;

var helper = new SigV4Helper({region: 'us-east-1', service: 's3'});

var SCOPE_JSON = JSON.stringify({
    version: 1,
    permissions: [
        { bucket: 'app-data', level: 'readwrite' },
        { bucket: 'logs-*', level: 'read' }
    ]
});

var USER_UUID = '550e8400-e29b-41d4-a716-446655440099';
var SCOPED_KEY_ID = 'AKIASCOPED00000000001';
var SCOPED_SECRET = 'scopedSecretKeyForTesting123456789abcdef0';
var UNSCOPED_KEY_ID = 'AKIAUNSCOPED000000001';
var UNSCOPED_SECRET = 'unscopedSecretKeyForTesting12345678abcde';

/*
 * PART 1: Replicator transforms — scoped key add/modify/delete
 */

test('setup - fresh redis', function (t) {
    REDIS = redis.createClient();
    t.done();
});

/* --- add: scoped permanent key --- */

test('add - scoped permanent key stores object format in Redis',
    function (t) {
    var entry = {
        dn: 'changenumber=100, cn=changelog',
        controls: [],
        targetdn: 'accesskeyid=' + SCOPED_KEY_ID +
            ', uuid=' + USER_UUID + ', ou=users, o=smartdc',
        changetype: 'add',
        objectclass: 'changeLogEntry',
        changetime: '2026-04-18T12:00:00.000Z',
        changes: {
            accesskeyid: [SCOPED_KEY_ID],
            accesskeysecret: [SCOPED_SECRET],
            accesskeyscope: [SCOPE_JSON],
            created: ['1761762138761'],
            status: ['Active'],
            updated: ['1761762138761'],
            objectclass: ['accesskey'],
            _owner: [USER_UUID],
            _parent: ['uuid=' + USER_UUID + ', ou=users, o=smartdc']
        },
        changenumber: '100'
    };

    var args = {
        changes: entry.changes,
        entry: entry,
        log: this.log,
        redis: REDIS
    };

    var userKey = '/uuid/' + USER_UUID;
    var lookupKey = '/accesskey/' + SCOPED_KEY_ID;

    transform.add(args, function (err, res) {
        t.ok(!err, 'add should not error');
        t.strictEqual(3, res.queue.length,
            'should have 3 redis operations');

        res.exec(function (execErr) {
            t.ok(!execErr, 'exec should not error');

            REDIS.get(userKey, function (getErr, userRes) {
                t.ok(!getErr, 'redis get should not error');
                var payload = JSON.parse(userRes);
                var keyData = payload.accesskeys[SCOPED_KEY_ID];

                // Scoped key must be stored as object, not string
                t.equal(typeof (keyData), 'object',
                    'scoped key should be stored as object');
                t.equal(keyData.secret, SCOPED_SECRET,
                    'secret should be correct');
                t.equal(keyData.scope, SCOPE_JSON,
                    'scope JSON should be preserved');

                // Reverse lookup should be JSON with userUuid
                REDIS.get(lookupKey, function (lErr, lookupRes) {
                    t.ok(!lErr, 'reverse lookup should not error');
                    var lookupData = JSON.parse(lookupRes);
                    t.equal(lookupData.type, 'accesskey',
                        'lookup should have type');
                    t.equal(lookupData.userUuid, USER_UUID,
                        'lookup should have correct userUuid');
                    t.equal(lookupData.credentialType, 'permanent',
                        'lookup should have correct credentialType');
                    t.equal(lookupData.scope, SCOPE_JSON,
                        'lookup should have scope');
                    t.done();
                });
            });
        });
    });
});

/* --- add: unscoped key alongside scoped key --- */

test('add - unscoped key uses unified object format',
    function (t) {
    var entry = {
        dn: 'changenumber=101, cn=changelog',
        controls: [],
        targetdn: 'accesskeyid=' + UNSCOPED_KEY_ID +
            ', uuid=' + USER_UUID + ', ou=users, o=smartdc',
        changetype: 'add',
        objectclass: 'changeLogEntry',
        changetime: '2026-04-18T12:00:00.000Z',
        changes: {
            accesskeyid: [UNSCOPED_KEY_ID],
            accesskeysecret: [UNSCOPED_SECRET],
            created: ['1761762138761'],
            status: ['Active'],
            updated: ['1761762138761'],
            objectclass: ['accesskey'],
            _owner: [USER_UUID],
            _parent: ['uuid=' + USER_UUID + ', ou=users, o=smartdc']
        },
        changenumber: '101'
    };

    var args = {
        changes: entry.changes,
        entry: entry,
        log: this.log,
        redis: REDIS
    };

    var userKey = '/uuid/' + USER_UUID;
    var lookupKey = '/accesskey/' + UNSCOPED_KEY_ID;

    transform.add(args, function (err, res) {
        t.ok(!err, 'add should not error');
        res.exec(function (execErr) {
            t.ok(!execErr, 'exec should not error');

            REDIS.get(userKey, function (getErr, userRes) {
                t.ok(!getErr);
                var payload = JSON.parse(userRes);

                // Unscoped key should be object with scope: null
                var unscopedData =
                    payload.accesskeys[UNSCOPED_KEY_ID];
                t.equal(typeof (unscopedData), 'object',
                    'unscoped key should be stored as object');
                t.equal(unscopedData.secret, UNSCOPED_SECRET,
                    'unscoped secret should be correct');
                t.equal(unscopedData.scope, null,
                    'unscoped key should have scope: null');

                // Scoped key should still be object
                t.equal(
                    typeof (payload.accesskeys[SCOPED_KEY_ID]),
                    'object',
                    'scoped key should still be object');

                // Reverse lookup should be JSON with scope: null
                REDIS.get(lookupKey, function (lErr, lookupRes) {
                    t.ok(!lErr);
                    var lookupData = JSON.parse(lookupRes);
                    t.equal(lookupData.userUuid, USER_UUID,
                        'unscoped reverse lookup userUuid');
                    t.equal(lookupData.credentialType,
                        'permanent',
                        'unscoped reverse lookup type');
                    t.equal(lookupData.scope, null,
                        'unscoped reverse lookup scope null');
                    t.done();
                });
            });
        });
    });
});

/* --- modify: scope-only change --- */

test('modify - scope-only change updates Redis', function (t) {
    var newScope = JSON.stringify({
        version: 1,
        permissions: [
            { bucket: 'new-bucket', level: 'full' }
        ]
    });

    var modEntry = {
        accesskeyid: [SCOPED_KEY_ID],
        accesskeysecret: [SCOPED_SECRET],
        accesskeyscope: [newScope],
        created: ['1761760834864'],
        objectclass: ['accesskey'],
        status: ['Active'],
        updated: ['1761760874472'],
        _owner: [USER_UUID],
        _parent: ['uuid=' + USER_UUID + ', ou=users, o=smartdc']
    };

    var changes = [
        {
            operation: 'replace',
            modification: {
                type: 'accesskeyscope',
                vals: [newScope]
            }
        },
        {
            operation: 'replace',
            modification: {
                type: 'updated',
                vals: ['1761760874472']
            }
        }
    ];

    var opts = {
        log: this.log,
        redis: REDIS,
        changes: changes,
        modEntry: modEntry,
        entry: { changenumber: '999' }
    };

    var userKey = '/uuid/' + USER_UUID;
    var lookupKey = '/accesskey/' + SCOPED_KEY_ID;

    transform.modify(opts, function (err, res) {
        t.ok(!err, 'modify should not error');
        t.ok(res, 'modify should return batch');
        // Should NOT be a NOP (must have redis writes)
        t.ok(res.queue.length > 1,
            'should have redis operations (not NOP)');

        res.exec(function (execErr) {
            t.ok(!execErr, 'exec should not error');

            REDIS.get(userKey, function (getErr, userRes) {
                t.ok(!getErr);
                var payload = JSON.parse(userRes);
                var keyData = payload.accesskeys[SCOPED_KEY_ID];
                t.equal(typeof (keyData), 'object',
                    'scoped key should still be object');
                t.equal(keyData.scope, newScope,
                    'scope should be updated to new value');
                t.equal(keyData.secret, SCOPED_SECRET,
                    'secret should be preserved');

                REDIS.get(lookupKey, function (lErr, lookupRes) {
                    t.ok(!lErr);
                    var lookupData = JSON.parse(lookupRes);
                    t.equal(lookupData.scope, newScope,
                        'reverse lookup scope should be updated');
                    t.done();
                });
            });
        });
    });
});

/* --- modify: scope removal sets scope to null --- */

test('modify - scope removal stores object with scope null',
    function (t) {
    var modEntry = {
        accesskeyid: [SCOPED_KEY_ID],
        accesskeysecret: [SCOPED_SECRET],
        created: ['1761760834864'],
        objectclass: ['accesskey'],
        status: ['Active'],
        updated: ['1761760874472'],
        _owner: [USER_UUID],
        _parent: ['uuid=' + USER_UUID + ', ou=users, o=smartdc']
    };

    var changes = [
        {
            operation: 'delete',
            modification: {
                type: 'accesskeyscope',
                vals: []
            }
        },
        {
            operation: 'replace',
            modification: {
                type: 'updated',
                vals: ['1761760874472']
            }
        }
    ];

    var opts = {
        log: this.log,
        redis: REDIS,
        changes: changes,
        modEntry: modEntry,
        entry: { changenumber: '999' }
    };

    var userKey = '/uuid/' + USER_UUID;
    var lookupKey = '/accesskey/' + SCOPED_KEY_ID;

    transform.modify(opts, function (err, res) {
        t.ok(!err, 'modify should not error');
        t.ok(res.queue.length > 1,
            'should have redis operations (not NOP)');

        res.exec(function (execErr) {
            t.ok(!execErr, 'exec should not error');

            REDIS.get(userKey, function (getErr, userRes) {
                t.ok(!getErr);
                var payload = JSON.parse(userRes);
                var keyData = payload.accesskeys[SCOPED_KEY_ID];
                // After scope removal, key should be object
                // with scope: null
                t.equal(typeof (keyData), 'object',
                    'key should remain object format');
                t.equal(keyData.secret, SCOPED_SECRET,
                    'secret should be correct');
                t.equal(keyData.scope, null,
                    'scope should be null after removal');

                REDIS.get(lookupKey, function (lErr, lookupRes) {
                    t.ok(!lErr);
                    var lookupData = JSON.parse(lookupRes);
                    t.equal(lookupData.userUuid, USER_UUID,
                        'reverse lookup userUuid correct');
                    t.equal(lookupData.scope, null,
                        'reverse lookup scope should be null');
                    t.done();
                });
            });
        });
    });
});

/* --- modify: status change on scoped key preserves scope --- */

test('modify - deactivate scoped key removes from Redis',
    function (t) {
    // First re-add the scoped key so we can deactivate it
    var addEntry = {
        dn: 'changenumber=102, cn=changelog',
        controls: [],
        targetdn: 'accesskeyid=' + SCOPED_KEY_ID +
            ', uuid=' + USER_UUID + ', ou=users, o=smartdc',
        changetype: 'add',
        objectclass: 'changeLogEntry',
        changetime: '2026-04-18T12:00:00.000Z',
        changes: {
            accesskeyid: [SCOPED_KEY_ID],
            accesskeysecret: [SCOPED_SECRET],
            accesskeyscope: [SCOPE_JSON],
            created: ['1761762138761'],
            status: ['Active'],
            updated: ['1761762138761'],
            objectclass: ['accesskey'],
            _owner: [USER_UUID],
            _parent: ['uuid=' + USER_UUID + ', ou=users, o=smartdc']
        },
        changenumber: '102'
    };

    var log = this.log;

    transform.add({
        changes: addEntry.changes,
        entry: addEntry,
        log: log,
        redis: REDIS
    }, function (addErr, addRes) {
        t.ok(!addErr, 'add should not error');
        addRes.exec(function () {
            // Now deactivate
            var modEntry = {
                accesskeyid: [SCOPED_KEY_ID],
                accesskeysecret: [SCOPED_SECRET],
                accesskeyscope: [SCOPE_JSON],
                created: ['1761760834864'],
                objectclass: ['accesskey'],
                status: ['Inactive'],
                updated: ['1761760874472'],
                _owner: [USER_UUID],
                _parent: ['uuid=' + USER_UUID +
                    ', ou=users, o=smartdc']
            };

            var changes = [
                {
                    operation: 'replace',
                    modification: {
                        type: 'status',
                        vals: ['Inactive']
                    }
                },
                {
                    operation: 'replace',
                    modification: {
                        type: 'updated',
                        vals: ['1761760874472']
                    }
                }
            ];

            transform.modify({
                log: log,
                redis: REDIS,
                changes: changes,
                modEntry: modEntry,
                entry: { changenumber: '999' }
            }, function (modErr, modRes) {
                t.ok(!modErr, 'modify should not error');
                t.strictEqual(3, modRes.queue.length,
                    'should have 3 redis operations');

                modRes.exec(function () {
                    var userKey = '/uuid/' + USER_UUID;
                    var lookupKey = '/accesskey/' + SCOPED_KEY_ID;

                    REDIS.get(userKey, function (getErr, userRes) {
                        t.ok(!getErr);
                        var payload = JSON.parse(userRes);
                        t.equal(
                            payload.accesskeys[SCOPED_KEY_ID],
                            undefined,
                            'scoped key should be removed');

                        REDIS.get(lookupKey,
                            function (lErr, lookupRes) {
                            t.ok(!lErr);
                            t.equal(lookupRes, null,
                                'reverse lookup should be removed');
                            t.done();
                        });
                    });
                });
            });
        });
    });
});

/* --- modify: reactivate scoped key restores scope --- */

test('modify - reactivate scoped key restores object format',
    function (t) {
    var modEntry = {
        accesskeyid: [SCOPED_KEY_ID],
        accesskeysecret: [SCOPED_SECRET],
        accesskeyscope: [SCOPE_JSON],
        created: ['1761760834864'],
        objectclass: ['accesskey'],
        status: ['Active'],
        updated: ['1761760874472'],
        _owner: [USER_UUID],
        _parent: ['uuid=' + USER_UUID + ', ou=users, o=smartdc']
    };

    var changes = [
        {
            operation: 'replace',
            modification: {
                type: 'status',
                vals: ['Active']
            }
        },
        {
            operation: 'replace',
            modification: {
                type: 'updated',
                vals: ['1761760874472']
            }
        }
    ];

    var opts = {
        log: this.log,
        redis: REDIS,
        changes: changes,
        modEntry: modEntry,
        entry: { changenumber: '999' }
    };

    var userKey = '/uuid/' + USER_UUID;
    var lookupKey = '/accesskey/' + SCOPED_KEY_ID;

    transform.modify(opts, function (err, res) {
        t.ok(!err, 'modify should not error');
        t.strictEqual(3, res.queue.length,
            'should have 3 redis operations');

        res.exec(function (execErr) {
            t.ok(!execErr);

            REDIS.get(userKey, function (getErr, userRes) {
                t.ok(!getErr);
                var payload = JSON.parse(userRes);
                var keyData = payload.accesskeys[SCOPED_KEY_ID];
                t.equal(typeof (keyData), 'object',
                    'reactivated scoped key should be object');
                t.equal(keyData.secret, SCOPED_SECRET,
                    'secret should be correct');
                t.equal(keyData.scope, SCOPE_JSON,
                    'scope should be preserved on reactivation');

                REDIS.get(lookupKey, function (lErr, lookupRes) {
                    t.ok(!lErr);
                    var lookupData = JSON.parse(lookupRes);
                    t.equal(lookupData.userUuid, USER_UUID,
                        'reverse lookup UUID should be correct');
                    t.equal(lookupData.scope, SCOPE_JSON,
                        'reverse lookup scope should be correct');
                    t.done();
                });
            });
        });
    });
});

/* --- delete: scoped key --- */

test('delete - scoped key is fully cleaned up', function (t) {
    var entry = {
        dn: 'changenumber=103, cn=changelog',
        controls: [],
        targetdn: 'accesskeyid=' + SCOPED_KEY_ID +
            ', uuid=' + USER_UUID + ', ou=users, o=smartdc',
        changetype: 'delete',
        objectclass: 'changeLogEntry',
        changetime: '2026-04-18T12:00:00.000Z',
        changes: {
            accesskeyid: [SCOPED_KEY_ID],
            accesskeysecret: [SCOPED_SECRET],
            accesskeyscope: [SCOPE_JSON],
            objectclass: ['accesskey'],
            _owner: [USER_UUID],
            _parent: ['uuid=' + USER_UUID + ', ou=users, o=smartdc']
        },
        changenumber: '103'
    };

    var args = {
        changes: entry.changes,
        entry: entry,
        log: this.log,
        redis: REDIS
    };

    var userKey = '/uuid/' + USER_UUID;
    var lookupKey = '/accesskey/' + SCOPED_KEY_ID;

    transform.delete(args, function (err, res) {
        t.ok(!err, 'delete should not error');
        t.strictEqual(3, res.queue.length,
            'should have 3 redis operations');

        res.exec(function (execErr) {
            t.ok(!execErr);

            REDIS.get(userKey, function (getErr, userRes) {
                t.ok(!getErr);
                var payload = JSON.parse(userRes);
                t.equal(payload.accesskeys[SCOPED_KEY_ID],
                    undefined,
                    'scoped key should be removed from user');

                // Unscoped key should still be there
                var unscopedData =
                    payload.accesskeys[UNSCOPED_KEY_ID];
                t.equal(typeof (unscopedData), 'object',
                    'unscoped key should remain as object');
                t.equal(unscopedData.secret, UNSCOPED_SECRET,
                    'unscoped key secret should remain');

                REDIS.get(lookupKey, function (lErr, lookupRes) {
                    t.ok(!lErr);
                    t.equal(lookupRes, null,
                        'reverse lookup should be removed');
                    t.done();
                });
            });
        });
    });
});

/*
 * PART 2: SigV4 verification — scoped permanent credentials
 */

/*
 * Helper: set up user in Redis and run sigv4 verify.
 * Supports both string (unscoped) and object (scoped) key formats.
 */
function setupAndVerify(opts, t, callback) {
    var user = opts.user;
    var accessKeyId = opts.accessKeyId;
    var secret = opts.secret;
    var lookupVal = opts.lookupVal || user.uuid;

    var log = bunyan.createLogger({
        name: 'scope-sigv4-test',
        level: 'fatal'
    });

    REDIS.set('/uuid/' + user.uuid, JSON.stringify(user),
        function (err1) {
        if (err1) {
            return (callback(err1));
        }
        return (REDIS.set('/accesskey/' + accessKeyId, lookupVal,
            function (err2) {
            if (err2) {
                return (callback(err2));
            }

            var headers = helper.createHeaders({
                method: opts.method || 'GET',
                path: opts.path || '/bucket/key',
                accessKey: accessKeyId,
                secret: secret
            });

            var payloadHash = crypto.createHash('sha256')
                .update('', 'utf8').digest('hex');
            headers['x-amz-content-sha256'] = payloadHash;

            var req = {
                method: opts.method || 'GET',
                url: opts.path || '/bucket/key',
                headers: headers,
                query: {}
            };

            return (sigv4.verifySigV4({
                req: req,
                log: log,
                redis: REDIS
            }, callback));
        }));
    });
}

test('sigv4 - unscoped key returns null bucketScope', function (t) {
    var user = {
        uuid: 'sigv4-user-unscoped',
        login: 'sigv4user',
        accesskeys: {
            'AKIASIGV4UNSCOPED01': {
                secret: 'secretForSigv4UnscopedTest1234567890',
                scope: null
            }
        }
    };

    setupAndVerify({
        user: user,
        accessKeyId: 'AKIASIGV4UNSCOPED01',
        secret: 'secretForSigv4UnscopedTest1234567890',
        method: 'GET',
        path: '/test-bucket/object.txt'
    }, t, function (err, result) {
        t.ok(!err, 'should not error');
        t.ok(result, 'should return result');
        t.equal(result.bucketScope, null,
            'unscoped key should have null bucketScope');
        t.done();
    });
});

test('sigv4 - scoped permanent key returns bucketScope', function (t) {
    var scopedSecret = 'scopedSigv4SecretForTesting123456789ab';

    var user = {
        uuid: 'sigv4-user-scoped',
        login: 'sigv4scoped',
        accesskeys: {
            'AKIASIGV4SCOPED001': {
                secret: scopedSecret,
                scope: SCOPE_JSON
            }
        }
    };

    // For scoped permanent keys, the reverse lookup is JSON
    var lookupData = JSON.stringify({
        type: 'accesskey',
        accessKeyId: 'AKIASIGV4SCOPED001',
        userUuid: 'sigv4-user-scoped',
        credentialType: 'permanent',
        scope: SCOPE_JSON
    });

    setupAndVerify({
        user: user,
        accessKeyId: 'AKIASIGV4SCOPED001',
        secret: scopedSecret,
        lookupVal: lookupData,
        method: 'GET',
        path: '/app-data/file.txt'
    }, t, function (err, result) {
        t.ok(!err, 'should not error: ' + (err ? err.message : ''));
        t.ok(result, 'should return result');
        t.equal(result.bucketScope, SCOPE_JSON,
            'scoped key should return bucketScope');
        t.equal(result.accessKeyId, 'AKIASIGV4SCOPED001',
            'should have correct access key ID');
        t.done();
    });
});

test('sigv4 - corrupt reverse lookup JSON returns error',
    function (t) {
    var secret = 'corruptLookupTestSecret12345678901234';
    var user = {
        uuid: 'sigv4-user-corrupt',
        login: 'corrupt',
        accesskeys: {
            'AKIACORRUPTLOOKUP01': secret
        }
    };

    // Store corrupt JSON in the reverse lookup
    setupAndVerify({
        user: user,
        accessKeyId: 'AKIACORRUPTLOOKUP01',
        secret: secret,
        lookupVal: '{corrupt json!!!',
        method: 'GET',
        path: '/bucket/key'
    }, t, function (err, result) {
        t.ok(err, 'should error on corrupt reverse lookup');
        t.done();
    });
});

/*
 * PART 3: STS helpers — scope in builder functions
 */

var buildLdapObj = sts.helpers.buildLdapObjectForSessionToken;
var buildRedisData = sts.helpers.buildAccessKeyDataForRedis;

test('buildLdapObjectForSessionToken - includes scope when present',
    function (t) {
    var obj = buildLdapObj({
        accessKeyId: 'MSTSTEST00000000001',
        secretKey: 'tempSecret123',
        sessionToken: 'jwt-token-here',
        expiration: new Date('2026-04-18T14:00:00Z'),
        principalUuid: 'user-uuid-123',
        bucketScope: SCOPE_JSON
    });

    t.equal(obj.accesskeyid, 'MSTSTEST00000000001');
    t.equal(obj.credentialtype, 'temporary');
    t.equal(obj.accesskeyscope, SCOPE_JSON,
        'should include accesskeyscope when scope is present');
    t.done();
});

test('buildLdapObjectForSessionToken - omits scope when null',
    function (t) {
    var obj = buildLdapObj({
        accessKeyId: 'MSTSTEST00000000002',
        secretKey: 'tempSecret456',
        sessionToken: 'jwt-token-here',
        expiration: new Date('2026-04-18T14:00:00Z'),
        principalUuid: 'user-uuid-123',
        bucketScope: null
    });

    t.equal(obj.accesskeyscope, undefined,
        'should NOT include accesskeyscope when scope is null');
    t.done();
});

test('buildLdapObjectForSessionToken - omits scope when absent',
    function (t) {
    var obj = buildLdapObj({
        accessKeyId: 'MSTSTEST00000000003',
        secretKey: 'tempSecret789',
        sessionToken: 'jwt-token-here',
        expiration: new Date('2026-04-18T14:00:00Z'),
        principalUuid: 'user-uuid-123'
    });

    t.equal(obj.accesskeyscope, undefined,
        'should NOT include accesskeyscope when not provided');
    t.done();
});

test('buildAccessKeyDataForRedis - includes scope when present',
    function (t) {
    var data = buildRedisData({
        accessKeyId: 'MSTSTEST00000000004',
        secretAccessKey: 'tempSecret111',
        sessionToken: 'jwt-token-here',
        userUuid: 'user-uuid-456',
        expiration: new Date('2026-04-18T14:00:00Z'),
        principalUuid: 'user-uuid-456',
        bucketScope: SCOPE_JSON
    });

    t.equal(data.accessKeyId, 'MSTSTEST00000000004');
    t.equal(data.credentialType, 'temporary');
    t.equal(data.bucketScope, SCOPE_JSON,
        'should include bucketScope when present');
    t.done();
});

test('buildAccessKeyDataForRedis - omits scope when null',
    function (t) {
    var data = buildRedisData({
        accessKeyId: 'MSTSTEST00000000005',
        secretAccessKey: 'tempSecret222',
        sessionToken: 'jwt-token-here',
        userUuid: 'user-uuid-456',
        expiration: new Date('2026-04-18T14:00:00Z'),
        principalUuid: 'user-uuid-456',
        bucketScope: null
    });

    t.equal(data.bucketScope, undefined,
        'should NOT include bucketScope when null');
    t.done();
});

test('buildAccessKeyDataForRedis - omits scope when absent',
    function (t) {
    var data = buildRedisData({
        accessKeyId: 'MSTSTEST00000000006',
        secretAccessKey: 'tempSecret333',
        sessionToken: 'jwt-token-here',
        userUuid: 'user-uuid-456',
        expiration: new Date('2026-04-18T14:00:00Z'),
        principalUuid: 'user-uuid-456'
    });

    t.equal(data.bucketScope, undefined,
        'should NOT include bucketScope when not provided');
    t.done();
});

/*
 * PART 4: SigV4 — temporary credentials with scope
 */

test('sigv4 - temp credential with bucketScope returns it',
    function (t) {
    /*
     * Temporary credentials use JWT session tokens for auth.
     * We can't easily mock the full JWT flow here, but we CAN
     * verify that the Redis credential data structure includes
     * bucketScope when present, by checking the builder output
     * that gets stored in Redis.
     */
    var data = buildRedisData({
        accessKeyId: 'MSARTEMP0000000001',
        secretAccessKey: 'tempScopedSecret999',
        sessionToken: 'jwt-for-scoped-temp',
        userUuid: 'temp-user-uuid',
        expiration: new Date('2026-04-18T14:00:00Z'),
        principalUuid: 'temp-user-uuid',
        bucketScope: SCOPE_JSON
    });

    t.equal(data.bucketScope, SCOPE_JSON,
        'temp credential data should carry bucketScope');
    t.equal(data.credentialType, 'temporary',
        'should be temporary credential');
    t.equal(data.accessKeyId, 'MSARTEMP0000000001',
        'access key ID should be correct');
    t.done();
});

test('sigv4 - temp credential without scope has no bucketScope',
    function (t) {
    var data = buildRedisData({
        accessKeyId: 'MSARTEMP0000000002',
        secretAccessKey: 'tempUnscopedSecret888',
        sessionToken: 'jwt-for-unscoped-temp',
        userUuid: 'temp-user-uuid',
        expiration: new Date('2026-04-18T14:00:00Z'),
        principalUuid: 'temp-user-uuid'
    });

    t.equal(data.bucketScope, undefined,
        'temp credential without scope should have no bucketScope');
    t.done();
});

/*
 * PART 5: UFDS fallback path — bucketScope in handleTemporaryCredential
 *
 * When a temporary credential is not found in Redis (e.g. after restart),
 * sigv4 falls back to UFDS lookup via handleTemporaryCredential.  These
 * tests verify that the result includes bucketScope from the UFDS record.
 */

var handleTempCred = sigv4._handleTemporaryCredential;

/*
 * Helper: build mocks and call handleTemporaryCredential.
 *
 * opts.accessKeyId     — temp key ID
 * opts.secret          — temp secret key
 * opts.sessionToken    — session token string
 * opts.principalUuid   — user UUID stored on the UFDS credential
 * opts.accesskeyscope  — scope JSON string (or omit for unscoped)
 * opts.assumedrole     — optional role ARN
 */
function runUfdsFallback(opts, t, callback) {
    var log = bunyan.createLogger({
        name: 'ufds-fallback-test',
        level: 'fatal'
    });

    var user = {
        uuid: opts.principalUuid,
        login: 'ufds-fallback-user',
        accesskeys: {}
    };

    /* Store principal user in Redis (required by the function) */
    REDIS.set('/uuid/' + opts.principalUuid, JSON.stringify(user),
        function (redisErr) {
        if (redisErr) {
            return (callback(redisErr));
        }

        /* Generate valid SigV4 headers with the temp secret */
        var method = 'GET';
        var path = '/test-bucket/obj.txt';
        var headers = helper.createHeaders({
            method: method,
            path: path,
            accessKey: opts.accessKeyId,
            secret: opts.secret
        });

        /* Parse auth header to build authInfo */
        var authInfo = sigv4.parseAuthHeader(headers.authorization);

        /* Build mock UFDS that returns the credential record */
        var credRecord = {
            accesskeyid: opts.accessKeyId,
            accesskeysecret: opts.secret,
            sessiontoken: opts.sessionToken,
            principaluuid: opts.principalUuid,
            credentialtype: 'temporary',
            expiration: new Date(Date.now() + 3600000).toISOString()
        };
        if (opts.assumedrole) {
            credRecord.assumedrole = opts.assumedrole;
        }
        if (opts.accesskeyscope) {
            credRecord.accesskeyscope = opts.accesskeyscope;
        }
        var mockUfds = {
            search: function (_base, _searchOpts, cb) {
                cb(null, [credRecord]);
            }
        };

        /* Build req object expected by handleTemporaryCredential */
        var req = {
            method: method,
            url: path,
            headers: headers,
            query: {},
            redis: REDIS
        };

        return (handleTempCred(authInfo, opts.sessionToken,
            req, log, mockUfds, callback));
    });
}

test('UFDS fallback - scoped temp credential returns bucketScope',
    function (t) {
    runUfdsFallback({
        accessKeyId: 'UFDSSCOPED000000001',
        secret: 'ufdsSecretScoped1234567890abcdef012345',
        sessionToken: 'session-token-scoped-ufds',
        principalUuid: 'ufds-scoped-user-uuid-001',
        accesskeyscope: SCOPE_JSON,
        assumedrole: 'arn:aws:iam::acct:role/TestRole'
    }, t, function (err, result) {
        t.ifError(err, 'should not error');
        t.ok(result, 'should return result');
        t.equal(result.bucketScope, SCOPE_JSON,
            'UFDS fallback should return bucketScope from accesskeyscope');
        t.equal(result.isTemporaryCredential, true,
            'should be marked as temporary credential');
        t.equal(result.assumedRole,
            'arn:aws:iam::acct:role/TestRole',
            'should include assumedRole');
        t.done();
    });
});

test('UFDS fallback - unscoped temp credential returns null bucketScope',
    function (t) {
    runUfdsFallback({
        accessKeyId: 'UFDSUNSCOPED0000001',
        secret: 'ufdsSecretUnscoped234567890abcdef01234',
        sessionToken: 'session-token-unscoped-ufds',
        principalUuid: 'ufds-unscoped-user-uuid-01'
    }, t, function (err, result) {
        t.ifError(err, 'should not error');
        t.ok(result, 'should return result');
        t.equal(result.bucketScope, null,
            'UFDS fallback without scope should return null bucketScope');
        t.done();
    });
});

/*
 * PART 6: Replicator → sigv4 round-trip
 *
 * Verifies that scope JSON written by the replicator
 * transform.add() survives unchanged when read back by
 * sigv4.verifySigV4(). Guards against accidental format
 * divergence between transform.add() and the sigv4 reader.
 */

var RT_UUID_REPL = 'rt-replicator-test-uuid-001';
var RT_KEY_REPL = 'AKIARTREPL000000001';
var RT_SECRET_REPL = 'rtReplSecretForTesting1234567890abc';

var RT_SCOPE_JSON = JSON.stringify({
    version: 1,
    permissions: [
        { bucket: 'cross-path-test', level: 'readwrite' }
    ]
});

test('cross-path: replicator transform.add() scope survives sigv4 round-trip',
    function (t) {
    var log = bunyan.createLogger({
        name: 'rt-repl-test',
        level: 'fatal'
    });

    var entry = {
        changes: {
            accesskeyid: [RT_KEY_REPL],
            accesskeysecret: [RT_SECRET_REPL],
            accesskeyscope: [RT_SCOPE_JSON],
            status: ['Active'],
            objectclass: ['accesskey'],
            _owner: [RT_UUID_REPL],
            _parent: ['uuid=' + RT_UUID_REPL +
                ', ou=users, o=smartdc']
        }
    };

    /* Write via replicator transform */
    transform.add({
        changes: entry.changes,
        entry: entry,
        log: log,
        redis: REDIS
    }, function (addErr, batch) {
        t.ok(!addErr, 'transform.add should not error');
        batch.exec(function (execErr) {
            t.ok(!execErr, 'exec should not error');

            /* Sign a request with the same key */
            var headers = helper.createHeaders({
                method: 'GET',
                path: '/cross-path-test/obj.txt',
                accessKey: RT_KEY_REPL,
                secret: RT_SECRET_REPL
            });
            headers['x-amz-content-sha256'] =
                crypto.createHash('sha256')
                    .update('', 'utf8').digest('hex');

            sigv4.verifySigV4({
                req: {
                    method: 'GET',
                    url: '/cross-path-test/obj.txt',
                    headers: headers,
                    query: {}
                },
                log: log,
                redis: REDIS
            }, function (verErr, result) {
                t.ok(!verErr,
                    'sigv4 verify should not error: ' +
                    (verErr ? verErr.message : ''));
                t.ok(result, 'should return result');
                t.equal(result.bucketScope, RT_SCOPE_JSON,
                    'scope must survive replicator → ' +
                    'sigv4 round-trip unchanged');
                t.done();
            });
        });
    });
});

/*
 * PART 7: UFDS read-through fallback for permanent keys
 *
 * Verifies that when a permanent key is absent from Redis,
 * verifySigV4 falls through to the UFDS client and returns
 * the correct bucketScope.  Guards against the ufdsPool→ufds
 * property name mismatch that previously left this path dead.
 */

var UFDS_FB_UUID = 'ufds-fallback-perm-uuid-001';
var UFDS_FB_KEY = 'AKIAUFDSFALLBACK0001';
var UFDS_FB_SECRET = 'ufdsFallbackSecretForTest1234567890a';

test('UFDS read-through: scoped permanent key found via UFDS when not in Redis',
    function (t) {
    var log = bunyan.createLogger({
        name: 'ufds-fb-perm-test',
        level: 'fatal'
    });

    /*
     * Do NOT write the key to Redis. This simulates a key
     * that exists in UFDS but has not yet replicated.
     * Only write the user record so the result can resolve.
     */
    var userPayload = {
        uuid: UFDS_FB_UUID,
        login: 'ufds-fb-user',
        accesskeys: {}
    };

    REDIS.set('/uuid/' + UFDS_FB_UUID,
        JSON.stringify(userPayload), function (setErr) {
        t.ok(!setErr, 'redis set user should not error');

        /* Mock UFDS proxy with .search() */
        var mockUfds = {
            search: function (_base, _opts, cb) {
                cb(null, [
                    {
                        accesskeyid: UFDS_FB_KEY,
                        accesskeysecret: UFDS_FB_SECRET,
                        status: 'Active',
                        accesskeyscope: RT_SCOPE_JSON,
                        _owner: UFDS_FB_UUID
                    }
                ]);
            }
        };

        var headers = helper.createHeaders({
            method: 'GET',
            path: '/cross-path-test/obj.txt',
            accessKey: UFDS_FB_KEY,
            secret: UFDS_FB_SECRET
        });
        headers['x-amz-content-sha256'] =
            crypto.createHash('sha256')
                .update('', 'utf8').digest('hex');

        sigv4.verifySigV4({
            req: {
                method: 'GET',
                url: '/cross-path-test/obj.txt',
                headers: headers,
                query: {}
            },
            log: log,
            redis: REDIS,
            ufds: mockUfds
        }, function (verErr, result) {
            t.ok(!verErr,
                'sigv4 verify should succeed via UFDS: ' +
                (verErr ? verErr.message : ''));
            t.ok(result, 'should return result');
            t.equal(result.bucketScope, RT_SCOPE_JSON,
                'scope must survive UFDS read-through');
            t.equal(result.accessKeyId, UFDS_FB_KEY,
                'should have correct access key ID');
            t.done();
        });
    });
});

/*
 * PART 8: Shared Redis entry builder
 *
 * Verifies that the builder functions in
 * redis-accesskey-format.js produce the exact structure
 * expected by sigv4.js and redislib.js consumers.
 */

var akFormat = require('../lib/redis-accesskey-format');
var REDIS_TOMBSTONE;

test('buildPermanentKeyEntry - scoped key', function (t) {
    var entry = akFormat.buildPermanentKeyEntry(
        'mySecret', SCOPE_JSON);
    t.equal(entry.secret, 'mySecret',
        'secret should be preserved');
    t.equal(entry.scope, SCOPE_JSON,
        'scope should be preserved');
    t.equal(Object.keys(entry).length, 3,
        'should have exactly three keys (secret, scope, version)');
    t.done();
});

test('buildPermanentKeyEntry - unscoped key', function (t) {
    var entry = akFormat.buildPermanentKeyEntry(
        'mySecret', null);
    t.equal(entry.scope, null,
        'scope should be null for unscoped key');
    t.done();
});

test('buildPermanentKeyLookup - scoped key', function (t) {
    var lookup = akFormat.buildPermanentKeyLookup(
        'AKIATEST', 'user-uuid', SCOPE_JSON);
    t.equal(lookup.type, 'accesskey',
        'type should be accesskey');
    t.equal(lookup.accessKeyId, 'AKIATEST',
        'accessKeyId should be preserved');
    t.equal(lookup.userUuid, 'user-uuid',
        'userUuid should be preserved');
    t.equal(lookup.credentialType, 'permanent',
        'credentialType should be permanent');
    t.equal(lookup.scope, SCOPE_JSON,
        'scope should be preserved');
    t.done();
});

test('buildPermanentKeyLookup - unscoped key', function (t) {
    var lookup = akFormat.buildPermanentKeyLookup(
        'AKIATEST', 'user-uuid', null);
    t.equal(lookup.scope, null,
        'scope should be null for unscoped key');
    t.equal(lookup.credentialType, 'permanent',
        'credentialType should be permanent');
    t.done();
});


/*
 * PART 9: Extracted sigv4 functions — buildPermanentResult,
 *         handlePermanentCredentialRedis
 *
 * Verifies the extracted functions produce the same results
 * as the monolithic verifySigV4 did before decomposition.
 */

test('buildPermanentResult - with scope', function (t) {
    var result = sigv4._buildPermanentResult(
        { uuid: USER_UUID },
        SCOPED_KEY_ID,
        new Buffer('signingKey'),
        SCOPE_JSON);
    t.equal(result.user.uuid, USER_UUID,
        'user.uuid should match');
    t.equal(result.accessKeyId, SCOPED_KEY_ID,
        'accessKeyId should match');
    t.ok(Buffer.isBuffer(result.signingKey),
        'signingKey should be a buffer');
    t.equal(result.bucketScope, SCOPE_JSON,
        'bucketScope should be scope JSON');
    t.done();
});

test('buildPermanentResult - null scope defaults to null', function (t) {
    var result = sigv4._buildPermanentResult(
        { uuid: USER_UUID },
        UNSCOPED_KEY_ID,
        new Buffer('signingKey'),
        null);
    t.strictEqual(result.bucketScope, null,
        'bucketScope should be null');
    t.done();
});

test('buildPermanentResult - undefined scope defaults to null', function (t) {
    var result = sigv4._buildPermanentResult(
        { uuid: USER_UUID },
        UNSCOPED_KEY_ID,
        new Buffer('signingKey'),
        undefined);
    t.strictEqual(result.bucketScope, null,
        'bucketScope should be null for undefined');
    t.done();
});

test('setup - fresh redis for PART 9', function (t) {
    REDIS = redis.createClient('part9');
    t.done();
});

test('exported functions exist', function (t) {
    t.ok(typeof (sigv4._handlePermanentCredentialRedis) === 'function',
        'handlePermanentCredentialRedis should be exported');
    t.ok(typeof (sigv4._handleTemporaryCredentialRedis) === 'function',
        'handleTemporaryCredentialRedis should be exported');
    t.ok(typeof (sigv4._buildPermanentResult) === 'function',
        'buildPermanentResult should be exported');
    t.ok(typeof (sigv4._buildTemporaryResult) === 'function',
        'buildTemporaryResult should be exported');
    t.done();
});

test('buildTemporaryResult - with scope and role', function (t) {
    var result = sigv4._buildTemporaryResult({
        accessKeyId: 'MSTS00000000001',
        secretAccessKey: 'tempSecret',
        userUuid: USER_UUID,
        assumedRole: { arn: 'arn:aws:iam::acct:role/Test' },
        principalUuid: 'principal-uuid',
        expiration: '2026-04-18T13:00:00.000Z',
        signingKey: new Buffer('signingKey'),
        bucketScope: SCOPE_JSON
    });
    t.equal(result.accessKeyId, 'MSTS00000000001',
        'accessKeyId should match');
    t.equal(result.userUuid, USER_UUID,
        'userUuid should match');
    t.equal(result.user.uuid, USER_UUID,
        'user.uuid should match');
    t.equal(result.account.uuid, USER_UUID,
        'account.uuid should match');
    t.equal(result.isTemporaryCredential, true,
        'isTemporaryCredential should be true');
    t.equal(result.credentialType, 'temporary',
        'credentialType should be temporary');
    t.equal(result.assumedRole.arn,
        'arn:aws:iam::acct:role/Test',
        'assumedRole should be preserved');
    t.equal(result.principalUuid, 'principal-uuid',
        'principalUuid should match');
    t.equal(result.bucketScope, SCOPE_JSON,
        'bucketScope should be scope JSON');
    t.done();
});

test('buildTemporaryResult - null scope defaults to null',
    function (t) {
    var result = sigv4._buildTemporaryResult({
        accessKeyId: 'MSTS00000000002',
        userUuid: USER_UUID,
        signingKey: new Buffer('signingKey')
    });
    t.strictEqual(result.bucketScope, null,
        'bucketScope should default to null');
    t.strictEqual(result.assumedRole, null,
        'assumedRole should default to null');
    t.strictEqual(result.expiration, null,
        'expiration should default to null');
    t.equal(result.principalUuid, USER_UUID,
        'principalUuid should default to userUuid');
    t.done();
});

/*
 * Helper: set up user in Redis and call
 * handlePermanentCredentialRedis with a properly signed request.
 */
function setupAndVerifyExtracted(opts, t, callback) {
    var user = opts.user;
    var accessKeyId = opts.accessKeyId;
    var secret = opts.secret;
    var lookupVal = opts.lookupVal;

    var log = bunyan.createLogger({
        name: 'part9-test',
        level: 'fatal'
    });

    REDIS.set('/uuid/' + user.uuid, JSON.stringify(user),
        function (err1) {
        if (err1) {
            return (callback(err1));
        }
        return (REDIS.set('/accesskey/' + accessKeyId, lookupVal,
            function (err2) {
            if (err2) {
                return (callback(err2));
            }

            var headers = helper.createHeaders({
                method: opts.method || 'GET',
                path: opts.path || '/bucket/key',
                accessKey: accessKeyId,
                secret: secret
            });

            var payloadHash = crypto.createHash('sha256')
                .update('', 'utf8').digest('hex');
            headers['x-amz-content-sha256'] = payloadHash;

            var req = {
                method: opts.method || 'GET',
                url: opts.path || '/bucket/key',
                headers: headers,
                query: {}
            };

            var authInfo = sigv4.parseAuthHeader(
                headers.authorization);

            return (sigv4._handlePermanentCredentialRedis(
                authInfo, req, log, REDIS, null, callback));
        }));
    });
}

test('handlePermanentCredentialRedis - scoped key returns bucketScope',
    function (t) {
    var P9_KEY_ID = 'AKIAP9SCOPED0000001';
    var P9_SECRET = 'p9scopedSecretKeyForTesting123456789abcde';
    var P9_UUID = 'p9-scoped-uuid-0000-0000-000000000001';

    var user = {
        uuid: P9_UUID,
        login: 'p9scopeduser',
        accesskeys: {}
    };
    user.accesskeys[P9_KEY_ID] =
        akFormat.buildPermanentKeyEntry(P9_SECRET, SCOPE_JSON);

    var lookupData = akFormat.buildPermanentKeyLookup(
        P9_KEY_ID, P9_UUID, SCOPE_JSON);

    setupAndVerifyExtracted({
        user: user,
        accessKeyId: P9_KEY_ID,
        secret: P9_SECRET,
        lookupVal: JSON.stringify(lookupData),
        method: 'GET',
        path: '/bucket/key'
    }, t, function (err, result) {
        t.ok(!err, 'should not error: ' + (err ? err.message : ''));
        t.ok(result, 'should return result');
        t.equal(result.bucketScope, SCOPE_JSON,
            'scoped key should return scope JSON');
        t.equal(result.accessKeyId, P9_KEY_ID,
            'accessKeyId should match');
        t.ok(result.signingKey,
            'signingKey should be present');
        t.equal(result.user.uuid, P9_UUID,
            'user.uuid should match');
        t.done();
    });
});

test('handlePermanentCredentialRedis - unscoped key returns null scope',
    function (t) {
    var P9U_KEY_ID = 'AKIAP9UNSCOPED00001';
    var P9U_SECRET = 'p9unscopedSecretKeyForTesting1234567890ab';
    var P9U_UUID = 'p9-unscoped-uuid-000-0000-000000000001';

    var user = {
        uuid: P9U_UUID,
        login: 'p9unscopeduser',
        accesskeys: {}
    };
    user.accesskeys[P9U_KEY_ID] =
        akFormat.buildPermanentKeyEntry(P9U_SECRET, null);

    var lookupData = akFormat.buildPermanentKeyLookup(
        P9U_KEY_ID, P9U_UUID, null);

    setupAndVerifyExtracted({
        user: user,
        accessKeyId: P9U_KEY_ID,
        secret: P9U_SECRET,
        lookupVal: JSON.stringify(lookupData),
        method: 'GET',
        path: '/bucket/key'
    }, t, function (err, result) {
        t.ok(!err, 'should not error: ' + (err ? err.message : ''));
        t.ok(result, 'should return result');
        t.strictEqual(result.bucketScope, null,
            'unscoped key should return null bucketScope');
        t.done();
    });
});

test('handlePermanentCredentialRedis - key not in Redis returns error',
    function (t) {
    var log = bunyan.createLogger({name: 'test', level: 'fatal'});
    var authInfo = {
        accessKeyId: 'AKIANONEXISTENT00001',
        dateStamp: '20260418',
        region: 'us-east-1',
        service: 's3',
        signedHeaders: 'host;x-amz-date',
        signature: 'dummy'
    };
    var mockReq = {
        headers: {
            host: 'localhost',
            'x-amz-date': '20260418T120000Z'
        },
        query: {}
    };

    sigv4._handlePermanentCredentialRedis(
        authInfo, mockReq, log, REDIS, null,
        function (err, result) {
            t.ok(err, 'should return error for missing key');
            t.ok(!result, 'should not return result');
            t.ok(err.message.indexOf('Invalid access key') >= 0 ||
                err.restCode === 'InvalidSignature',
                'error should indicate invalid key');
            t.done();
        });
});

test('handlePermanentCredentialRedis - legacy string format',
    function (t) {
    var LEGACY_KEY_ID = 'AKIALEGACY0000000001';
    var LEGACY_SECRET = 'legacySecretKeyForTesting1234567890abcde';
    var LEGACY_UUID = '660e8400-e29b-41d4-a716-446655440099';

    var user = {
        uuid: LEGACY_UUID,
        login: 'legacyuser',
        accesskeys: {}
    };
    // Legacy format: bare string (no object wrapper)
    user.accesskeys[LEGACY_KEY_ID] = LEGACY_SECRET;

    setupAndVerifyExtracted({
        user: user,
        accessKeyId: LEGACY_KEY_ID,
        secret: LEGACY_SECRET,
        lookupVal: LEGACY_UUID,  // Legacy: plain UUID string
        method: 'GET',
        path: '/bucket/key'
    }, t, function (err, result) {
        t.ok(!err, 'should not error: ' + (err ? err.message : ''));
        t.ok(result, 'should return result');
        t.strictEqual(result.bucketScope, null,
            'legacy key should have null bucketScope');
        t.equal(result.accessKeyId, LEGACY_KEY_ID,
            'accessKeyId should match');
        t.done();
    });
});


/*
 * PART 10: Revocation tombstones — durable scope-revoke
 *
 * Verifies that a revocation tombstone in Redis prevents
 * the replicator from re-adding or modifying a revoked key.
 */

test('setup - fresh redis for PART 10', function (t) {
    REDIS_TOMBSTONE = redis.createClient('part10');
    t.done();
});

test('revokedKeyPath produces correct path', function (t) {
    var path = akFormat.revokedKeyPath('AKIATEST123');
    t.equal(path, '/revoked/AKIATEST123',
        'should produce /revoked/ prefix');
    t.done();
});

test('buildRevocationTombstone includes revokedAt and userUuid',
    function (t) {
    var before = Date.now();
    var tombstone = akFormat.buildRevocationTombstone('user-uuid');
    var after = Date.now();
    t.equal(tombstone.userUuid, 'user-uuid',
        'userUuid should be preserved');
    t.ok(tombstone.revokedAt >= before &&
        tombstone.revokedAt <= after,
        'revokedAt should be current time');
    t.done();
});

test('REVOKE_TTL_SECONDS is 24 hours', function (t) {
    t.equal(akFormat.REVOKE_TTL_SECONDS, 86400,
        'TTL should be 86400 seconds (24 hours)');
    t.done();
});

test('tombstone prevents replicator add()', function (t) {
    var REVOKED_KEY_ID = 'AKIAREVOKED00000001';
    var REVOKED_SECRET = 'revokedSecretKeyForTesting12345678abcdef';
    var REVOKED_UUID = '770e8400-e29b-41d4-a716-446655440099';

    var log = bunyan.createLogger({name: 'test', level: 'fatal'});

    // Write tombstone
    var revokedKey = akFormat.revokedKeyPath(REVOKED_KEY_ID);
    REDIS_TOMBSTONE.set(revokedKey,
        JSON.stringify(akFormat.buildRevocationTombstone(REVOKED_UUID)),
        function () {

        // Try to add the key via replicator
        var entry = {
            dn: 'changenumber=200, cn=changelog',
            controls: [],
            targetdn: 'accesskeyid=' + REVOKED_KEY_ID +
                ', uuid=' + REVOKED_UUID +
                ', ou=users, o=smartdc',
            changetype: 'add',
            objectclass: 'changeLogEntry',
            changetime: '2026-04-18T12:00:00.000Z',
            changes: {
                accesskeyid: [REVOKED_KEY_ID],
                accesskeysecret: [REVOKED_SECRET],
                created: ['1761762138761'],
                status: ['Active'],
                updated: ['1761762138761'],
                objectclass: ['accesskey'],
                _owner: [REVOKED_UUID],
                _parent: ['uuid=' + REVOKED_UUID +
                    ', ou=users, o=smartdc']
            },
            changenumber: '200'
        };

        transform.add({
            changes: entry.changes,
            entry: entry,
            log: log,
            redis: REDIS_TOMBSTONE
        }, function (err, batch) {
            t.ifError(err, 'add should not error');
            // Execute the batch and verify key was NOT added
            batch.exec(function () {
                var userKey = '/uuid/' + REVOKED_UUID;
                REDIS_TOMBSTONE.get(userKey, function (_, val) {
                    if (val) {
                        var payload = JSON.parse(val);
                        t.ok(!payload.accesskeys ||
                            !payload.accesskeys[REVOKED_KEY_ID],
                            'revoked key should NOT be in Redis');
                    } else {
                        t.ok(true,
                            'user record absent (key not added)');
                    }
                    t.done();
                });
            });
        });
    });
});

test('no tombstone allows replicator add()', function (t) {
    var NORMAL_KEY_ID = 'AKIANORMAL000000001';
    var NORMAL_SECRET = 'normalSecretKeyForTesting123456789abcdef';
    var NORMAL_UUID = '880e8400-e29b-41d4-a716-446655440099';

    var log = bunyan.createLogger({name: 'test', level: 'fatal'});

    var entry = {
        dn: 'changenumber=201, cn=changelog',
        controls: [],
        targetdn: 'accesskeyid=' + NORMAL_KEY_ID +
            ', uuid=' + NORMAL_UUID +
            ', ou=users, o=smartdc',
        changetype: 'add',
        objectclass: 'changeLogEntry',
        changetime: '2026-04-18T12:00:00.000Z',
        changes: {
            accesskeyid: [NORMAL_KEY_ID],
            accesskeysecret: [NORMAL_SECRET],
            created: ['1761762138761'],
            status: ['Active'],
            updated: ['1761762138761'],
            objectclass: ['accesskey'],
            _owner: [NORMAL_UUID],
            _parent: ['uuid=' + NORMAL_UUID +
                ', ou=users, o=smartdc']
        },
        changenumber: '201'
    };

    transform.add({
        changes: entry.changes,
        entry: entry,
        log: log,
        redis: REDIS_TOMBSTONE
    }, function (err, batch) {
        t.ifError(err, 'add should not error');
        batch.exec(function () {
            var userKey = '/uuid/' + NORMAL_UUID;
            REDIS_TOMBSTONE.get(userKey, function (_, val) {
                t.ok(val, 'user record should exist');
                var payload = JSON.parse(val);
                t.ok(payload.accesskeys &&
                    payload.accesskeys[NORMAL_KEY_ID],
                    'key should be in Redis');
                t.done();
            });
        });
    });
});

test('tombstone prevents replicator modify()', function (t) {
    var MOD_KEY_ID = 'AKIAMODREVOKED00001';
    var MOD_SECRET = 'modRevokedSecretKey1234567890abcdefgh';
    var MOD_UUID = '990e8400-e29b-41d4-a716-446655440099';

    var log = bunyan.createLogger({name: 'test', level: 'fatal'});

    // Pre-populate user record so modify has something to work with
    var userPayload = {
        uuid: MOD_UUID,
        accesskeys: {}
    };
    userPayload.accesskeys[MOD_KEY_ID] =
        akFormat.buildPermanentKeyEntry(MOD_SECRET, null);

    var batch1 = REDIS_TOMBSTONE.multi();
    batch1.set('/uuid/' + MOD_UUID, JSON.stringify(userPayload));
    batch1.set('/accesskey/' + MOD_KEY_ID,
        JSON.stringify(akFormat.buildPermanentKeyLookup(
            MOD_KEY_ID, MOD_UUID, null)));
    batch1.exec(function () {

        // Write tombstone
        var revokedKey = akFormat.revokedKeyPath(MOD_KEY_ID);
        REDIS_TOMBSTONE.set(revokedKey,
            JSON.stringify(akFormat.buildRevocationTombstone(MOD_UUID)),
            function () {

            // Try to modify the key via replicator
            var modEntry = {
                accesskeyid: [MOD_KEY_ID],
                accesskeysecret: [MOD_SECRET],
                _owner: [MOD_UUID],
                credentialtype: ['permanent'],
                objectclass: ['accesskey'],
                accesskeyscope: [SCOPE_JSON]
            };

            var changes = [
                {
                    operation: 'add',
                    modification: {
                        type: 'accesskeyscope',
                        vals: [SCOPE_JSON]
                    }
                }
            ];

            transform.modify({
                changes: changes,
                modEntry: modEntry,
                entry: { changenumber: '300' },
                log: log,
                redis: REDIS_TOMBSTONE
            }, function (err, modBatch) {
                t.ifError(err, 'modify should not error');
                modBatch.exec(function () {
                    // Key should still have null scope (modify was skipped)
                    var userKey = '/uuid/' + MOD_UUID;
                    REDIS_TOMBSTONE.get(userKey, function (_, val) {
                        var payload = JSON.parse(val);
                        var keyData = payload.accesskeys[MOD_KEY_ID];
                        t.equal(keyData.scope, null,
                            'scope should NOT have been updated ' +
                            '(tombstone blocked modify)');
                        t.done();
                    });
                });
            });
        });
    });
});


/*
 * PART 11: Permanent-key schema — version field defaults
 *
 * Verifies that the version field is present in both the user
 * entry and the reverse-lookup row and that it defaults to 0
 * when not supplied. The replicator records each write's
 * UFDS changenumber here; the field is informational since
 * CHG-138 (no consumer compares it). These tests guard the
 * format from regressing.
 */

test('buildPermanentKeyEntry includes version field', function (t) {
    var entry = akFormat.buildPermanentKeyEntry(
        'mySecret', SCOPE_JSON, 42);
    t.equal(entry.secret, 'mySecret',
        'secret should be preserved');
    t.equal(entry.scope, SCOPE_JSON,
        'scope should be preserved');
    t.equal(entry.version, 42,
        'version should be 42');
    t.done();
});

test('buildPermanentKeyEntry defaults version to 0', function (t) {
    var entry = akFormat.buildPermanentKeyEntry(
        'mySecret', null);
    t.equal(entry.version, 0,
        'version should default to 0');
    t.done();
});

test('buildPermanentKeyLookup includes version field', function (t) {
    var lookup = akFormat.buildPermanentKeyLookup(
        'AKIATEST', 'user-uuid', SCOPE_JSON, 99);
    t.equal(lookup.version, 99,
        'version should be 99');
    t.done();
});

test('buildPermanentKeyLookup defaults version to 0', function (t) {
    var lookup = akFormat.buildPermanentKeyLookup(
        'AKIATEST', 'user-uuid', null);
    t.equal(lookup.version, 0,
        'version should default to 0');
    t.done();
});


/*
 * Regression test for the vals[i] -> vals[0] fix in
 * modify().  The original code indexed into vals with
 * the outer loop variable (i), which read the wrong
 * element when multiple changes were present.  The fix
 * uses vals[0] since each change entry has exactly one
 * value.
 */
test('modify - vals[0] regression: status extracted ' +
    'correctly with multiple changes',
    function (t) {
    var log = this.log;

    /* Pre-populate a key in Redis */
    var addEntry = {
        dn: 'changenumber=200, cn=changelog',
        controls: [],
        targetdn: 'accesskeyid=' + SCOPED_KEY_ID +
            ', uuid=' + USER_UUID +
            ', ou=users, o=smartdc',
        changetype: 'add',
        objectclass: 'changeLogEntry',
        changetime: '2026-04-18T12:00:00.000Z',
        changes: {
            accesskeyid: [SCOPED_KEY_ID],
            accesskeysecret: [SCOPED_SECRET],
            accesskeyscope: [SCOPE_JSON],
            created: ['1761762138761'],
            status: ['Active'],
            updated: ['1761762138761'],
            objectclass: ['accesskey'],
            _owner: [USER_UUID],
            _parent: ['uuid=' + USER_UUID +
                ', ou=users, o=smartdc']
        },
        changenumber: '200'
    };

    transform.add({
        changes: addEntry.changes,
        entry: addEntry,
        log: log,
        redis: REDIS
    }, function (addErr, addRes) {
        t.ok(!addErr, 'add should not error');
        addRes.exec(function () {
            /*
             * Send a modify with status as the SECOND
             * change (index 1).  With the old vals[i]
             * bug, the code would read vals[1] which
             * is undefined, and status would be null
             * instead of 'Inactive'.
             */
            var modEntry = {
                accesskeyid: [SCOPED_KEY_ID],
                accesskeysecret: [SCOPED_SECRET],
                accesskeyscope: [SCOPE_JSON],
                created: ['1761762138761'],
                objectclass: ['accesskey'],
                status: ['Inactive'],
                updated: ['1761762200000'],
                _owner: [USER_UUID],
                _parent: ['uuid=' + USER_UUID +
                    ', ou=users, o=smartdc']
            };

            var changes = [
                {
                    operation: 'replace',
                    modification: {
                        type: 'updated',
                        vals: ['1761762200000']
                    }
                },
                {
                    operation: 'replace',
                    modification: {
                        type: 'status',
                        vals: ['Inactive']
                    }
                }
            ];

            transform.modify({
                log: log,
                redis: REDIS,
                changes: changes,
                modEntry: modEntry,
                entry: { changenumber: '201' }
            }, function (modErr, modRes) {
                t.ok(!modErr, 'modify should not error');
                /*
                 * Status is Inactive, so the key should
                 * be DELETED from Redis (3 ops: set user,
                 * del reverse lookup, multi).
                 */
                t.ok(modRes.queue.length >= 2,
                    'should delete key from Redis');
                t.done();
            });
        });
    });
});
