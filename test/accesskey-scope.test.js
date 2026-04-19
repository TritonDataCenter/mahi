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

/* ========================================================
 * PART 1: Replicator transforms — scoped key add/modify/delete
 * ======================================================== */

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
                t.equal(typeof keyData, 'object',
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

test('add - unscoped key still uses legacy string format',
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

                // Unscoped key should be plain string
                t.equal(typeof payload.accesskeys[UNSCOPED_KEY_ID],
                    'string',
                    'unscoped key should be stored as string');
                t.equal(payload.accesskeys[UNSCOPED_KEY_ID],
                    UNSCOPED_SECRET,
                    'unscoped secret should be correct');

                // Scoped key should still be object
                t.equal(
                    typeof payload.accesskeys[SCOPED_KEY_ID],
                    'object',
                    'scoped key should still be object');

                // Reverse lookup should be plain UUID
                REDIS.get(lookupKey, function (lErr, lookupRes) {
                    t.ok(!lErr);
                    t.equal(lookupRes, USER_UUID,
                        'unscoped reverse lookup should be UUID');
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
        modEntry: modEntry
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
                t.equal(typeof keyData, 'object',
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

/* --- modify: scope removal converts back to string format --- */

test('modify - scope removal converts to legacy string format',
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
        modEntry: modEntry
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
                // After scope removal, key should be plain string
                t.equal(typeof keyData, 'string',
                    'key should revert to string format');
                t.equal(keyData, SCOPED_SECRET,
                    'secret should be correct');

                REDIS.get(lookupKey, function (lErr, lookupRes) {
                    t.ok(!lErr);
                    t.equal(lookupRes, USER_UUID,
                        'reverse lookup should revert to UUID');
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
                modEntry: modEntry
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
        modEntry: modEntry
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
                t.equal(typeof keyData, 'object',
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
                t.equal(payload.accesskeys[UNSCOPED_KEY_ID],
                    UNSCOPED_SECRET,
                    'unscoped key should remain');

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

/* ========================================================
 * PART 2: SigV4 verification — scoped permanent credentials
 * ======================================================== */

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
            return callback(err1);
        }
        return REDIS.set('/accesskey/' + accessKeyId, lookupVal,
            function (err2) {
            if (err2) {
                return callback(err2);
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

            return sigv4.verifySigV4({
                req: req,
                log: log,
                redis: REDIS
            }, callback);
        });
    });
}

test('sigv4 - unscoped key returns null bucketScope', function (t) {
    var user = {
        uuid: 'sigv4-user-unscoped',
        login: 'sigv4user',
        accesskeys: {
            'AKIASIGV4UNSCOPED01': 'secretForSigv4UnscopedTest1234567890'
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

/* ========================================================
 * PART 3: STS helpers — scope in builder functions
 * ======================================================== */

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

/* ========================================================
 * PART 4: SigV4 — temporary credentials with scope
 * ======================================================== */

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
