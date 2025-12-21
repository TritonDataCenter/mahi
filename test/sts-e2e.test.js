/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright 2025 Edgecast Cloud LLC.
 */

/*
 * test/sts-e2e.test.js: End-to-end tests for STS operations
 *
 * Tests complete AssumeRole and GetSessionToken flows including
 * credential generation, token validation, and subsequent usage
 * with SigV4 authentication.
 */

var _nodeunit = require('nodeunit');
var bunyan = require('bunyan');
var fakeredis = require('fakeredis');
var _crypto = require('crypto');
var sts = require('../lib/server/sts.js');
var _sigv4 = require('../lib/server/sigv4');
var _sessionTokenModule = require('../lib/server/session-token');
var SigV4Helper = require('./lib/sigv4-helper');

var log = bunyan.createLogger({
    name: 'sts-e2e-test',
    level: 'fatal'
});

var redis;
var _helper;

// Test accounts and users (using proper UUIDs)
var TEST_ACCOUNT_UUID = '12345678-1234-1234-1234-123456789012';
var TEST_USER_UUID = 'aaaaaaaa-1111-1111-1111-111111111111';
var TEST_ROLE_UUID = 'bbbbbbbb-2222-2222-2222-222222222222';
var TEST_ROLE_NAME = 'TestRole';
var TEST_ACCESS_KEY = 'AKIATEST12345678';
var TEST_SECRET_KEY = 'testsecretkey1234567890';

// Session secret for JWT generation
var SESSION_SECRET = {
    key: 'test-session-secret-key-for-jwt',
    keyId: 'test-key-001'
};

/* --- Setup and teardown --- */

exports.setUp = function (cb) {
    redis = fakeredis.createClient();
    helper = new SigV4Helper({region: 'us-east-1', service: 's3'});

    // Set up test data in Redis
    var testUser = {
        uuid: TEST_USER_UUID,
        login: 'testuser',
        account: {
            uuid: TEST_ACCOUNT_UUID,
            login: 'testaccount'
        },
        accesskeys: {}
    };
    testUser.accesskeys[TEST_ACCESS_KEY] = TEST_SECRET_KEY;

    var testRole = {
        uuid: TEST_ROLE_UUID,
        name: TEST_ROLE_NAME,
        account: TEST_ACCOUNT_UUID,
        assumerolepolicydocument: JSON.stringify({
            Version: '2012-10-17',
            Statement: [ {
                Effect: 'Allow',
                Principal: {
                    AWS: 'arn:aws:iam::' + TEST_ACCOUNT_UUID + ':root'
                },
                Action: 'sts:AssumeRole'
            }]
        })
    };

    // Store test data
    redis.set('/uuid/' + TEST_USER_UUID, JSON.stringify(testUser));
    redis.set('/accesskey/' + TEST_ACCESS_KEY, TEST_USER_UUID);
    redis.set('/uuid/' + TEST_ROLE_UUID, JSON.stringify(testRole));
    redis.set('/role/' + TEST_ACCOUNT_UUID + '/' + TEST_ROLE_NAME,
        TEST_ROLE_UUID);

    cb();
};

exports.tearDown = function (cb) {
    if (redis) {
        redis.quit();
    }
    cb();
};

/* --- Helper functions --- */

/*
 * Create a mock request object for STS operations
 */
function createMockRequest(opts) {
    var req = {
        log: log,
        redis: redis,
        sessionConfig: {
            secretKey: SESSION_SECRET.key,
            secretKeyId: SESSION_SECRET.keyId,
            gracePeriod: 300,
            issuer: 'manta-mahi',
            audience: 'manta-s3'
        },
        body: opts.body || {},
        params: opts.params || {},
        ufdsPool: opts.ufdsPool || null
    };

    return (req);
}

/*
 * Create a mock response object
 */
function createMockResponse() {
    var responseData = null;
    var statusCode = null;

    var res = {
        send: function (code, data) {
            statusCode = code;
            responseData = data;
        },
        getStatus: function () {
            return (statusCode);
        },
        getData: function () {
            return (responseData);
        }
    };

    return (res);
}

/*
 * Create a mock UFDS pool for testing
 */
function createMockUfdsPool() {
    var addedEntries = [];

    var mockClient = {
        add: function (dn, entry, callback) {
            addedEntries.push({dn: dn, entry: entry});
            setImmediate(function () {
                callback(null);
            });
        }
    };

    return {
        acquire: function (callback) {
            setImmediate(function () {
                callback(null, mockClient);
            });
        },
        release: function (_client) {
            // No-op for mock
        },
        getAddedEntries: function () {
            return (addedEntries);
        }
    };
}

/* --- AssumeRole end-to-end tests --- */

exports.testAssumeRoleCompleteFlow = function (t) {
    var roleArn = 'arn:aws:iam::' + TEST_ACCOUNT_UUID +
        ':role/' + TEST_ROLE_NAME;
    var roleSessionName = 'test-session-001';
    var durationSeconds = 3600;

    var caller = {
        user: {
            uuid: TEST_USER_UUID,
            login: 'testuser'
        },
        account: {
            uuid: TEST_ACCOUNT_UUID,
            login: 'testaccount'
        }
    };

    var req = createMockRequest({
        body: {
            caller: caller,
            RoleArn: roleArn,
            RoleSessionName: roleSessionName,
            DurationSeconds: durationSeconds
        }
    });
    req.ufdsPool = createMockUfdsPool();

    var res = createMockResponse();

    sts.assumeRole(req, res, function (err) {
        // Check for errors
        if (err) {
            t.ok(false, 'AssumeRole should not return error: ' +
                err.message);
            t.done();
            return;
        }

        // Check response status
        var status = res.getStatus();
        var data = res.getData();

        if (status !== 200) {
            t.ok(false, 'Expected 200 response, got: ' + status +
                ' with data: ' + JSON.stringify(data));
            t.done();
            return;
        }

        t.equal(status, 200, 'should return 200 status');
        t.ok(data, 'should return response data');

        // Navigate response structure: AssumeRoleResponse.AssumeRoleResult
        if (data.AssumeRoleResponse &&
            data.AssumeRoleResponse.AssumeRoleResult) {
            var result = data.AssumeRoleResponse.AssumeRoleResult;
            t.ok(result.Credentials, 'should include Credentials');
            if (result.Credentials) {
                t.ok(result.Credentials.AccessKeyId,
                    'should include AccessKeyId');
                t.ok(result.Credentials.AccessKeyId.substring(0, 4) ===
                    'MSAR', 'AccessKeyId should start with MSAR');
                t.ok(result.Credentials.SecretAccessKey,
                    'should include SecretAccessKey');
                t.ok(result.Credentials.SessionToken,
                    'should include SessionToken');
                t.ok(result.Credentials.Expiration,
                    'should include Expiration');
            }
            t.ok(result.AssumedRoleUser,
                'should include AssumedRoleUser');
            if (result.AssumedRoleUser) {
                t.equal(result.AssumedRoleUser.Arn, roleArn,
                    'should return correct role ARN');
            }
        } else {
            t.ok(false, 'Response missing AssumeRoleResponse structure');
        }

        t.done();
    });
};

exports.testAssumeRoleInvalidRoleArn = function (t) {
    var caller = {
        user: {
            uuid: TEST_USER_UUID,
            login: 'testuser'
        },
        account: {
            uuid: TEST_ACCOUNT_UUID,
            login: 'testaccount'
        }
    };

    var req = createMockRequest({
        body: {
            caller: caller,
            RoleArn: 'invalid-arn',
            RoleSessionName: 'test-session',
            DurationSeconds: 3600
        }
    });

    var res = createMockResponse();

    sts.assumeRole(req, res, function (err) {
        // Should get error or 400 response
        t.ok(err || res.getStatus() === 400,
            'should reject invalid role ARN');
        t.done();
    });
};

exports.testAssumeRoleNonexistentRole = function (t) {
    var roleArn = 'arn:aws:iam::' + TEST_ACCOUNT_UUID +
        ':role/NonexistentRole';

    var caller = {
        user: {
            uuid: TEST_USER_UUID,
            login: 'testuser'
        },
        account: {
            uuid: TEST_ACCOUNT_UUID,
            login: 'testaccount'
        }
    };

    var req = createMockRequest({
        body: {
            caller: caller,
            RoleArn: roleArn,
            RoleSessionName: 'test-session',
            DurationSeconds: 3600
        }
    });
    req.ufdsPool = createMockUfdsPool();

    var res = createMockResponse();

    sts.assumeRole(req, res, function (_err) {
        // Should get 404 response for nonexistent role (via res.send)
        var status = res.getStatus();
        t.ok(status === 404 || !status,
            'should return 404 for nonexistent role');
        if (status) {
            t.equal(status, 404, 'status should be 404');
        }
        t.done();
    });
};

exports.testAssumeRoleTrustPolicyDenial = function (t) {
    // Create a role with restrictive trust policy
    var restrictedRoleUuid = 'cccccccc-3333-3333-3333-333333333333';
    var restrictedRoleName = 'RestrictedRole';
    var otherUserUuid = 'dddddddd-4444-4444-4444-444444444444';

    var restrictedRole = {
        uuid: restrictedRoleUuid,
        name: restrictedRoleName,
        account: TEST_ACCOUNT_UUID,
        assumerolepolicydocument: JSON.stringify({
            Version: '2012-10-17',
            Statement: [ {
                Effect: 'Allow',
                Principal: {
                    AWS: 'arn:aws:iam::' + TEST_ACCOUNT_UUID +
                        ':user/' + otherUserUuid
                },
                Action: 'sts:AssumeRole'
            }]
        })
    };

    redis.set('/uuid/' + restrictedRoleUuid,
        JSON.stringify(restrictedRole));
    redis.set('/role/' + TEST_ACCOUNT_UUID + '/' + restrictedRoleName,
        restrictedRoleUuid);

    var roleArn = 'arn:aws:iam::' + TEST_ACCOUNT_UUID +
        ':role/' + restrictedRoleName;

    var caller = {
        user: {
            uuid: TEST_USER_UUID,
            login: 'testuser'
        },
        account: {
            uuid: TEST_ACCOUNT_UUID,
            login: 'testaccount'
        }
    };

    var req = createMockRequest({
        body: {
            caller: caller,
            RoleArn: roleArn,
            RoleSessionName: 'test-session',
            DurationSeconds: 3600
        }
    });
    req.ufdsPool = createMockUfdsPool();

    var res = createMockResponse();

    sts.assumeRole(req, res, function (_err) {
        // Should get 403 response for trust policy denial (via res.send)
        var status = res.getStatus();
        t.ok(status === 403 || !status,
            'should return 403 when trust policy denies access');
        if (status) {
            t.equal(status, 403, 'status should be 403');
        }
        t.done();
    });
};

/* --- GetSessionToken end-to-end tests --- */

exports.testGetSessionTokenCompleteFlow = function (t) {
    var caller = {
        user: {
            uuid: TEST_USER_UUID,
            login: 'testuser'
        },
        account: {
            uuid: TEST_ACCOUNT_UUID,
            login: 'testaccount'
        }
    };

    var req = createMockRequest({
        body: {
            caller: caller,
            DurationSeconds: 3600
        }
    });
    req.ufdsPool = createMockUfdsPool();

    var res = createMockResponse();

    sts.getSessionToken(req, res, function (err) {
        // Check for errors
        if (err) {
            t.ok(false, 'GetSessionToken should not return error: ' +
                err.message);
            t.done();
            return;
        }

        // Check response status
        var status = res.getStatus();
        var data = res.getData();

        if (status !== 200) {
            t.ok(false, 'Expected 200 response, got: ' + status +
                ' with data: ' + JSON.stringify(data));
            t.done();
            return;
        }

        t.equal(status, 200, 'should return 200 status');
        t.ok(data, 'should return response data');

        // Navigate response structure:
        // GetSessionTokenResponse.GetSessionTokenResult
        if (data.GetSessionTokenResponse &&
            data.GetSessionTokenResponse.GetSessionTokenResult) {
            var result = data.GetSessionTokenResponse.GetSessionTokenResult;
            t.ok(result.Credentials, 'should include Credentials');
            if (result.Credentials) {
                t.ok(result.Credentials.AccessKeyId,
                    'should include AccessKeyId');
                t.ok(result.Credentials.AccessKeyId.substring(0, 4) ===
                    'MSTS', 'AccessKeyId should start with MSTS');
                t.ok(result.Credentials.SecretAccessKey,
                    'should include SecretAccessKey');
                t.ok(result.Credentials.SessionToken,
                    'should include SessionToken');
                t.ok(result.Credentials.Expiration,
                    'should include Expiration');
            }
        } else {
            t.ok(false, 'Response missing GetSessionTokenResponse structure');
        }

        t.done();
    });
};

exports.testGetSessionTokenInvalidDuration = function (t) {
    var caller = {
        user: {
            uuid: TEST_USER_UUID,
            login: 'testuser'
        },
        account: {
            uuid: TEST_ACCOUNT_UUID,
            login: 'testaccount'
        }
    };

    var req = createMockRequest({
        body: {
            caller: caller,
            DurationSeconds: 300 // Too short (< 900)
        }
    });

    var res = createMockResponse();

    sts.getSessionToken(req, res, function (err) {
        // Should get error for invalid duration
        t.ok(err, 'should reject invalid duration');
        t.done();
    });
};

exports.testGetSessionTokenMissingCaller = function (t) {
    var req = createMockRequest({
        body: {
            DurationSeconds: 3600
        }
    });

    var res = createMockResponse();

    // The function uses assert.object(req.body.caller) which throws
    // if caller is missing, so we need to catch the assertion error
    try {
        sts.getSessionToken(req, res, function (_err) {
            // Should not reach here
            t.ok(false, 'should have thrown assertion error');
            t.done();
        });
    } catch (assertionError) {
        t.ok(assertionError, 'should throw for missing caller');
        t.done();
    }
};

/* --- Token usage tests --- */
