/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright 2025 Edgecast Cloud LLC.
 */

/*
 * test/iam-role-assumption.test.js: Unit tests for IAM role assumption
 *
 * Tests the AssumeRole functionality including role lookup, trust policy
 * evaluation, permission policy retrieval, and temporary credential
 * generation.
 */

var _nodeunit = require('nodeunit');
var bunyan = require('bunyan');
var fakeredis = require('fakeredis');
var sts = require('../lib/server/sts.js');

var log = bunyan.createLogger({
    name: 'iam-role-assumption-test',
    level: 'fatal'
});

var redis;

// Test data constants
var TEST_ACCOUNT_UUID = '12345678-1234-1234-1234-123456789012';
var TEST_USER_UUID = 'aaaaaaaa-1111-1111-1111-111111111111';
var TEST_ROLE_UUID = 'bbbbbbbb-2222-2222-2222-222222222222';
var TEST_ROLE_NAME = 'TestRole';
var TEST_CROSS_ACCOUNT_UUID = '87654321-4321-4321-4321-210987654321';
var TEST_SESSION_SECRET = {
    key: 'test-session-secret-key-for-jwt',
    keyId: 'test-key-001'
};

/* --- Setup and teardown --- */

exports.setUp = function (cb) {
    redis = fakeredis.createClient();
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
 * Create a mock request object for AssumeRole
 */
function createMockRequest(opts) {
    var req = {
        log: log,
        redis: redis,
        sessionConfig: {
            secretKey: TEST_SESSION_SECRET.key,
            secretKeyId: TEST_SESSION_SECRET.keyId,
            gracePeriod: 300,
            issuer: 'manta-mahi',
            audience: 'manta-s3'
        },
        body: opts.body || {},
        params: opts.params || {}
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
 * Setup basic role data in Redis
 */
function setupRoleData(roleUuid, roleName, accountId, trustPolicy, cb) {
    var roleNameKey = '/role/' + accountId + '/' + roleName;
    var roleDataKey = '/uuid/' + roleUuid;

    var roleData = {
        uuid: roleUuid,
        name: roleName,
        account: accountId,
        assumerolepolicydocument: trustPolicy
    };

    redis.set(roleNameKey, roleUuid, function (err1) {
        if (err1) {
            return (cb(err1));
        }

        var roleDataStr = JSON.stringify(roleData);
        return redis.set(roleDataKey, roleDataStr, function (err2) {
            if (err2) {
                return (cb(err2));
            }

            return (cb(null));
        });
    });
}

/*
 * Setup role with permission policies
 */
function setupRoleWithPolicies(roleUuid, roleName, accountId, trustPolicy,
    permissionPolicies, cb) {

    setupRoleData(roleUuid, roleName, accountId, trustPolicy,
        function (err) {
        if (err) {
            return (cb(err));
        }

        var policiesKey = '/role-permissions/' + roleUuid;
        return redis.set(policiesKey, JSON.stringify(permissionPolicies),
            function (policyErr) {
            if (policyErr) {
                return (cb(policyErr));
            }

            return (cb(null));
        });
    });
}

/* --- Test valid role assumption --- */

exports.testValidRoleAssumption = function (t) {
    var trustPolicy = JSON.stringify({
        Version: '2012-10-17',
        Statement: [ {
            Effect: 'Allow',
            Principal: {
                AWS: 'arn:aws:iam::' + TEST_ACCOUNT_UUID + ':root'
            },
            Action: 'sts:AssumeRole'
        } ]
    });

    setupRoleData(TEST_ROLE_UUID, TEST_ROLE_NAME, TEST_ACCOUNT_UUID,
        trustPolicy, function (err) {
        t.ok(!err, 'should setup role data');

        var roleArn = 'arn:aws:iam::' + TEST_ACCOUNT_UUID +
            ':role/' + TEST_ROLE_NAME;

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

        var res = createMockResponse();

        sts.assumeRole(req, res, function (assumeErr) {
            if (assumeErr) {
                t.ok(false, 'AssumeRole should not error: ' +
                    assumeErr.message);
                t.done();
                return;
            }

            var status = res.getStatus();
            var data = res.getData();

            t.equal(status, 200, 'should return 200 status');
            t.ok(data, 'should return response data');

            if (data && data.AssumeRoleResponse &&
                data.AssumeRoleResponse.AssumeRoleResult) {

                var result = data.AssumeRoleResponse.AssumeRoleResult;

                t.ok(result.Credentials, 'should have Credentials');
                t.ok(result.Credentials.AccessKeyId,
                    'should have AccessKeyId');
                t.ok(result.Credentials.SecretAccessKey,
                    'should have SecretAccessKey');
                t.ok(result.Credentials.SessionToken,
                    'should have SessionToken');
                t.ok(result.Credentials.Expiration,
                    'should have Expiration');

                t.ok(result.Credentials.AccessKeyId.substring(0, 4) ===
                    'MSAR', 'AccessKeyId should start with MSAR');

                t.ok(result.AssumedRoleUser, 'should have AssumedRoleUser');
                t.equal(result.AssumedRoleUser.Arn, roleArn,
                    'should have correct role ARN');
            } else {
                t.ok(false, 'Response missing expected structure');
            }

            t.done();
        });
    });
};

exports.testRoleAssumptionWithSpecificUser = function (t) {
    var trustPolicy = JSON.stringify({
        Version: '2012-10-17',
        Statement: [ {
            Effect: 'Allow',
            Principal: {
                AWS: 'arn:aws:iam::' + TEST_ACCOUNT_UUID + ':user/testuser'
            },
            Action: 'sts:AssumeRole'
        } ]
    });

    setupRoleData(TEST_ROLE_UUID, TEST_ROLE_NAME, TEST_ACCOUNT_UUID,
        trustPolicy, function (err) {
        t.ok(!err, 'should setup role data');

        var roleArn = 'arn:aws:iam::' + TEST_ACCOUNT_UUID +
            ':role/' + TEST_ROLE_NAME;

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
                RoleSessionName: 'specific-user-session',
                DurationSeconds: 3600
            }
        });

        var res = createMockResponse();

        sts.assumeRole(req, res, function (assumeErr) {
            var status = res.getStatus();
            t.equal(status, 200,
                'should allow assumption by specific user');
            t.done();
        });
    });
};

/* --- Test trust policy evaluation --- */

exports.testTrustPolicyDenial = function (t) {
    var otherUserUuid = 'dddddddd-4444-4444-4444-444444444444';

    var trustPolicy = JSON.stringify({
        Version: '2012-10-17',
        Statement: [ {
            Effect: 'Allow',
            Principal: {
                AWS: 'arn:aws:iam::' + TEST_ACCOUNT_UUID + ':user/' +
                    otherUserUuid
            },
            Action: 'sts:AssumeRole'
        } ]
    });

    setupRoleData(TEST_ROLE_UUID, TEST_ROLE_NAME, TEST_ACCOUNT_UUID,
        trustPolicy, function (err) {
        t.ok(!err, 'should setup role data');

        var roleArn = 'arn:aws:iam::' + TEST_ACCOUNT_UUID +
            ':role/' + TEST_ROLE_NAME;

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
                RoleSessionName: 'denied-session',
                DurationSeconds: 3600
            }
        });

        var res = createMockResponse();

        sts.assumeRole(req, res, function (assumeErr) {
            var status = res.getStatus();
            t.equal(status, 403,
                'should deny access with 403 when trust policy denies');

            var data = res.getData();
            t.ok(data && data.error === 'AccessDenied',
                'should return AccessDenied error');

            t.done();
        });
    });
};

exports.testTrustPolicyExplicitDeny = function (t) {
    var trustPolicy = JSON.stringify({
        Version: '2012-10-17',
        Statement: [
            {
                Effect: 'Allow',
                Principal: {
                    AWS: 'arn:aws:iam::' + TEST_ACCOUNT_UUID + ':root'
                },
                Action: 'sts:AssumeRole'
            },
            {
                Effect: 'Deny',
                Principal: {
                    AWS: 'arn:aws:iam::' + TEST_ACCOUNT_UUID + ':user/testuser'
                },
                Action: 'sts:AssumeRole'
            }
        ]
    });

    setupRoleData(TEST_ROLE_UUID, TEST_ROLE_NAME, TEST_ACCOUNT_UUID,
        trustPolicy, function (err) {
        t.ok(!err, 'should setup role data');

        var roleArn = 'arn:aws:iam::' + TEST_ACCOUNT_UUID +
            ':role/' + TEST_ROLE_NAME;

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
                RoleSessionName: 'explicit-deny-session',
                DurationSeconds: 3600
            }
        });

        var res = createMockResponse();

        sts.assumeRole(req, res, function (assumeErr) {
            var status = res.getStatus();
            t.equal(status, 403,
                'should deny when explicit Deny statement matches');

            t.done();
        });
    });
};

/* --- Test role permission retrieval --- */

exports.testRoleWithPermissionPolicies = function (t) {
    var trustPolicy = JSON.stringify({
        Version: '2012-10-17',
        Statement: [ {
            Effect: 'Allow',
            Principal: {
                AWS: 'arn:aws:iam::' + TEST_ACCOUNT_UUID + ':root'
            },
            Action: 'sts:AssumeRole'
        } ]
    });

    var permissionPolicies = [
        {
            Version: '2012-10-17',
            Statement: [ {
                Effect: 'Allow',
                Action: 's3:*',
                Resource: '*'
            } ]
        }
    ];

    setupRoleWithPolicies(TEST_ROLE_UUID, TEST_ROLE_NAME, TEST_ACCOUNT_UUID,
        trustPolicy, permissionPolicies, function (err) {
        t.ok(!err, 'should setup role with policies');

        var roleArn = 'arn:aws:iam::' + TEST_ACCOUNT_UUID +
            ':role/' + TEST_ROLE_NAME;

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
                RoleSessionName: 'policy-test-session',
                DurationSeconds: 3600
            }
        });

        var res = createMockResponse();

        sts.assumeRole(req, res, function (assumeErr) {
            t.ok(!assumeErr, 'should not error');

            var status = res.getStatus();
            t.equal(status, 200,
                'should succeed when loading permission policies');

            t.done();
        });
    });
};

exports.testRoleWithoutPermissionPolicies = function (t) {
    var trustPolicy = JSON.stringify({
        Version: '2012-10-17',
        Statement: [ {
            Effect: 'Allow',
            Principal: {
                AWS: 'arn:aws:iam::' + TEST_ACCOUNT_UUID + ':root'
            },
            Action: 'sts:AssumeRole'
        } ]
    });

    setupRoleData(TEST_ROLE_UUID, TEST_ROLE_NAME, TEST_ACCOUNT_UUID,
        trustPolicy, function (err) {
        t.ok(!err, 'should setup role data');

        var roleArn = 'arn:aws:iam::' + TEST_ACCOUNT_UUID +
            ':role/' + TEST_ROLE_NAME;

        var caller = {
            account: {
                uuid: TEST_ACCOUNT_UUID,
                login: 'testaccount'
            }
        };

        var req = createMockRequest({
            body: {
                caller: caller,
                RoleArn: roleArn,
                RoleSessionName: 'no-policies-session',
                DurationSeconds: 3600
            }
        });

        var res = createMockResponse();

        sts.assumeRole(req, res, function (assumeErr) {
            t.ok(!assumeErr, 'should not error');

            var status = res.getStatus();
            t.equal(status, 200,
                'should succeed even without permission policies');

            t.done();
        });
    });
};

/* --- Test invalid role rejection --- */

exports.testNonexistentRole = function (t) {
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

    var res = createMockResponse();

    sts.assumeRole(req, res, function (assumeErr) {
        var status = res.getStatus();
        t.equal(status, 404, 'should return 404 for nonexistent role');

        var data = res.getData();
        t.ok(data && data.error, 'should have error message');
        t.ok(data.error.indexOf('not found') >= 0,
            'error should mention role not found');

        t.done();
    });
};

exports.testInvalidRoleArn = function (t) {
    var caller = {
        account: {
            uuid: TEST_ACCOUNT_UUID,
            login: 'testaccount'
        }
    };

    var req = createMockRequest({
        body: {
            caller: caller,
            RoleArn: 'invalid-arn-format',
            RoleSessionName: 'test-session',
            DurationSeconds: 3600
        }
    });

    var res = createMockResponse();

    sts.assumeRole(req, res, function (assumeErr) {
        var status = res.getStatus();
        t.ok(status === 400 || assumeErr,
            'should reject invalid ARN format');

        t.done();
    });
};

exports.testRoleArnNotForRole = function (t) {
    var caller = {
        account: {
            uuid: TEST_ACCOUNT_UUID,
            login: 'testaccount'
        }
    };

    var req = createMockRequest({
        body: {
            caller: caller,
            RoleArn: 'arn:aws:iam::' + TEST_ACCOUNT_UUID + ':user/testuser',
            RoleSessionName: 'test-session',
            DurationSeconds: 3600
        }
    });

    var res = createMockResponse();

    sts.assumeRole(req, res, function (assumeErr) {
        var status = res.getStatus();
        t.ok(assumeErr || status === 400,
            'should reject ARN that does not specify a role');

        if (assumeErr) {
            t.ok(assumeErr.message || assumeErr.error,
                'should have error message');
        }

        t.done();
    });
};

exports.testMissingRoleData = function (t) {
    var roleNameKey = '/role/' + TEST_ACCOUNT_UUID + '/' + TEST_ROLE_NAME;

    redis.set(roleNameKey, TEST_ROLE_UUID, function (err) {
        t.ok(!err, 'should set role name key');

        var roleArn = 'arn:aws:iam::' + TEST_ACCOUNT_UUID +
            ':role/' + TEST_ROLE_NAME;

        var caller = {
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

        var res = createMockResponse();

        sts.assumeRole(req, res, function (assumeErr) {
            var status = res.getStatus();
            t.equal(status, 404,
                'should return 404 when role data is missing');

            t.done();
        });
    });
};

/* --- Test cross-account role assumption --- */

exports.testCrossAccountRoleAssumption = function (t) {
    var trustPolicy = JSON.stringify({
        Version: '2012-10-17',
        Statement: [ {
            Effect: 'Allow',
            Principal: {
                AWS: 'arn:aws:iam::' + TEST_CROSS_ACCOUNT_UUID + ':root'
            },
            Action: 'sts:AssumeRole'
        } ]
    });

    setupRoleData(TEST_ROLE_UUID, TEST_ROLE_NAME, TEST_ACCOUNT_UUID,
        trustPolicy, function (err) {
        t.ok(!err, 'should setup role data');

        var roleArn = 'arn:aws:iam::' + TEST_ACCOUNT_UUID +
            ':role/' + TEST_ROLE_NAME;

        var caller = {
            user: {
                uuid: TEST_USER_UUID,
                login: 'crossuser'
            },
            account: {
                uuid: TEST_CROSS_ACCOUNT_UUID,
                login: 'crossaccount'
            }
        };

        var req = createMockRequest({
            body: {
                caller: caller,
                RoleArn: roleArn,
                RoleSessionName: 'cross-account-session',
                DurationSeconds: 3600
            }
        });

        var res = createMockResponse();

        sts.assumeRole(req, res, function (assumeErr) {
            t.ok(!assumeErr, 'should not error');

            var status = res.getStatus();
            t.equal(status, 200,
                'should allow cross-account role assumption');

            t.done();
        });
    });
};

exports.testCrossAccountDenied = function (t) {
    var trustPolicy = JSON.stringify({
        Version: '2012-10-17',
        Statement: [ {
            Effect: 'Allow',
            Principal: {
                AWS: 'arn:aws:iam::' + TEST_ACCOUNT_UUID + ':root'
            },
            Action: 'sts:AssumeRole'
        } ]
    });

    setupRoleData(TEST_ROLE_UUID, TEST_ROLE_NAME, TEST_ACCOUNT_UUID,
        trustPolicy, function (err) {
        t.ok(!err, 'should setup role data');

        var roleArn = 'arn:aws:iam::' + TEST_ACCOUNT_UUID +
            ':role/' + TEST_ROLE_NAME;

        var caller = {
            user: {
                uuid: TEST_USER_UUID,
                login: 'crossuser'
            },
            account: {
                uuid: TEST_CROSS_ACCOUNT_UUID,
                login: 'crossaccount'
            }
        };

        var req = createMockRequest({
            body: {
                caller: caller,
                RoleArn: roleArn,
                RoleSessionName: 'cross-account-denied',
                DurationSeconds: 3600
            }
        });

        var res = createMockResponse();

        sts.assumeRole(req, res, function (assumeErr) {
            var status = res.getStatus();
            t.equal(status, 403,
                'should deny cross-account access when not in trust policy');

            t.done();
        });
    });
};

/* --- Test edge cases and error conditions --- */

exports.testMalformedRoleData = function (t) {
    var roleNameKey = '/role/' + TEST_ACCOUNT_UUID + '/' + TEST_ROLE_NAME;
    var roleDataKey = '/uuid/' + TEST_ROLE_UUID;

    redis.set(roleNameKey, TEST_ROLE_UUID, function (err1) {
        t.ok(!err1, 'should set role name key');

        redis.set(roleDataKey, 'invalid-json{', function (err2) {
            t.ok(!err2, 'should set malformed role data');

            var roleArn = 'arn:aws:iam::' + TEST_ACCOUNT_UUID +
                ':role/' + TEST_ROLE_NAME;

            var caller = {
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

            var res = createMockResponse();

            sts.assumeRole(req, res, function (assumeErr) {
                var status = res.getStatus();
                t.equal(status, 500,
                    'should return 500 for malformed role data');

                t.done();
            });
        });
    });
};

exports.testInvalidPermissionPoliciesData = function (t) {
    var trustPolicy = JSON.stringify({
        Version: '2012-10-17',
        Statement: [ {
            Effect: 'Allow',
            Principal: {
                AWS: 'arn:aws:iam::' + TEST_ACCOUNT_UUID + ':root'
            },
            Action: 'sts:AssumeRole'
        } ]
    });

    setupRoleData(TEST_ROLE_UUID, TEST_ROLE_NAME, TEST_ACCOUNT_UUID,
        trustPolicy, function (err) {
        t.ok(!err, 'should setup role data');

        var policiesKey = '/role-permissions/' + TEST_ROLE_UUID;
        redis.set(policiesKey, 'invalid-json[', function (policyErr) {
            t.ok(!policyErr, 'should set invalid policies data');

            var roleArn = 'arn:aws:iam::' + TEST_ACCOUNT_UUID +
                ':role/' + TEST_ROLE_NAME;

            var caller = {
                account: {
                    uuid: TEST_ACCOUNT_UUID,
                    login: 'testaccount'
                }
            };

            var req = createMockRequest({
                body: {
                    caller: caller,
                    RoleArn: roleArn,
                    RoleSessionName: 'bad-policies-session',
                    DurationSeconds: 3600
                }
            });

            var res = createMockResponse();

            sts.assumeRole(req, res, function (assumeErr) {
                var status = res.getStatus();
                t.equal(status, 500,
                    'should return 500 for invalid policies JSON');

                t.done();
            });
        });
    });
};

exports.testInvalidDuration = function (t) {
    var caller = {
        account: {
            uuid: TEST_ACCOUNT_UUID,
            login: 'testaccount'
        }
    };

    var req = createMockRequest({
        body: {
            caller: caller,
            RoleArn: 'arn:aws:iam::' + TEST_ACCOUNT_UUID +
                ':role/TestRole',
            RoleSessionName: 'test-session',
            DurationSeconds: 100
        }
    });

    var res = createMockResponse();

    sts.assumeRole(req, res, function (assumeErr) {
        t.ok(assumeErr || res.getStatus() >= 400,
            'should reject invalid duration (too short)');

        t.done();
    });
};

exports.testMissingSessionName = function (t) {
    var caller = {
        account: {
            uuid: TEST_ACCOUNT_UUID,
            login: 'testaccount'
        }
    };

    var req = createMockRequest({
        body: {
            caller: caller,
            RoleArn: 'arn:aws:iam::' + TEST_ACCOUNT_UUID +
                ':role/TestRole',
            DurationSeconds: 3600
        }
    });

    var res = createMockResponse();

    sts.assumeRole(req, res, function (assumeErr) {
        t.ok(assumeErr || res.getStatus() >= 400,
            'should reject missing RoleSessionName');

        t.done();
    });
};
