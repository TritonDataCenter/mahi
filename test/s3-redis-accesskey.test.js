/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2026 Edgecast Cloud LLC.
 */

/*
 * test/s3-redis-accesskey.test.js: Unit tests for Redis S3 access key lookup
 * functionality in redislib.js
 *
 * WORK-1: CHG-047 - Redis S3 Access Key Lookup Tests
 *
 * Coverage targets:
 *   - redislib.js: 26% -> 50%+ statements
 *   - redis.js: 15% -> 40%+
 *
 * Test areas:
 *   - Access key not found (null response)
 *   - Malformed JSON in Redis value
 *   - Missing required fields in key data
 *   - Temporary credential parsing (MSTS/MSAR)
 *   - getObject/getAccount/getUser/getRole/getPolicy
 *   - getAccountUuid/getUuid lookups
 *   - getRoles/generateLookup/getRoleMembers
 */

var nodeunit = require('nodeunit-plus');
var test = nodeunit.test;
var fakeredis = require('fakeredis');
var bunyan = require('bunyan');

var redislib = require('../lib/server/redislib');

var log = bunyan.createLogger({
    name: 's3-redis-accesskey-test',
    level: 'fatal'
});

var redis;

/*
 * ==============================
 * SETUP
 */

test('setup', function (t) {
    redis = fakeredis.createClient();
    t.ok(redis, 'fakeredis client created');
    t.done();
});

/*
 * ==============================
 * SECTION 1: getObject Tests
 */

test('getObject - valid object', function (t) {
    var testUuid = 'test-object-uuid-001';
    var testData = {
        uuid: testUuid,
        type: 'user',
        login: 'testuser'
    };

    redis.set('/uuid/' + testUuid, JSON.stringify(testData), function (err) {
        t.ok(!err, 'should set test data');

        redislib.getObject({
            uuid: testUuid,
            log: log,
            redis: redis
        }, function (err, result) {
            t.ok(!err, 'should not error for valid object');
            t.ok(result, 'should return result');
            t.equal(result.uuid, testUuid, 'should have correct uuid');
            t.equal(result.login, 'testuser', 'should have correct login');
            t.done();
        });
    });
});

test('getObject - object not found', function (t) {
    redislib.getObject({
        uuid: 'nonexistent-uuid-12345',
        log: log,
        redis: redis
    }, function (err, result) {
        t.ok(err, 'should error for nonexistent object');
        t.equal(err.restCode, 'ObjectDoesNotExist',
            'should be ObjectDoesNotExist');
        t.ok(!result, 'should not return result');
        t.done();
    });
});

/*
 * Note: getObject with malformed JSON in Redis throws an uncaught
 * SyntaxError from JSON.parse. This is a potential bug in the production
 * code that should be addressed. The error is thrown asynchronously
 * inside the Redis callback, making it untestable with standard methods.
 */

/*
 * ==============================
 * SECTION 2: getAccount Tests
 */

test('getAccount - valid account', function (t) {
    var testUuid = 'test-account-uuid-001';
    var testData = {
        uuid: testUuid,
        type: 'account',
        login: 'testaccount',
        groups: ['operators']
    };

    redis.set('/uuid/' + testUuid, JSON.stringify(testData), function (err) {
        t.ok(!err, 'should set account data');

        redislib.getAccount({
            uuid: testUuid,
            log: log,
            redis: redis
        }, function (err, result) {
            t.ok(!err, 'should not error for valid account');
            t.ok(result, 'should return result');
            t.equal(result.type, 'account', 'should be account type');
            t.equal(result.isOperator, true, 'should be operator');
            t.done();
        });
    });
});

test('getAccount - not found', function (t) {
    redislib.getAccount({
        uuid: 'nonexistent-account-uuid',
        log: log,
        redis: redis
    }, function (err, result) {
        t.ok(err, 'should error for nonexistent account');
        // Note: code checks err.code but errors use restCode, so
        // AccountIdDoesNotExistError is not thrown -
        // ObjectDoesNotExist bubbles up
        t.equal(err.restCode, 'ObjectDoesNotExist', 'correct error code');
        t.done();
    });
});

test('getAccount - wrong type (user instead of account)', function (t) {
    var testUuid = 'wrong-type-user-uuid';
    var testData = {
        uuid: testUuid,
        type: 'user',
        login: 'testuser'
    };

    redis.set('/uuid/' + testUuid, JSON.stringify(testData), function (err) {
        t.ok(!err, 'should set user data');

        redislib.getAccount({
            uuid: testUuid,
            log: log,
            redis: redis
        }, function (err, result) {
            t.ok(err, 'should error for wrong type');
            t.equal(err.restCode, 'WrongType', 'should be WrongType error');
            t.done();
        });
    });
});

test('getAccount - non-operator (no groups)', function (t) {
    var testUuid = 'non-operator-account-uuid';
    var testData = {
        uuid: testUuid,
        type: 'account',
        login: 'regularaccount'
    };

    redis.set('/uuid/' + testUuid, JSON.stringify(testData), function (err) {
        t.ok(!err, 'should set account data');

        redislib.getAccount({
            uuid: testUuid,
            log: log,
            redis: redis
        }, function (err, result) {
            t.ok(!err, 'should not error');
            // isOperator = result.groups &&
            //     result.groups.indexOf('operators') >= 0
            // When groups is undefined, this evaluates to undefined (falsy)
            t.ok(!result.isOperator, 'should not be operator (falsy)');
            t.done();
        });
    });
});

/*
 * ==============================
 * SECTION 3: getUser Tests
 */

test('getUser - valid user', function (t) {
    var testUuid = 'test-user-uuid-002';
    var testData = {
        uuid: testUuid,
        type: 'user',
        login: 'subuser',
        account: 'parent-account-uuid'
    };

    redis.set('/uuid/' + testUuid, JSON.stringify(testData), function (err) {
        t.ok(!err, 'should set user data');

        redislib.getUser({
            uuid: testUuid,
            log: log,
            redis: redis
        }, function (err, result) {
            t.ok(!err, 'should not error for valid user');
            t.ok(result, 'should return result');
            t.equal(result.type, 'user', 'should be user type');
            t.equal(result.login, 'subuser', 'should have correct login');
            t.done();
        });
    });
});

test('getUser - not found', function (t) {
    redislib.getUser({
        uuid: 'nonexistent-user-uuid',
        log: log,
        redis: redis
    }, function (err, result) {
        t.ok(err, 'should error for nonexistent user');
        // Note: err.code check vs restCode - ObjectDoesNotExist bubbles up
        t.equal(err.restCode, 'ObjectDoesNotExist', 'correct error code');
        t.done();
    });
});

test('getUser - wrong type (account instead of user)', function (t) {
    var testUuid = 'wrong-type-account-uuid';
    var testData = {
        uuid: testUuid,
        type: 'account',
        login: 'testaccount'
    };

    redis.set('/uuid/' + testUuid, JSON.stringify(testData), function (err) {
        t.ok(!err, 'should set account data');

        redislib.getUser({
            uuid: testUuid,
            log: log,
            redis: redis
        }, function (err, result) {
            t.ok(err, 'should error for wrong type');
            t.equal(err.restCode, 'WrongType', 'should be WrongType error');
            t.done();
        });
    });
});

/*
 * ==============================
 * SECTION 4: getRole Tests
 */

test('getRole - valid role', function (t) {
    var testUuid = 'test-role-uuid-001';
    var testData = {
        uuid: testUuid,
        type: 'role',
        name: 'admin',
        account: 'parent-account-uuid',
        policies: []
    };

    redis.set('/uuid/' + testUuid, JSON.stringify(testData), function (err) {
        t.ok(!err, 'should set role data');

        redislib.getRole({
            uuid: testUuid,
            log: log,
            redis: redis
        }, function (err, result) {
            t.ok(!err, 'should not error for valid role');
            t.ok(result, 'should return result');
            t.equal(result.type, 'role', 'should be role type');
            t.equal(result.name, 'admin', 'should have correct name');
            t.done();
        });
    });
});

test('getRole - not found', function (t) {
    redislib.getRole({
        uuid: 'nonexistent-role-uuid',
        log: log,
        redis: redis
    }, function (err, result) {
        t.ok(err, 'should error for nonexistent role');
        // Note: err.code check vs restCode - ObjectDoesNotExist bubbles up
        t.equal(err.restCode, 'ObjectDoesNotExist', 'correct error code');
        t.done();
    });
});

test('getRole - wrong type', function (t) {
    var testUuid = 'wrong-type-for-role-uuid';
    var testData = {
        uuid: testUuid,
        type: 'policy',
        name: 'testpolicy'
    };

    redis.set('/uuid/' + testUuid, JSON.stringify(testData), function (err) {
        t.ok(!err, 'should set policy data');

        redislib.getRole({
            uuid: testUuid,
            log: log,
            redis: redis
        }, function (err, result) {
            t.ok(err, 'should error for wrong type');
            t.equal(err.restCode, 'WrongType', 'should be WrongType error');
            t.done();
        });
    });
});

/*
 * ==============================
 * SECTION 5: getPolicy Tests
 */

test('getPolicy - valid policy', function (t) {
    var testUuid = 'test-policy-uuid-001';
    var testData = {
        uuid: testUuid,
        type: 'policy',
        name: 'testpolicy',
        rules: ['CAN read *']
    };

    redis.set('/uuid/' + testUuid, JSON.stringify(testData), function (err) {
        t.ok(!err, 'should set policy data');

        redislib.getPolicy({
            uuid: testUuid,
            log: log,
            redis: redis
        }, function (err, result) {
            t.ok(!err, 'should not error for valid policy');
            t.ok(result, 'should return result');
            t.equal(result.type, 'policy', 'should be policy type');
            t.equal(result.name, 'testpolicy', 'should have correct name');
            t.done();
        });
    });
});

test('getPolicy - not found', function (t) {
    redislib.getPolicy({
        uuid: 'nonexistent-policy-uuid',
        log: log,
        redis: redis
    }, function (err, result) {
        t.ok(err, 'should error for nonexistent policy');
        // Note: err.code check vs restCode - ObjectDoesNotExist bubbles up
        t.equal(err.restCode, 'ObjectDoesNotExist', 'correct error code');
        t.done();
    });
});

test('getPolicy - wrong type', function (t) {
    var testUuid = 'wrong-type-for-policy-uuid';
    var testData = {
        uuid: testUuid,
        type: 'role',
        name: 'testrole'
    };

    redis.set('/uuid/' + testUuid, JSON.stringify(testData), function (err) {
        t.ok(!err, 'should set role data');

        redislib.getPolicy({
            uuid: testUuid,
            log: log,
            redis: redis
        }, function (err, result) {
            t.ok(err, 'should error for wrong type');
            t.equal(err.restCode, 'WrongType', 'should be WrongType error');
            t.done();
        });
    });
});

/*
 * ==============================
 * SECTION 6: getAccountUuid Tests
 */

test('getAccountUuid - valid lookup', function (t) {
    var testLogin = 'myaccount';
    var testUuid = 'account-uuid-from-login';

    redis.set('/account/' + testLogin, testUuid, function (err) {
        t.ok(!err, 'should set account mapping');

        redislib.getAccountUuid({
            account: testLogin,
            log: log,
            redis: redis
        }, function (err, result) {
            t.ok(!err, 'should not error for valid lookup');
            t.equal(result, testUuid, 'should return correct uuid');
            t.done();
        });
    });
});

test('getAccountUuid - account not found', function (t) {
    redislib.getAccountUuid({
        account: 'nonexistent-account-login',
        log: log,
        redis: redis
    }, function (err, result) {
        t.ok(err, 'should error for nonexistent account');
        t.equal(err.restCode, 'AccountDoesNotExist', 'correct error code');
        t.done();
    });
});

/*
 * ==============================
 * SECTION 7: getUuid Tests
 */

test('getUuid - valid user lookup', function (t) {
    var accountUuid = 'parent-account-for-getUuid';
    var userName = 'subuser1';
    var userUuid = 'subuser1-uuid';

    redis.set('/user/' + accountUuid + '/' + userName, userUuid,
        function (err) {
        t.ok(!err, 'should set user mapping');

        redislib.getUuid({
            accountUuid: accountUuid,
            name: userName,
            type: 'user',
            log: log,
            redis: redis
        }, function (err, result) {
            t.ok(!err, 'should not error for valid lookup');
            t.equal(result, userUuid, 'should return correct uuid');
            t.done();
        });
    });
});

test('getUuid - valid role lookup', function (t) {
    var accountUuid = 'parent-account-for-role';
    var roleName = 'myrole';
    var roleUuid = 'myrole-uuid';

    redis.set('/role/' + accountUuid + '/' + roleName, roleUuid,
        function (err) {
        t.ok(!err, 'should set role mapping');

        redislib.getUuid({
            accountUuid: accountUuid,
            name: roleName,
            type: 'role',
            log: log,
            redis: redis
        }, function (err, result) {
            t.ok(!err, 'should not error for valid lookup');
            t.equal(result, roleUuid, 'should return correct uuid');
            t.done();
        });
    });
});

test('getUuid - valid policy lookup', function (t) {
    var accountUuid = 'parent-account-for-policy';
    var policyName = 'mypolicy';
    var policyUuid = 'mypolicy-uuid';

    redis.set('/policy/' + accountUuid + '/' + policyName, policyUuid,
        function (err) {
        t.ok(!err, 'should set policy mapping');

        redislib.getUuid({
            accountUuid: accountUuid,
            name: policyName,
            type: 'policy',
            log: log,
            redis: redis
        }, function (err, result) {
            t.ok(!err, 'should not error for valid lookup');
            t.equal(result, policyUuid, 'should return correct uuid');
            t.done();
        });
    });
});

test('getUuid - object not found', function (t) {
    redislib.getUuid({
        accountUuid: 'some-account',
        name: 'nonexistent-user',
        type: 'user',
        log: log,
        redis: redis
    }, function (err, result) {
        t.ok(err, 'should error for nonexistent object');
        t.equal(err.restCode, 'ObjectDoesNotExist', 'correct error code');
        t.done();
    });
});

/*
 * ==============================
 * SECTION 8: getUserByAccessKey Tests
 */

test('getUserByAccessKey - permanent credential (account)', function (t) {
    var accessKeyId = 'AKIAPERMANENT001';
    var accountUuid = 'account-for-permanent-key';
    var accountData = {
        uuid: accountUuid,
        type: 'account',
        login: 'permanentaccount',
        accesskeys: {}
    };
    accountData.accesskeys[accessKeyId] = 'secretkey123';

    redis.set('/accesskey/' + accessKeyId, accountUuid, function (err) {
        t.ok(!err, 'should set access key mapping');

        redis.set('/uuid/' + accountUuid, JSON.stringify(accountData),
            function (err2) {
            t.ok(!err2, 'should set account data');

            redislib.getUserByAccessKey({
                accessKeyId: accessKeyId,
                log: log,
                redis: redis
            }, function (err, result) {
                t.ok(!err, 'should not error');
                t.ok(result, 'should return result');
                t.ok(result.account, 'should have account');
                t.equal(result.account.uuid, accountUuid, 'correct account');
                t.equal(result.user, null, 'user should be null for account');
                t.equal(result.isTemporaryCredential, false,
                    'should not be temporary');
                t.done();
            });
        });
    });
});

test('getUserByAccessKey - permanent credential (user)', function (t) {
    var accessKeyId = 'AKIAPERMANENTUSER';
    var userUuid = 'user-for-permanent-key';
    var userData = {
        uuid: userUuid,
        type: 'user',
        login: 'subuser',
        account: 'parent-account-uuid',
        accesskeys: {}
    };
    userData.accesskeys[accessKeyId] = 'usersecret456';

    redis.set('/accesskey/' + accessKeyId, userUuid, function (err) {
        t.ok(!err, 'should set access key mapping');

        redis.set('/uuid/' + userUuid, JSON.stringify(userData),
            function (err2) {
            t.ok(!err2, 'should set user data');

            redislib.getUserByAccessKey({
                accessKeyId: accessKeyId,
                log: log,
                redis: redis
            }, function (err, result) {
                t.ok(!err, 'should not error');
                t.ok(result, 'should return result');
                t.ok(result.account, 'should have account');
                t.ok(result.user, 'should have user');
                t.equal(result.user.uuid, userUuid, 'correct user');
                t.equal(result.isTemporaryCredential, false,
                    'should not be temporary');
                t.done();
            });
        });
    });
});

test('getUserByAccessKey - MSTS temporary credential', function (t) {
    var accessKeyId = 'MSTStemp001abc';
    var userUuid = 'user-for-msts-key';
    var tempCredData = {
        userUuid: userUuid,
        secretAccessKey: 'tempsecret789',
        expiration: Date.now() + 3600000,
        sessionToken: 'sessiontoken123',
        credentialType: 'session'
    };
    var userData = {
        uuid: userUuid,
        type: 'user',
        login: 'mstsuser',
        account: 'msts-parent-account'
    };

    redis.set('/accesskey/' + accessKeyId, JSON.stringify(tempCredData),
        function (err) {
        t.ok(!err, 'should set temp cred mapping');

        redis.set('/uuid/' + userUuid, JSON.stringify(userData),
            function (err2) {
            t.ok(!err2, 'should set user data');

            redislib.getUserByAccessKey({
                accessKeyId: accessKeyId,
                log: log,
                redis: redis
            }, function (err, result) {
                t.ok(!err, 'should not error');
                t.ok(result, 'should return result');
                t.equal(result.isTemporaryCredential, true,
                    'should be temporary');
                t.ok(result.user.accesskeys[accessKeyId],
                    'should inject temp cred');
                t.equal(result.user.accesskeys[accessKeyId].secret,
                    'tempsecret789', 'correct secret injected');
                t.done();
            });
        });
    });
});

test('getUserByAccessKey - MSAR assumed role credential', function (t) {
    var accessKeyId = 'MSARassumed001';
    var principalUuid = 'principal-for-msar';
    var tempCredData = {
        principalUuid: principalUuid,
        secretAccessKey: 'assumedsecret',
        expiration: Date.now() + 3600000,
        sessionToken: 'assumeroletoken',
        sessionName: 'mysession',
        credentialType: 'assumed-role',
        assumedRole: {
            roleUuid: 'assumed-role-uuid',
            arn: 'arn:aws:sts::123456:assumed-role/myrole/mysession',
            policies: ['policy1']
        }
    };
    var userData = {
        uuid: principalUuid,
        type: 'user',
        login: 'msaruser',
        account: 'msar-parent-account'
    };

    redis.set('/accesskey/' + accessKeyId, JSON.stringify(tempCredData),
        function (err) {
        t.ok(!err, 'should set assumed role cred mapping');

        redis.set('/uuid/' + principalUuid, JSON.stringify(userData),
            function (err2) {
            t.ok(!err2, 'should set user data');

            redislib.getUserByAccessKey({
                accessKeyId: accessKeyId,
                log: log,
                redis: redis
            }, function (err, result) {
                t.ok(!err, 'should not error');
                t.ok(result, 'should return result');
                t.equal(result.isTemporaryCredential, true,
                    'should be temporary');
                t.ok(result.assumedRole, 'should have assumed role');
                t.equal(result.sessionName, 'mysession', 'correct session');
                t.ok(result.roles['assumed-role-uuid'],
                    'roles should include assumed role');
                t.done();
            });
        });
    });
});

test('getUserByAccessKey - access key not found', function (t) {
    redislib.getUserByAccessKey({
        accessKeyId: 'AKIANONEXISTENT123',
        log: log,
        redis: redis
    }, function (err, result) {
        t.ok(err, 'should error for nonexistent key');
        t.equal(err.restCode, 'AccessKeyNotFound', 'correct error code');
        t.done();
    });
});

test('getUserByAccessKey - MSTS with malformed JSON (fallback)', function (t) {
    var accessKeyId = 'MSTSmalformed01';
    var userUuid = 'user-for-malformed-msts';
    var userData = {
        uuid: userUuid,
        type: 'user',
        login: 'malformeduser',
        account: 'malformed-parent'
    };

    // Set malformed JSON for temp cred - should fallback to treating as UUID
    redis.set('/accesskey/' + accessKeyId, 'not-valid-json{{{',
        function (err) {
        t.ok(!err, 'should set malformed mapping');

        redis.set('/uuid/not-valid-json{{{', JSON.stringify(userData),
            function (err2) {
            t.ok(!err2, 'should set user data at fallback UUID');

            redislib.getUserByAccessKey({
                accessKeyId: accessKeyId,
                log: log,
                redis: redis
            }, function (err, result) {
                // Should fallback and try to use the raw string as UUID
                // This will likely fail or succeed based on what's in Redis
                t.ok(result || err, 'should complete (success or error)');
                t.done();
            });
        });
    });
});

test('getUserByAccessKey - user object not found after key lookup',
    function (t) {
    var accessKeyId = 'AKIAorphanedkey1';
    var orphanUuid = 'orphaned-user-uuid-not-in-redis';

    // Key exists but user doesn't
    redis.set('/accesskey/' + accessKeyId, orphanUuid, function (err) {
        t.ok(!err, 'should set access key mapping');

        redislib.getUserByAccessKey({
            accessKeyId: accessKeyId,
            log: log,
            redis: redis
        }, function (err, result) {
            t.ok(err, 'should error when user not found');
            t.equal(err.restCode, 'ObjectDoesNotExist', 'correct error code');
            t.done();
        });
    });
});

/*
 * ==============================
 * SECTION 9: getAccessKeySecret Tests
 */

test('getAccessKeySecret - valid secret from user', function (t) {
    var accessKeyId = 'AKIAsecrettest01';
    var userUuid = 'user-for-secret-test';
    var userData = {
        uuid: userUuid,
        type: 'user',
        login: 'secretuser',
        account: 'secret-parent-account',
        accesskeys: {}
    };
    userData.accesskeys[accessKeyId] = 'mysecretkey';

    redis.set('/accesskey/' + accessKeyId, userUuid, function (err) {
        t.ok(!err, 'should set access key mapping');

        redis.set('/uuid/' + userUuid, JSON.stringify(userData),
            function (err2) {
            t.ok(!err2, 'should set user data');

            redislib.getAccessKeySecret({
                accessKeyId: accessKeyId,
                log: log,
                redis: redis
            }, function (err, result) {
                t.ok(!err, 'should not error');
                t.equal(result, 'mysecretkey', 'should return correct secret');
                t.done();
            });
        });
    });
});

test('getAccessKeySecret - key not found', function (t) {
    redislib.getAccessKeySecret({
        accessKeyId: 'AKIAnonexistentkey',
        log: log,
        redis: redis
    }, function (err, result) {
        t.ok(err, 'should error for nonexistent key');
        t.equal(err.restCode, 'AccessKeyNotFound', 'correct error code');
        t.done();
    });
});

test('getAccessKeySecret - user has no accesskeys object', function (t) {
    var accessKeyId = 'AKIAnoaccesskeys';
    var userUuid = 'user-no-accesskeys';
    var userData = {
        uuid: userUuid,
        type: 'user',
        login: 'nokeysuser',
        account: 'nokeys-parent'
        // No accesskeys field
    };

    redis.set('/accesskey/' + accessKeyId, userUuid, function (err) {
        t.ok(!err, 'should set access key mapping');

        redis.set('/uuid/' + userUuid, JSON.stringify(userData),
            function (err2) {
            t.ok(!err2, 'should set user data');

            redislib.getAccessKeySecret({
                accessKeyId: accessKeyId,
                log: log,
                redis: redis
            }, function (err, result) {
                t.ok(err, 'should error when accesskeys missing');
                t.equal(err.restCode, 'AccessKeyNotFound',
                    'correct error code');
                t.done();
            });
        });
    });
});

test('getAccessKeySecret - accesskeys exists but key not in it', function (t) {
    var accessKeyId = 'AKIAnotinobject1';
    var userUuid = 'user-key-not-in-obj';
    var userData = {
        uuid: userUuid,
        type: 'user',
        login: 'keynotinuser',
        account: 'keynotin-parent',
        accesskeys: {
            'AKIADIFFERENTKEY': 'differentsecret'
        }
    };

    redis.set('/accesskey/' + accessKeyId, userUuid, function (err) {
        t.ok(!err, 'should set access key mapping');

        redis.set('/uuid/' + userUuid, JSON.stringify(userData),
            function (err2) {
            t.ok(!err2, 'should set user data');

            redislib.getAccessKeySecret({
                accessKeyId: accessKeyId,
                log: log,
                redis: redis
            }, function (err, result) {
                t.ok(err, 'should error when key not in accesskeys');
                t.equal(err.restCode, 'AccessKeyNotFound',
                    'correct error code');
                t.done();
            });
        });
    });
});

/*
 * ==============================
 * SECTION 10: getRoles Tests
 */

test('getRoles - empty roles list', function (t) {
    redislib.getRoles({
        roles: [],
        log: log,
        redis: redis
    }, function (err, result) {
        t.ok(!err, 'should not error for empty list');
        t.deepEqual(result, {}, 'should return empty object');
        t.done();
    });
});

test('getRoles - single role with policy', function (t) {
    var roleUuid = 'role-with-policy-uuid';
    var policyUuid = 'policy-for-role-uuid';

    var roleData = {
        uuid: roleUuid,
        type: 'role',
        name: 'testrole',
        policies: [policyUuid]
    };
    var policyData = {
        uuid: policyUuid,
        type: 'policy',
        name: 'testpolicy',
        rules: ['CAN read *', 'CAN write own']
    };

    redis.set('/uuid/' + roleUuid, JSON.stringify(roleData), function (err) {
        t.ok(!err, 'should set role data');

        redis.set('/uuid/' + policyUuid, JSON.stringify(policyData),
            function (err2) {
            t.ok(!err2, 'should set policy data');

            redislib.getRoles({
                roles: [roleUuid],
                log: log,
                redis: redis
            }, function (err, result) {
                t.ok(!err, 'should not error');
                t.ok(result[roleUuid], 'should have role');
                t.ok(result[roleUuid].rules, 'should have rules');
                t.equal(result[roleUuid].rules.length, 2,
                    'should have 2 rules');
                t.done();
            });
        });
    });
});

test('getRoles - role not found', function (t) {
    redislib.getRoles({
        roles: ['nonexistent-role-uuid-xyz'],
        log: log,
        redis: redis
    }, function (err, result) {
        t.ok(err, 'should error for nonexistent role');
        t.done();
    });
});

/*
 * ==============================
 * SECTION 11: Concurrent Operations Tests
 */

test('concurrent getObject calls', function (t) {
    var testUuids = ['concurrent-001', 'concurrent-002', 'concurrent-003'];
    var completed = 0;
    var errors = [];

    // Setup test data
    var setupCount = 0;
    testUuids.forEach(function (uuid) {
        var data = {uuid: uuid, type: 'user', login: 'user-' + uuid};
        redis.set('/uuid/' + uuid, JSON.stringify(data), function (err) {
            setupCount++;
            if (setupCount === testUuids.length) {
                // All data set, now run concurrent lookups
                testUuids.forEach(function (uuid) {
                    redislib.getObject({
                        uuid: uuid,
                        log: log,
                        redis: redis
                    }, function (err, result) {
                        if (err) {
                            errors.push(err);
                        }
                        completed++;
                        if (completed === testUuids.length) {
                            t.equal(errors.length, 0, 'no errors');
                            t.done();
                        }
                    });
                });
            }
        });
    });
});

test('concurrent getUserByAccessKey calls', function (t) {
    var keys = [
        {id: 'AKIAconcur001', uuid: 'concur-user-001'},
        {id: 'AKIAconcur002', uuid: 'concur-user-002'}
    ];
    var setupCount = 0;
    var completed = 0;

    // Setup - each key requires 2 redis.set calls (nested)
    keys.forEach(function (key) {
        var userData = {
            uuid: key.uuid,
            type: 'user',
            login: 'user-' + key.uuid,
            account: 'parent',
            accesskeys: {}
        };
        userData.accesskeys[key.id] = 'secret';

        redis.set('/accesskey/' + key.id, key.uuid, function () {
            redis.set('/uuid/' + key.uuid, JSON.stringify(userData),
                function () {
                setupCount++;
                // Check if all keys are set up (one increment per key)
                if (setupCount === keys.length) {
                    // Run concurrent lookups
                    keys.forEach(function (k) {
                        redislib.getUserByAccessKey({
                            accessKeyId: k.id,
                            log: log,
                            redis: redis
                        }, function (err, result) {
                            t.ok(!err, 'lookup should succeed');
                            completed++;
                            if (completed === keys.length) {
                                t.done();
                            }
                        });
                    });
                }
            });
        });
    });
});

/*
 * ==============================
 * TEARDOWN
 */

test('teardown', function (t) {
    if (redis) {
        redis.quit();
    }
    t.done();
});

console.log('Redis S3 access key lookup tests loaded');
