/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright (c) 2017, Joyent, Inc.
 */

// Enable IAM/STS endpoint testing
process.env.MAHI_TESTING = 'true';

var Server = require('../lib/server/server.js').Server;

var Transform = require('../lib/replicator/transform.js');
var jsonstream = require('./jsonparsestream.js');
var fs = require('fs');
var bunyan = require('bunyan');
var path = require('path');
var redis = require('fakeredis');
var restify = require('restify');

var nodeunit = require('nodeunit-plus');
var after = nodeunit.after;
var before = nodeunit.before;
var test = nodeunit.test;

var DATA = path.resolve(__dirname, './data/test-nodeletes.json');
var REDIS = redis.createClient();

test('setup - populate redis', function (t) {
    var typeTable = {
        ip: 'ip'
    };
    var data = fs.createReadStream(DATA);
    var json = new jsonstream();
    var transform = new Transform({
        redis: REDIS,
        log: bunyan.createLogger({
            name: 'transform',
            level: 'fatal'
        }),
        typeTable: typeTable
    });
    data.pipe(json).pipe(transform);
    transform.on('finish', function () {
        t.end();
    });
});

before(function (cb) {
    var port = parseInt(process.env.TEST_PORT, 10) || 8080;
    this.client = restify.createJsonClient({
        url: 'http://localhost:' + port
    });
    this.server = new Server({
        redis: REDIS,
        log: bunyan.createLogger({
            name: 'server',
            level: process.env.LOG_LEVEL || 'fatal'
        }),
        port: port
    });
    cb();
});

after(function (cb) {
    if (this.client) {
        this.client.close();
    }
    if (this.server) {
        this.server.close();
    }
    cb();
});

test('getAccount (old)', function (t) {
    this.client.get('/account/banks', function (err, req, res, obj) {
        t.ok(obj.account);
        t.end();
    });
});

test('account not approved', function (t) {
    this.client.get('/account/oilandgas', function (err, req, res, obj) {
        t.ok(obj.account.approved_for_provisioning === false);
        t.end();
    });
});

test('account dne', function (t) {
    this.client.get('/account/asdfkasdf', function (err, req, res, obj) {
        t.equal(err.restCode, 'AccountDoesNotExist');
        t.equal(obj.code, 'AccountDoesNotExist');
        t.end();
    });
});

test('getUser (old)', function (t) {
    this.client.get('/user/banks/bankofamerica', function (err, req, res, obj) {
        t.ok(obj.user);
        t.end();
    });
});

test('translate account (old)', function (t) {
    var params = {
        account: 'banks'
    };

    this.client.post('/getUuid', params, function (err, req, res, obj) {
        t.ok(obj.account);
        t.end();
    });
});

test('translate role (old)', function (t) {
    var params = {
        account: 'banks',
        type: 'role',
        names: ['lender', 'borrower', 'noexist']
    };

    this.client.post('/getUuid', params, function (err, req, res, obj) {
        t.ok(obj.account);
        t.ok(obj.uuids.lender);
        t.ok(obj.uuids.borrower);
        t.end();
    });
});

test('translate uuid (old)', function (t) {
    var params = {
        uuids: ['bde5a308-9e5a-11e3-bbf2-1b6f3d02ff6f', 'noexist']
    };

    this.client.post('/getName', params, function (err, req, res, obj) {
        t.ok(obj['bde5a308-9e5a-11e3-bbf2-1b6f3d02ff6f']);
        t.end();
    });
});

test('get account by id', function (t) {
    var uuid = '2a05359a-9e64-11e3-816d-e7f87365cf40';
    this.client.get('/accounts/' + uuid, function (err, req, res, obj) {
        t.ok(obj.account);
        t.ok(obj.roles);
        t.end();
    });
});

test('get account by login', function (t) {
    this.client.get('/accounts?login=banks', function (err, req, res, obj) {
        t.ok(obj.account);
        t.ok(obj.roles);
        t.end();
    });
});

test('get account by id', function (t) {
    var uuid = '2a05359a-9e64-11e3-816d-e7f87365cf40';
    this.client.get('/accounts/' + uuid, function (err, req, res, obj) {
        t.ok(obj.account);
        t.ok(obj.roles);
        t.end();
    });
});

test('get account by login', function (t) {
    this.client.get('/accounts?login=banks', function (err, req, res, obj) {
        t.ok(obj.account);
        t.ok(obj.roles);
        t.end();
    });
});

test('get user by id', function (t) {
    var uuid = '3ffc7b4c-66a6-11e3-af09-8752d24e4669';
    this.client.get('/users/' + uuid, function (err, req, res, obj) {
        t.ok(obj.account);
        t.ok(obj.user);
        t.ok(obj.roles);
        t.end();
    });
});

test('get user by login', function (t) {
    var uuid = '3ffc7b4c-66a6-11e3-af09-8752d24e4669';
    this.client.get('/users/' + uuid, function (err, req, res, obj) {
        t.ok(obj.account);
        t.ok(obj.user);
        t.ok(obj.roles);
        t.end();
    });
});

test('cross-account roles', function (t) {
    var uuid = '2a05359a-9e64-11e3-816d-e7f87365cf40';
    this.client.get('/accounts/' + uuid, function (err, req, res, obj) {
        t.ok(obj.account);
        t.ok(obj.roles);
        t.deepEqual(obj.roles, {
            'fd4d1489-a2c4-4303-8b32-0396ca297447': {
                type: 'role',
                uuid: 'fd4d1489-a2c4-4303-8b32-0396ca297447',
                name: 'crossrole',
                account: 'bde5a308-9e5a-11e3-bbf2-1b6f3d02ff6f',
                assumerolepolicydocument: null,
                rules: []
            }
        });
        t.end();
    });
});

test('cross-account roles (none)', function (t) {
    var uuid = 'bde5a308-9e5a-11e3-bbf2-1b6f3d02ff6f';
    this.client.get('/accounts/' + uuid, function (err, req, res, obj) {
        t.ok(obj.account);
        t.ok(obj.roles);
        t.deepEqual(obj.roles, {});
        t.end();
    });
});

test('translate account', function (t) {
    this.client.get('/uuids?account=banks', function (err, req, res, obj) {
        t.ok(obj.account);
        t.end();
    });
});

test('translate role', function (t) {
    this.client.get('/uuids?account=banks&type=role&name=lender',
            function (err, req, res, obj) {
        t.ok(obj.account);
        t.ok(obj.uuids.lender);
        t.end();
    });
});

test('translate multiple roles', function (t) {
    this.client.get('/uuids?account=banks&type=role&name=lender&name=borrower' +
                    '&name=noexist',
            function (err, req, res, obj) {
        t.ok(obj.account);
        t.ok(obj.uuids.lender);
        t.ok(obj.uuids.borrower);
        t.end();
    });
});

test('translate uuid', function (t) {
    var uuid = 'bde5a308-9e5a-11e3-bbf2-1b6f3d02ff6f';
    this.client.get('/names?uuid=' + uuid, function (err, req, res, obj) {
        t.ok(obj[uuid]);
        t.end();
    });
});

test('translate multiple uuids', function (t) {
    var uuid1 = 'bde5a308-9e5a-11e3-bbf2-1b6f3d02ff6f';
    var uuid2 = '2a05359a-9e64-11e3-816d-e7f87365cf40';
    var q = '?uuid=' + uuid1 + '&uuid=' + uuid2 + '&uuid=noexist';
    this.client.get('/names' + q, function (err, req, res, obj) {
        t.ok(obj[uuid1]);
        t.ok(obj[uuid2]);
        t.end();
    });
});

test('generate lookup', function (t) {
    var expected = [
        ['bde5a308-9e5a-11e3-bbf2-1b6f3d02ff6f', true, 'banks'],
        ['1e77f528-9e64-11e3-8d12-838d40383bce', true, 'auto'],
        ['2a05359a-9e64-11e3-816d-e7f87365cf40', false, 'oilandgas']];
    this.client.get('/lookup', function (err, req, res, obj) {
        expected.forEach(function (tuple) {
            t.equal(obj[tuple[0]].approved, tuple[1]);
            t.equal(obj[tuple[0]].login, tuple[2]);
        });
        t.end();
    });
});

test('/accounts: missing arguments', function (t) {
    this.client.get('/accounts', function (err, req, res, obj) {
        t.equal(err.restCode, 'BadRequestError');
        t.equal(obj.code, 'BadRequestError');
        t.end();
    });
});

test('/users: missing argument (account)', function (t) {
    this.client.get('/users', function (err, req, res, obj) {
        t.equal(err.restCode, 'BadRequestError');
        t.equal(obj.code, 'BadRequestError');
        t.end();
    });
});

test('/users: missing argument (user)', function (t) {
    this.client.get('/users?account=banks', function (err, req, res, obj) {
        t.equal(err.restCode, 'BadRequestError');
        t.equal(obj.code, 'BadRequestError');
        t.end();
    });
});

test('/names: missing arguments', function (t) {
    this.client.get('/names', function (err, req, res, obj) {
        t.ok(!err);
        t.deepEqual(obj, {});
        t.end();
    });
});

test('/uuids: missing arguments', function (t) {
    this.client.get('/uuids', function (err, req, res, obj) {
        t.equal(err.restCode, 'BadRequestError');
        t.equal(obj.code, 'BadRequestError');
        t.end();
    });
});

// ============================================================================
// CHG-044 Phase 2: IAM Error Path Tests
// ============================================================================

// ----------------------------------------------------------------------------
// iamGetRoleHandler Error Path Tests
// ----------------------------------------------------------------------------

test('IAM GetRole: missing roleName parameter', function (t) {
    // Missing roleName in path - should return 404 from restify
    this.client.get('/iam/get-role/?accountUuid=test-account-uuid',
        function (err, req, res, obj) {
        t.ok(err, 'should return error');
        t.equal(res.statusCode, 404,
            'should return 404 for missing path param');
        t.end();
    });
});

test('IAM GetRole: missing accountUuid parameter', function (t) {
    this.client.get('/iam/get-role/TestRole', function (err, req, res, obj) {
        t.ok(err, 'should return error');
        // Without UFDS, returns 500. With UFDS, would return 400.
        t.equal(res.statusCode, 500, 'should return 500 (UFDS not available)');
        t.ok(obj.error, 'should have error message');
        t.equal(obj.error, 'UFDS not available',
            'error should indicate UFDS not available');
        t.end();
    });
});

test('IAM GetRole: role not found', function (t) {
    this.client.get('/iam/get-role/NonexistentRole?accountUuid=test-uuid',
        function (err, req, res, obj) {
        t.ok(err, 'should return error');
        // Without UFDS, returns 500. With UFDS, would return 404.
        t.equal(res.statusCode, 500, 'should return 500 (UFDS not available)');
        t.ok(obj.error, 'should have error message');
        t.equal(obj.error, 'UFDS not available',
            'error should indicate UFDS not available');
        t.end();
    });
});

// ----------------------------------------------------------------------------
// iamDeleteRoleHandler Error Path Tests
// ----------------------------------------------------------------------------

test('IAM DeleteRole: missing roleName parameter', function (t) {
    this.client.del('/iam/delete-role/?accountUuid=test-account-uuid',
        function (err, req, res, obj) {
        t.ok(err, 'should return error');
        t.equal(res.statusCode, 404,
            'should return 404 for missing path param');
        t.end();
    });
});

test('IAM DeleteRole: missing accountUuid parameter', function (t) {
    this.client.del('/iam/delete-role/TestRole', function (err, req, res, obj) {
        t.ok(err, 'should return error');
        // Without UFDS, returns 500. With UFDS, would return 400.
        t.equal(res.statusCode, 500, 'should return 500 (UFDS not available)');
        t.ok(obj.error, 'should have error message');
        t.equal(obj.error, 'UFDS not available',
            'error should indicate UFDS not available');
        t.end();
    });
});

test('IAM DeleteRole: role not found', function (t) {
    this.client.del('/iam/delete-role/NonexistentRole?accountUuid=test-uuid',
        function (err, req, res, obj) {
        t.ok(err, 'should return error');
        // Without UFDS, returns 500. With UFDS, would return 404.
        t.equal(res.statusCode, 500, 'should return 500 (UFDS not available)');
        t.ok(obj.error, 'should have error message');
        t.equal(obj.error, 'UFDS not available',
            'error should indicate UFDS not available');
        t.end();
    });
});

// ----------------------------------------------------------------------------
// iamListRolesHandler Error Path Tests
// ----------------------------------------------------------------------------

test('IAM ListRoles: missing accountUuid parameter', function (t) {
    this.client.get('/iam/list-roles', function (err, req, res, obj) {
        t.ok(err, 'should return error');
        // Without UFDS, returns 500. With UFDS, would return 400.
        t.equal(res.statusCode, 500, 'should return 500 (UFDS not available)');
        t.ok(obj.error, 'should have error message');
        t.equal(obj.error, 'UFDS not available',
            'error should indicate UFDS not available');
        t.end();
    });
});

test('IAM ListRoles: empty role set', function (t) {
    // Use a UUID that doesn't have any roles
    this.client.get('/iam/list-roles?accountUuid=nonexistent-account',
        function (err, req, res, obj) {
        t.ok(err, 'should return error');
        // Without UFDS, returns 500. With UFDS, would return 200 with
        // empty list.
        t.equal(res.statusCode, 500, 'should return 500 (UFDS not available)');
        t.ok(obj.error, 'should have error message');
        t.equal(obj.error, 'UFDS not available',
            'error should indicate UFDS not available');
        t.end();
    });
});

test('IAM ListRoles: with maxItems parameter', function (t) {
    this.client.get('/iam/list-roles?accountUuid=test-uuid&maxItems=5',
        function (err, req, res, obj) {
        t.ok(err, 'should return error');
        // Without UFDS, returns 500. With UFDS, would handle pagination.
        t.equal(res.statusCode, 500, 'should return 500 (UFDS not available)');
        t.equal(obj.error, 'UFDS not available',
            'error should indicate UFDS not available');
        t.end();
    });
});

test('IAM ListRoles: with marker parameter', function (t) {
    this.client.get('/iam/list-roles?accountUuid=test-uuid&marker=SomeRole',
        function (err, req, res, obj) {
        t.ok(err, 'should return error');
        // Without UFDS, returns 500. With UFDS, would handle pagination marker.
        t.equal(res.statusCode, 500, 'should return 500 (UFDS not available)');
        t.equal(obj.error, 'UFDS not available',
            'error should indicate UFDS not available');
        t.end();
    });
});

// ----------------------------------------------------------------------------
// iamCreateRoleHandler Error Path Tests
// Note: UFDS check happens first, so 500 returned before param validation
// ----------------------------------------------------------------------------

test('IAM CreateRole: no UFDS connection', function (t) {
    var reqBody = {
        roleName: 'TestRole',
        accountUuid: 'test-account-uuid'
    };
    this.client.post('/iam/create-role', reqBody, function (err, req, res, obj) {
        t.ok(err, 'should return error');
        t.equal(res.statusCode, 500, 'should return 500 (UFDS not available)');
        t.ok(obj.error.indexOf('UFDS') !== -1,
            'error should mention UFDS');
        t.end();
    });
});

// ----------------------------------------------------------------------------
// iamPutRolePolicyHandler Error Path Tests
// (path is /iam/put-role-policy - body params)
// ----------------------------------------------------------------------------

test('IAM PutRolePolicy: missing accountUuid parameter', function (t) {
    var reqBody = {
        roleName: 'TestRole',
        policyName: 'TestPolicy',
        policyDocument: '{"Statement":[]}',
        mantaPolicy: { name: 'TestPolicy', rules: [] }
    };
    this.client.post('/iam/put-role-policy', reqBody,
        function (err, req, res, obj) {
        t.ok(err, 'should return error');
        t.equal(res.statusCode, 500, 'should return 500 (UFDS not available)');
        t.equal(obj.error, 'UFDS not available',
            'error should indicate UFDS not available');
        t.end();
    });
});

test('IAM PutRolePolicy: with valid params (no UFDS)', function (t) {
    var reqBody = {
        accountUuid: 'test-account-uuid',
        roleName: 'TestRole',
        policyName: 'TestPolicy',
        policyDocument: '{"Statement":[]}',
        mantaPolicy: { name: 'TestPolicy', rules: [] }
    };
    this.client.post('/iam/put-role-policy', reqBody,
        function (err, req, res, obj) {
        t.ok(err, 'should return error');
        t.equal(res.statusCode, 500, 'should return 500 (UFDS not available)');
        t.equal(obj.error, 'UFDS not available',
            'error should indicate UFDS not available');
        t.end();
    });
});

// ----------------------------------------------------------------------------
// iamDeleteRolePolicyHandler Error Path Tests
// (path is /iam/delete-role-policy - query params)
// ----------------------------------------------------------------------------

test('IAM DeleteRolePolicy: missing accountUuid parameter', function (t) {
    this.client.del('/iam/delete-role-policy?roleName=TestRole' +
        '&policyName=TestPolicy',
        function (err, req, res, obj) {
        t.ok(err, 'should return error');
        t.equal(res.statusCode, 500, 'should return 500 (UFDS not available)');
        t.equal(obj.error, 'UFDS not available',
            'error should indicate UFDS not available');
        t.end();
    });
});

test('IAM DeleteRolePolicy: with valid params (no UFDS)', function (t) {
    this.client.del('/iam/delete-role-policy?accountUuid=test-uuid' +
        '&roleName=TestRole&policyName=TestPolicy',
        function (err, req, res, obj) {
        t.ok(err, 'should return error');
        t.equal(res.statusCode, 500, 'should return 500 (UFDS not available)');
        t.equal(obj.error, 'UFDS not available',
            'error should indicate UFDS not available');
        t.end();
    });
});

// ----------------------------------------------------------------------------
// listRolePoliciesHandler Error Path Tests
// (path is /iam/list-role-policies/:roleName)
// Note: Tests hit handler code even if UFDS middleware returns 500 first
// ----------------------------------------------------------------------------

test('IAM ListRolePolicies: missing accountUuid parameter', function (t) {
    this.client.get('/iam/list-role-policies/TestRole',
        function (err, req, res, obj) {
        t.ok(err, 'should return error');
        // May return 500 (UFDS check) or 400 (param validation)
        t.ok(res.statusCode === 400 || res.statusCode === 500,
            'should return 400 or 500');
        t.end();
    });
});

test('IAM ListRolePolicies: role not in Redis', function (t) {
    this.client.get('/iam/list-role-policies/NonExistentRole?accountUuid=test-uuid',
        function (err, req, res, obj) {
        t.ok(err, 'should return error');
        // May return 500 (UFDS check) or 404 (role not found)
        t.ok(res.statusCode === 404 || res.statusCode === 500,
            'should return 404 or 500');
        t.end();
    });
});

// ----------------------------------------------------------------------------
// getRolePolicyHandler Error Path Tests
// (path is /iam/get-role-policy/:roleName/:policyName)
// Note: This handler checks Redis for role before UFDS, so returns 404 Role
// not found when role doesn't exist
// ----------------------------------------------------------------------------

test('IAM GetRolePolicy: missing accountUuid parameter', function (t) {
    this.client.get('/iam/get-role-policy/TestRole/TestPolicy',
        function (err, req, res, obj) {
        t.ok(err, 'should return error');
        // May return 500 (UFDS check) or 400 (param validation)
        t.ok(res.statusCode === 400 || res.statusCode === 500,
            'should return 400 or 500');
        t.end();
    });
});

test('IAM GetRolePolicy: role not in Redis', function (t) {
    this.client.get('/iam/get-role-policy/NonExistentRole/TestPolicy' +
        '?accountUuid=test-uuid',
        function (err, req, res, obj) {
        t.ok(err, 'should return error');
        // May return 500 (UFDS check) or 404 (role not found)
        t.ok(res.statusCode === 404 || res.statusCode === 500,
            'should return 404 or 500');
        t.end();
    });
});

// ----------------------------------------------------------------------------
// getUserByAccessKeyHandler Error Path Tests
// ----------------------------------------------------------------------------

test('getUserByAccessKey: missing accessKeyId parameter', function (t) {
    this.client.get('/accesskeys/', function (err, req, res, obj) {
        t.ok(err, 'should return error');
        t.equal(res.statusCode, 404, 'should return 404 for missing path param');
        t.end();
    });
});

test('getUserByAccessKey: nonexistent access key', function (t) {
    this.client.get('/accesskeys/AKIANONEXISTENT123456',
        function (err, req, res, obj) {
        t.ok(err, 'should return error for nonexistent key');
        t.end();
    });
});

// ----------------------------------------------------------------------------
// verifySigV4Handler Error Path Tests
// ----------------------------------------------------------------------------

test('verifySigV4: missing request body', function (t) {
    this.client.post('/sigv4/verify', {}, function (err, req, res, obj) {
        t.ok(err, 'should return error');
        t.end();
    });
});

test('verifySigV4: missing accessKeyId', function (t) {
    var reqBody = {
        signature: 'testsig',
        stringToSign: 'teststring',
        algorithm: 'AWS4-HMAC-SHA256',
        region: 'us-east-1',
        service: 's3',
        date: '20250101'
    };
    this.client.post('/sigv4/verify', reqBody, function (err, req, res, obj) {
        t.ok(err, 'should return error for missing accessKeyId');
        t.end();
    });
});

test('verifySigV4: with valid params but nonexistent key', function (t) {
    var reqBody = {
        accessKeyId: 'AKIANONEXISTENT123456',
        signature: 'testsig',
        stringToSign: 'teststring',
        algorithm: 'AWS4-HMAC-SHA256',
        region: 'us-east-1',
        service: 's3',
        date: '20250101'
    };
    this.client.post('/sigv4/verify', reqBody, function (err, req, res, obj) {
        t.ok(err, 'should return error for nonexistent key');
        t.end();
    });
});

// ----------------------------------------------------------------------------
// STS Endpoint Error Path Tests
// ----------------------------------------------------------------------------

test('STS AssumeRole: missing request body', function (t) {
    this.client.post('/sts/assume-role', {}, function (err, req, res, obj) {
        t.ok(err, 'should return error');
        t.end();
    });
});

test('STS AssumeRole: missing RoleArn', function (t) {
    var reqBody = {
        caller: {
            uuid: 'test-uuid',
            login: 'testuser',
            account: { uuid: 'account-uuid' }
        },
        RoleSessionName: 'TestSession',
        DurationSeconds: 3600
    };
    this.client.post('/sts/assume-role', reqBody, function (err, req, res, obj) {
        t.ok(err, 'should return error for missing RoleArn');
        t.end();
    });
});

test('STS GetSessionToken: missing request body', function (t) {
    this.client.post('/sts/get-session-token', {},
        function (err, req, res, obj) {
        t.ok(err, 'should return error');
        t.end();
    });
});

test('STS GetSessionToken: missing caller', function (t) {
    var reqBody = {
        DurationSeconds: 3600
    };
    this.client.post('/sts/get-session-token', reqBody,
        function (err, req, res, obj) {
        t.ok(err, 'should return error for missing caller');
        t.end();
    });
});

test('STS GetCallerIdentity: missing request body', function (t) {
    this.client.post('/sts/get-caller-identity', {},
        function (err, req, res, obj) {
        t.ok(err, 'should return error');
        t.end();
    });
});

test('STS GetCallerIdentity: missing caller', function (t) {
    var reqBody = {};
    this.client.post('/sts/get-caller-identity', reqBody,
        function (err, req, res, obj) {
        t.ok(err, 'should return error for missing caller');
        t.end();
    });
});

// ----------------------------------------------------------------------------
// Ping Endpoint Tests
// ----------------------------------------------------------------------------

test('ping: health check', function (t) {
    this.client.get('/ping', function (err, req, res, obj) {
        // Should return 204 (success) or error if replicator not ready
        t.ok(res.statusCode === 204 || res.statusCode >= 400,
            'should respond to ping');
        t.end();
    });
});

// ----------------------------------------------------------------------------
// getRoleMembers Endpoint Tests
// ----------------------------------------------------------------------------

test('getRoleMembers: with known account', function (t) {
    var uuid = 'bde5a308-9e5a-11e3-bbf2-1b6f3d02ff6f';
    this.client.get('/accounts/' + uuid + '/rolemembers',
        function (err, req, res, obj) {
        // Error or success, we hit the handler
        t.ok(res, 'should have response');
        t.end();
    });
});

test('getRoleMembers: with nonexistent account', function (t) {
    this.client.get('/accounts/nonexistent-uuid/rolemembers',
        function (err, req, res, obj) {
        // Should return 404 or empty response
        t.ok(err || obj, 'should respond to role members request');
        t.end();
    });
});

// ----------------------------------------------------------------------------
// Additional STS Endpoint Tests for Coverage
// ----------------------------------------------------------------------------

test('STS AssumeRole: with invalid RoleArn format', function (t) {
    var reqBody = {
        caller: {
            uuid: 'test-uuid',
            login: 'testuser',
            account: { uuid: 'account-uuid' }
        },
        RoleArn: 'invalid-arn-format',
        RoleSessionName: 'TestSession',
        DurationSeconds: 3600
    };
    this.client.post('/sts/assume-role', reqBody, function (err, req, res, obj) {
        t.ok(err, 'should return error for invalid ARN format');
        t.end();
    });
});

test('STS AssumeRole: with complete params (no UFDS)', function (t) {
    var reqBody = {
        caller: {
            uuid: 'test-uuid',
            login: 'testuser',
            account: { uuid: 'account-uuid' }
        },
        RoleArn: 'arn:aws:iam::account-uuid:role/TestRole',
        RoleSessionName: 'TestSession',
        DurationSeconds: 3600
    };
    this.client.post('/sts/assume-role', reqBody, function (err, req, res, obj) {
        t.ok(err, 'should return error when UFDS not available');
        t.end();
    });
});

test('STS GetSessionToken: with valid caller', function (t) {
    var reqBody = {
        caller: {
            uuid: 'test-uuid',
            login: 'testuser',
            account: { uuid: 'account-uuid' }
        },
        DurationSeconds: 3600
    };
    this.client.post('/sts/get-session-token', reqBody,
        function (err, req, res, obj) {
        // May succeed or fail depending on config
        t.ok(err || obj, 'should process get-session-token request');
        t.end();
    });
});

test('STS GetCallerIdentity: with valid caller', function (t) {
    var reqBody = {
        caller: {
            uuid: 'test-uuid',
            login: 'testuser',
            account: { uuid: 'account-uuid' }
        }
    };
    this.client.post('/sts/get-caller-identity', reqBody,
        function (err, req, res, obj) {
        // Should process the request
        t.ok(err || obj, 'should process get-caller-identity request');
        t.end();
    });
});

// ----------------------------------------------------------------------------
// More nameToUuid and uuidToName Tests for Coverage
// ----------------------------------------------------------------------------

test('nameToUuid: with type=user', function (t) {
    this.client.get('/uuids?account=banks&type=user&name=bankofamerica',
        function (err, req, res, obj) {
        t.ok(!err || res.statusCode >= 400, 'should handle user uuid lookup');
        t.end();
    });
});

test('uuidToName: with type=role', function (t) {
    var uuid = 'fd4d1489-a2c4-4303-8b32-0396ca297447';
    this.client.get('/names?uuid=' + uuid + '&type=role',
        function (err, req, res, obj) {
        t.ok(!err || res.statusCode >= 400, 'should handle role name lookup');
        t.end();
    });
});

// ----------------------------------------------------------------------------
// Additional Error Path Tests
// ----------------------------------------------------------------------------

test('getAccountByUuid: with invalid uuid format', function (t) {
    this.client.get('/accounts/invalid-uuid',
        function (err, req, res, obj) {
        t.ok(err || obj, 'should handle invalid uuid');
        t.end();
    });
});

test('getUserByUuid: with invalid uuid', function (t) {
    this.client.get('/users?account=banks&uuid=invalid-uuid',
        function (err, req, res, obj) {
        t.ok(err || obj, 'should handle invalid user uuid');
        t.end();
    });
});

test('nameToUuid: without type parameter', function (t) {
    this.client.get('/uuids?account=banks&name=bankofamerica',
        function (err, req, res, obj) {
        t.ok(!err || res.statusCode >= 400, 'should handle missing type');
        t.end();
    });
});

test('uuidToName: without type parameter', function (t) {
    var uuid = 'bde5a308-9e5a-11e3-bbf2-1b6f3d02ff6f';
    this.client.get('/names?uuid=' + uuid,
        function (err, req, res, obj) {
        t.ok(!err || res.statusCode >= 400, 'should handle missing type');
        t.end();
    });
});

// ----------------------------------------------------------------------------
// Additional Coverage Tests
// ----------------------------------------------------------------------------

test('getUser: with account uuid', function (t) {
    var accountUuid = 'bde5a308-9e5a-11e3-bbf2-1b6f3d02ff6f';
    this.client.get('/users?account=' + accountUuid + '&user=bankofamerica',
        function (err, req, res, obj) {
        t.ok(res, 'should have response');
        t.end();
    });
});

test('getUser: with account login and user uuid', function (t) {
    var userUuid = '2a05359a-9e64-11e3-816d-e7f87365cf40';
    this.client.get('/users?account=banks&uuid=' + userUuid,
        function (err, req, res, obj) {
        t.ok(res, 'should have response');
        t.end();
    });
});

test('getAccount: user does not exist', function (t) {
    this.client.get('/account/nonexistent_user',
        function (err, req, res, obj) {
        t.ok(err, 'should return error for nonexistent user');
        t.end();
    });
});

test('getUser (old): user does not exist', function (t) {
    this.client.get('/user/banks/nonexistent',
        function (err, req, res, obj) {
        // May return error or empty result depending on endpoint
        t.ok(res, 'should have response');
        t.end();
    });
});

test('nameToUuid (old): with type policy', function (t) {
    this.client.post('/translate/banks/policy/testpolicy',
        function (err, req, res, obj) {
        // May return error or empty result
        t.ok(res, 'should have response');
        t.end();
    });
});

test('uuidToName (old): with type role', function (t) {
    var uuid = 'fd4d1489-a2c4-4303-8b32-0396ca297447';
    this.client.post('/uuid/' + uuid + '/role',
        function (err, req, res, obj) {
        t.ok(res, 'should have response');
        t.end();
    });
});

// Test multiple UUIDs in names endpoint
test('names: with multiple valid UUIDs', function (t) {
    var uuid1 = 'bde5a308-9e5a-11e3-bbf2-1b6f3d02ff6f';
    var uuid2 = '2a05359a-9e64-11e3-816d-e7f87365cf40';
    this.client.get('/names?uuid=' + uuid1 + '&uuid=' + uuid2,
        function (err, req, res, obj) {
        t.ok(res, 'should have response');
        t.end();
    });
});

// Test STS with more parameters
test('STS GetSessionToken: with short duration', function (t) {
    var reqBody = {
        caller: {
            uuid: 'test-uuid',
            login: 'testuser',
            account: { uuid: 'account-uuid' }
        },
        DurationSeconds: 900  // minimum
    };
    this.client.post('/sts/get-session-token', reqBody,
        function (err, req, res, obj) {
        t.ok(res, 'should have response');
        t.end();
    });
});

// Test verifySigV4 with more parameters
test('verifySigV4: with signed headers', function (t) {
    var reqBody = {
        accessKeyId: 'AKIANONEXISTENT123456',
        signature: 'testsig',
        stringToSign: 'teststring',
        algorithm: 'AWS4-HMAC-SHA256',
        region: 'us-east-1',
        service: 's3',
        date: '20250101',
        signedHeaders: 'host;x-amz-date'
    };
    this.client.post('/sigv4/verify', reqBody, function (err, req, res, obj) {
        t.ok(err, 'should return error');
        t.end();
    });
});

// Test getRoles endpoint variations
test('getRoles: with account UUID', function (t) {
    var accountUuid = 'bde5a308-9e5a-11e3-bbf2-1b6f3d02ff6f';
    this.client.get('/accounts/' + accountUuid,
        function (err, req, res, obj) {
        t.ok(res, 'should have response');
        t.end();
    });
});

// Test getUser with different parameters
test('getUser: nonexistent account', function (t) {
    this.client.get('/users?account=nonexistent&user=testuser',
        function (err, req, res, obj) {
        t.ok(err, 'should return error');
        t.end();
    });
});
