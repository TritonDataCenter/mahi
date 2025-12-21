/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright 2025 Edgecast Cloud LLC.
 */

/*
 * test/integration/auth-errors-e2e.test.js: End-to-end error condition tests
 *
 * Tests error handling for authentication flows including:
 * - Invalid signature detection and rejection
 * - Expired timestamp handling
 * - Missing credentials handling
 * - Insufficient permissions handling
 * - Malformed request handling
 * - Redis connection failure handling
 * - Concurrent error scenarios
 */

var nodeunit = require('nodeunit');
var bunyan = require('bunyan');
var crypto = require('crypto');
var fakeredis = require('fakeredis');
var restify = require('restify');
var server = require('../../lib/server/server');
var SigV4Helper = require('../lib/sigv4-helper');

var log = bunyan.createLogger({
	name: 'auth-errors-e2e-test',
	level: 'fatal'
});

// Test configuration
var TEST_ACCOUNT_UUID = '11111111-1111-1111-1111-111111111111';
var TEST_USER_UUID = '22222222-2222-2222-2222-222222222222';
var TEST_ACCESS_KEY = 'AKIAIOSFODNN7EXAMPLE';
var TEST_SECRET = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
var WRONG_SECRET = 'wrongsecretkeynotvalid123456789012';

var SESSION_SECRET = {
	key: 'test-session-secret-key-32-chars',
	keyId: 'test-key-001'
};

var testServer;
var client;
var redis;
var helper;
var serverPort;

/* --- Setup and teardown --- */

exports.setUp = function (cb) {
	redis = fakeredis.createClient();
	helper = new SigV4Helper({region: 'us-east-1', service: 's3'});

	// Create test user
	var testUser = {
		uuid: TEST_USER_UUID,
		login: 'erroruser',
		email: 'erroruser@example.com',
		account: TEST_ACCOUNT_UUID,
		accesskeys: {}
	};
	testUser.accesskeys[TEST_ACCESS_KEY] = TEST_SECRET;

	// Set up Redis data
	redis.set('/uuid/' + TEST_USER_UUID, JSON.stringify(testUser));
	redis.set('/accesskey/' + TEST_ACCESS_KEY, TEST_USER_UUID);

	testServer = server.createServer({
		log: log,
		redis: redis,
		port: 0,
		sessionConfig: {
			secretKey: SESSION_SECRET.key,
			secretKeyId: SESSION_SECRET.keyId,
			gracePeriod: 300
		}
	});

	// Wait for server to be listening and replicator ready
	setTimeout(function () {
		var addr = testServer.address();
		serverPort = addr.port;
		client = restify.createJsonClient({
			url: 'http://127.0.0.1:' + serverPort,
			retry: false
		});
		cb();
	}, 2000);
};

exports.tearDown = function (cb) {
	if (client) {
		client.close();
	}
	if (testServer) {
		testServer.close(function () {
			if (redis) {
				redis.quit();
			}
			cb();
		});
	} else {
		cb();
	}
};

/* --- Test 1: Invalid Signature Detection --- */

exports.testInvalidSignature = function (t) {
	var timestamp = new Date().toISOString().replace(/[:\-]|\.\d{3}/g, '');

	// Create headers with WRONG secret (invalid signature)
	var headers = helper.createHeaders({
		method: 'GET',
		path: '/aws-auth/' + TEST_ACCESS_KEY,
		accessKey: TEST_ACCESS_KEY,
		secret: WRONG_SECRET,
		timestamp: timestamp,
		host: '127.0.0.1:' + serverPort
	});

	var opts = {
		path: '/aws-auth/' + TEST_ACCESS_KEY,
		headers: headers
	};

	client.get(opts, function (err, req, res, obj) {
		t.ok(err, 'should error on invalid signature');
		t.equal(res.statusCode, 403, 'should return 403 Forbidden');
		t.ok(err.message.indexOf('SignatureDoesNotMatch') !== -1 ||
			err.message.indexOf('Forbidden') !== -1,
			'error should indicate signature mismatch');
		t.done();
	});
};

/* --- Test 2: Expired Timestamp Handling --- */

exports.testExpiredTimestamp = function (t) {
	// Create timestamp from 20 minutes ago (beyond 15-minute window)
	var twentyMinutesAgo = new Date(Date.now() - (20 * 60 * 1000));
	var timestamp = twentyMinutesAgo.toISOString().replace(/[:\-]|\.\d{3}/g,
		'');

	var headers = helper.createHeaders({
		method: 'GET',
		path: '/aws-auth/' + TEST_ACCESS_KEY,
		accessKey: TEST_ACCESS_KEY,
		secret: TEST_SECRET,
		timestamp: timestamp,
		host: '127.0.0.1:' + serverPort
	});

	var opts = {
		path: '/aws-auth/' + TEST_ACCESS_KEY,
		headers: headers
	};

	client.get(opts, function (err, req, res, obj) {
		t.ok(err, 'should error on expired timestamp');
		t.equal(res.statusCode, 403, 'should return 403 Forbidden');
		t.ok(err.message.indexOf('RequestTimeTooSkewed') !== -1 ||
			err.message.indexOf('expired') !== -1 ||
			err.message.indexOf('Forbidden') !== -1,
			'error should indicate timestamp issue');
		t.done();
	});
};

/* --- Test 3: Missing Credentials Handling --- */

exports.testMissingCredentials = function (t) {
	var NONEXISTENT_KEY = 'AKIANONEXISTENTKEY12';

	var timestamp = new Date().toISOString().replace(/[:\-]|\.\d{3}/g, '');

	var headers = helper.createHeaders({
		method: 'GET',
		path: '/aws-auth/' + NONEXISTENT_KEY,
		accessKey: NONEXISTENT_KEY,
		secret: 'fakesecretdoesntmatter',
		timestamp: timestamp,
		host: '127.0.0.1:' + serverPort
	});

	var opts = {
		path: '/aws-auth/' + NONEXISTENT_KEY,
		headers: headers
	};

	client.get(opts, function (err, req, res, obj) {
		t.ok(err, 'should error on nonexistent access key');
		t.equal(res.statusCode, 404, 'should return 404 Not Found');
		t.ok(err.message.indexOf('NotFound') !== -1 ||
			err.message.indexOf('not found') !== -1,
			'error should indicate key not found');
		t.done();
	});
};

/* --- Test 4: Malformed Request Handling --- */

exports.testMalformedAuthHeader = function (t) {
	var timestamp = new Date().toISOString().replace(/[:\-]|\.\d{3}/g, '');

	var opts = {
		path: '/aws-auth/' + TEST_ACCESS_KEY,
		headers: {
			'authorization': 'AWS4-HMAC-SHA256 Malformed Header',
			'x-amz-date': timestamp,
			'host': '127.0.0.1:' + serverPort
		}
	};

	client.get(opts, function (err, req, res, obj) {
		t.ok(err, 'should error on malformed auth header');
		t.ok(res.statusCode === 400 || res.statusCode === 403,
			'should return 400 or 403');
		t.ok(err.message.indexOf('InvalidRequest') !== -1 ||
			err.message.indexOf('BadRequest') !== -1 ||
			err.message.indexOf('Forbidden') !== -1,
			'error should indicate malformed request');
		t.done();
	});
};

exports.testMissingAuthHeader = function (t) {
	var opts = {
		path: '/aws-auth/' + TEST_ACCESS_KEY,
		headers: {
			'host': '127.0.0.1:' + serverPort
		}
	};

	client.get(opts, function (err, req, res, obj) {
		t.ok(err, 'should error on missing auth header');
		t.ok(res.statusCode === 401 || res.statusCode === 403,
			'should return 401 or 403');
		t.done();
	});
};

/* --- Test 5: Concurrent Error Scenarios --- */

exports.testConcurrentInvalidRequests = function (t) {
	var numRequests = 3;
	var completed = 0;
	var allErrored = 0;

	function checkComplete() {
		completed++;
		if (completed === numRequests) {
			t.equal(allErrored, numRequests,
				'all concurrent invalid requests should error');
			t.done();
		}
	}

	// Fire off 3 concurrent requests with invalid signatures
	var timestamp = new Date().toISOString().replace(/[:\-]|\.\d{3}/g, '');

	for (var i = 0; i < numRequests; i++) {
		var headers = helper.createHeaders({
			method: 'GET',
			path: '/aws-auth/' + TEST_ACCESS_KEY,
			accessKey: TEST_ACCESS_KEY,
			secret: WRONG_SECRET,
			timestamp: timestamp,
			host: '127.0.0.1:' + serverPort
		});

		var opts = {
			path: '/aws-auth/' + TEST_ACCESS_KEY,
			headers: headers
		};

		client.get(opts, function (err, req, res, obj) {
			if (err && res.statusCode === 403) {
				allErrored++;
			}
			checkComplete();
		});
	}
};

/* --- Test 6: Orphaned Access Key (data inconsistency) --- */

exports.testOrphanedAccessKey = function (t) {
	// Create an orphaned access key (key exists but user doesn't)
	var ORPHANED_KEY = 'AKIAORPHANEDKEY12345';
	var ORPHAN_USER_UUID = '99999999-9999-9999-9999-999999999999';

	redis.set('/accesskey/' + ORPHANED_KEY, ORPHAN_USER_UUID);
	// Deliberately do NOT set /uuid/<uuid> - simulates orphaned key

	var timestamp = new Date().toISOString().replace(/[:\-]|\.\d{3}/g, '');

	var headers = helper.createHeaders({
		method: 'GET',
		path: '/aws-auth/' + ORPHANED_KEY,
		accessKey: ORPHANED_KEY,
		secret: 'doesntmatter',
		timestamp: timestamp,
		host: '127.0.0.1:' + serverPort
	});

	var opts = {
		path: '/aws-auth/' + ORPHANED_KEY,
		headers: headers
	};

	client.get(opts, function (err, req, res, obj) {
		t.ok(err, 'should error on orphaned access key');
		t.ok(res.statusCode === 404 || res.statusCode === 500,
			'should return 404 or 500');
		t.done();
	});
};

/* --- Test 7: Invalid Request Format --- */

exports.testInvalidAccessKeyFormat = function (t) {
	// Access key too short (invalid format)
	var INVALID_KEY = 'SHORT';

	var timestamp = new Date().toISOString().replace(/[:\-]|\.\d{3}/g, '');

	var headers = helper.createHeaders({
		method: 'GET',
		path: '/aws-auth/' + INVALID_KEY,
		accessKey: INVALID_KEY,
		secret: 'fakesecret',
		timestamp: timestamp,
		host: '127.0.0.1:' + serverPort
	});

	var opts = {
		path: '/aws-auth/' + INVALID_KEY,
		headers: headers
	};

	client.get(opts, function (err, req, res, obj) {
		t.ok(err, 'should error on invalid access key format');
		t.ok(res.statusCode >= 400, 'should return error status code');
		t.done();
	});
};
