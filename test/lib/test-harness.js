/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright (c) 2025, Joyent, Inc.
 */

/**
 * Unified Test Harness for Mahi Integration Testing
 *
 * Provides a unified interface for setting up complete test
 * environments with mock UFDS, Redis fixtures, time mocking, and
 * authenticated HTTP clients.
 */

var assert = require('assert-plus');
var bunyan = require('bunyan');
var redis = require('fakeredis');
var restify = require('restify');
var vasync = require('vasync');

var Server = require('../../lib/server/server.js').Server;
var MockUfdsServer = require('./mock-ufds.js');
var RedisFixture = require('./redis-fixtures.js');
var TimeMock = require('./time-mock.js');
var SigV4Helper = require('./sigv4-helper.js');

/**
 * @brief Unified test harness for integration testing
 *
 * Integrates all mock components into a single easy-to-use test
 * harness. Handles setup and teardown of mock UFDS, Redis fixtures,
 * time mocking, Mahi server, and HTTP clients.
 *
 * @constructor
 * @param {object} opts Configuration options
 * @param {object} [opts.log] Bunyan logger (default: fatal level)
 * @param {boolean} [opts.mockUfds] Enable mock UFDS server
 *                                   (default: false)
 * @param {number} [opts.ufdsPort] Mock UFDS port (default: 1389)
 * @param {string} [opts.redisFixture] Redis scenario to load:
 *                 'empty', 'basicAuth', 'stsRoles', 'sigv4Users'
 *                 (default: 'empty')
 * @param {boolean} [opts.timeMock] Enable time mocking
 *                                   (default: false)
 * @param {number} [opts.serverPort] Mahi server port (default: 8080)
 * @param {object} [opts.serverOpts] Additional Mahi server options
 *
 * @example
 * var TestHarness = require('./lib/test-harness');
 *
 * before(function(cb) {
 *     this.harness = new TestHarness({
 *         mockUfds: true,
 *         redisFixture: 'stsRoles',
 *         timeMock: true
 *     });
 *     this.harness.setup(cb);
 * });
 *
 * after(function(cb) {
 *     this.harness.teardown(cb);
 * });
 *
 * test('my test', function(t) {
 *     this.harness.client.get('/accounts/uuid', ...);
 * });
 *
 * @since 1.0.0
 */
function TestHarness(opts) {
    opts = opts || {};
    assert.optionalObject(opts.log, 'opts.log');
    assert.optionalBool(opts.mockUfds, 'opts.mockUfds');
    assert.optionalNumber(opts.ufdsPort, 'opts.ufdsPort');
    assert.optionalString(opts.redisFixture, 'opts.redisFixture');
    assert.optionalBool(opts.timeMock, 'opts.timeMock');
    assert.optionalNumber(opts.serverPort, 'opts.serverPort');
    assert.optionalObject(opts.serverOpts, 'opts.serverOpts');

    this.log = opts.log || bunyan.createLogger({
        name: 'test-harness',
        level: process.env.LOG_LEVEL || 'fatal'
    });

    // Configuration
    this.enableMockUfds = opts.mockUfds || false;
    this.ufdsPort = opts.ufdsPort || 1389;
    this.redisFixture = opts.redisFixture || 'empty';
    this.enableTimeMock = opts.timeMock || false;
    this.serverPort = opts.serverPort || 8080;
    this.serverOpts = opts.serverOpts || {};

    // Components (initialized in setup())
    this.mockUfds = null;
    this.redis = null;
    this.fixtures = null;
    this.time = null;
    this.sigv4 = null;
    this.server = null;
    this.client = null;
}

/**
 * @brief Set up the complete test environment
 *
 * Initializes all enabled components in the correct order: mock UFDS,
 * Redis fixtures, time mocking, Mahi server, and HTTP client.
 *
 * @param {function} callback Callback function (err)
 *
 * @return {void}
 *
 * @note Should be called in nodeunit before() hook
 *
 * @example
 * before(function(cb) {
 *     this.harness.setup(cb);
 * });
 *
 * @since 1.0.0
 */
TestHarness.prototype.setup = function setup(callback) {
    assert.func(callback, 'callback');

    var self = this;

    // Create SigV4 helper (always available)
    self.sigv4 = new SigV4Helper();

    vasync.pipeline({
        funcs: [
            // Step 1: Start mock UFDS if enabled
            function startMockUfds(_, cb) {
                if (!self.enableMockUfds) {
                    return (cb());
                }

                self.mockUfds = new MockUfdsServer({
                    log: self.log,
                    port: self.ufdsPort
                });

                self.mockUfds.start(cb);
            },

            // Step 2: Create Redis client and fixtures
            function createRedis(_, cb) {
                self.redis = redis.createClient();
                self.fixtures = new RedisFixture({
                    redis: self.redis,
                    log: self.log
                });
                cb();
            },

            // Step 3: Load Redis fixture
            function loadFixture(_, cb) {
                self.fixtures.loadScenario(self.redisFixture, cb);
            },

            // Step 4: Enable time mocking if requested
            function enableTimeMock(_, cb) {
                if (!self.enableTimeMock) {
                    return (cb());
                }

                self.time = new TimeMock();
                cb();
            },

            // Step 5: Start Mahi server
            function startServer(_, cb) {
                var serverConfig = {
                    redis: self.redis,
                    log: self.log,
                    port: self.serverPort
                };

                // Merge additional server options
                Object.keys(self.serverOpts).forEach(function (key) {
                    serverConfig[key] = self.serverOpts[key];
                });

                self.server = new Server(serverConfig);
                cb();
            },

            // Step 6: Create HTTP client
            function createClient(_, cb) {
                self.client = restify.createJsonClient({
                    url: 'http://localhost:' + self.serverPort
                });
                cb();
            }
        ]
    }, function (err) {
        if (err) {
            self.log.error({err: err}, 'test harness setup failed');
            return (callback(err));
        }

        self.log.debug('test harness setup complete');
        callback();
    });
};

/**
 * @brief Tear down the test environment
 *
 * Cleans up all resources in reverse order: HTTP client, Mahi server,
 * time mock, Redis, and mock UFDS.
 *
 * @param {function} callback Callback function (err)
 *
 * @return {void}
 *
 * @note Should be called in nodeunit after() hook
 * @note Restores all mocked global state
 *
 * @example
 * after(function(cb) {
 *     this.harness.teardown(cb);
 * });
 *
 * @since 1.0.0
 */
TestHarness.prototype.teardown = function teardown(callback) {
    assert.func(callback, 'callback');

    var self = this;

    vasync.pipeline({
        funcs: [
            // Step 1: Close HTTP client
            function closeClient(_, cb) {
                if (self.client) {
                    self.client.close();
                }
                cb();
            },

            // Step 2: Close Mahi server
            function closeServer(_, cb) {
                if (self.server) {
                    self.server.close();
                }
                cb();
            },

            // Step 3: Restore time mock
            function restoreTime(_, cb) {
                if (self.time) {
                    self.time.restore();
                }
                cb();
            },

            // Step 4: Flush Redis
            function flushRedis(_, cb) {
                if (self.redis) {
                    self.redis.flushdb(cb);
                } else {
                    cb();
                }
            },

            // Step 5: Stop mock UFDS
            function stopMockUfds(_, cb) {
                if (self.mockUfds) {
                    self.mockUfds.stop(cb);
                } else {
                    cb();
                }
            }
        ]
    }, function (err) {
        if (err) {
            self.log.error({err: err}, 'test harness teardown had errors');
        } else {
            self.log.debug('test harness teardown complete');
        }
        callback(err);
    });
};

/**
 * @brief Create test user in Redis
 *
 * Helper method to create a test user with access keys in Redis for
 * authentication testing.
 *
 * @param {object} opts User options
 * @param {string} opts.login User login name
 * @param {string} opts.account Account UUID
 * @param {string} [opts.accessKey] AWS access key ID (auto-generated
 *                                   if not provided)
 * @param {string} [opts.secret] AWS secret key (auto-generated if not
 *                                provided)
 * @param {function} callback Callback function (err, user)
 *
 * @return {void}
 *
 * @note Returns user object with uuid, login, accessKey, secret
 *
 * @example
 * harness.createUser({
 *     login: 'testuser',
 *     account: accountUuid
 * }, function(err, user) {
 *     // user.accessKey and user.secret now available
 * });
 *
 * @since 1.0.0
 */
TestHarness.prototype.createUser = function createUser(opts, callback) {
    assert.object(opts, 'opts');
    assert.string(opts.login, 'opts.login');
    assert.string(opts.account, 'opts.account');
    assert.optionalString(opts.accessKey, 'opts.accessKey');
    assert.optionalString(opts.secret, 'opts.secret');
    assert.func(callback, 'callback');

    var uuid = this._generateUuid();
    var accessKey = opts.accessKey || this._generateAccessKey();
    var secret = opts.secret || this._generateSecret();

    var user = {
        uuid: uuid,
        login: opts.login,
        account: opts.account,
        accessKey: accessKey,
        secret: secret
    };

    // Store in Redis
    var userKey = '/uuid/' + uuid;
    var userData = JSON.stringify({
        uuid: uuid,
        login: opts.login,
        account: opts.account
    });

    var self = this;
    vasync.pipeline({
        funcs: [
            function storeUser(_, cb) {
                self.redis.set(userKey, userData, cb);
            },
            function storeAccessKey(_, cb) {
                var accessKeyData = JSON.stringify({
                    user: uuid,
                    secret: secret
                });
                self.redis.set('/accesskey/' + accessKey, accessKeyData, cb);
            }
        ]
    }, function (err) {
        if (err) {
            return (callback(err));
        }
        callback(null, user);
    });
};

/**
 * @brief Generate random UUID
 *
 * Internal helper to generate test UUIDs.
 *
 * @return {string} UUID string
 *
 * @since 1.0.0
 */
TestHarness.prototype._generateUuid = function _generateUuid() {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g,
        function (c) {
        var r = Math.random() * 16 | 0;
        var v = c === 'x' ? r : (r & 0x3 | 0x8);
        return (v.toString(16));
    });
};

/**
 * @brief Generate random AWS access key ID
 *
 * Internal helper to generate test access keys.
 *
 * @return {string} Access key ID
 *
 * @since 1.0.0
 */
TestHarness.prototype._generateAccessKey = function _generateAccessKey() {
    var chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    var key = 'AKIA';
    for (var i = 0; i < 16; i++) {
        key += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return (key);
};

/**
 * @brief Generate random secret key
 *
 * Internal helper to generate test secret keys.
 *
 * @return {string} Secret key
 *
 * @since 1.0.0
 */
TestHarness.prototype._generateSecret = function _generateSecret() {
    var chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz' +
        '0123456789+/';
    var secret = '';
    for (var i = 0; i < 40; i++) {
        secret += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return (secret);
};

module.exports = TestHarness;
