/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright (c) 2025, Joyent, Inc.
 */

/**
 * Redis Fixtures Management for Testing
 *
 * Provides pre-configured Redis scenarios and fixture loading
 * utilities for consistent test setup. Integrates with existing
 * Transform pipeline from the replicator.
 */

var assert = require('assert-plus');
var fs = require('fs');
var path = require('path');
var _bunyan = require('bunyan');
var Transform = require('../../lib/replicator/transform.js');
var jsonstream = require('../jsonparsestream.js');

/**
 * @brief Redis fixture manager for test scenarios
 *
 * Manages loading and configuring Redis with pre-defined test
 * scenarios. Provides common test data setups including users,
 * accounts, roles, and access keys.
 *
 * @constructor
 * @param {object} opts Configuration options
 * @param {object} opts.redis Redis client instance (fakeredis)
 * @param {object} opts.log Bunyan logger instance
 * @param {object} [opts.typeTable] Aperture type table for policy
 *                                   parsing (default: {ip: 'ip'})
 *
 * @example
 * var redis = require('fakeredis');
 * var RedisFixture = require('./redis-fixtures');
 *
 * var fixture = new RedisFixture({
 *     redis: redis.createClient(),
 *     log: bunyan.createLogger({name: 'test', level: 'fatal'})
 * });
 *
 * fixture.loadScenario('basicAuth', function(err) {
 *     // Redis now populated with test users and accounts
 * });
 *
 * @since 1.0.0
 */
function RedisFixture(opts) {
    assert.object(opts, 'opts');
    assert.object(opts.redis, 'opts.redis');
    assert.object(opts.log, 'opts.log');
    assert.optionalObject(opts.typeTable, 'opts.typeTable');

    this.redis = opts.redis;
    this.log = opts.log.child({component: 'RedisFixture'}, true);
    this.typeTable = opts.typeTable || {ip: 'ip'};
}

/**
 * @brief Load a pre-configured test scenario
 *
 * Loads one of the pre-configured test scenarios into Redis. Each
 * scenario provides a different set of test data appropriate for
 * specific test cases.
 *
 * @param {string} scenarioName Name of scenario: 'empty', 'basicAuth',
 *                               'stsRoles', or 'sigv4Users'
 * @param {function} callback Callback function (err)
 *
 * @return {void}
 *
 * @note Scenarios:
 *   - empty: Clean Redis (flushdb)
 *   - basicAuth: Users, accounts, basic access keys
 *   - stsRoles: Accounts with IAM roles and trust policies
 *   - sigv4Users: Users with active AWS access keys for SigV4
 *                  testing
 *
 * @example
 * fixture.loadScenario('stsRoles', function(err) {
 *     if (err) throw err;
 *     // Redis now has accounts with IAM roles
 * });
 *
 * @since 1.0.0
 */
RedisFixture.prototype.loadScenario = function loadScenario(scenarioName,
    callback) {
    assert.string(scenarioName, 'scenarioName');
    assert.func(callback, 'callback');

    var scenarios = {
        'empty': this._loadEmpty.bind(this),
        'basicAuth': this._loadBasicAuth.bind(this),
        'stsRoles': this._loadStsRoles.bind(this),
        'sigv4Users': this._loadSigv4Users.bind(this)
    };

    var loader = scenarios[scenarioName];
    if (!loader) {
        return callback(new Error('Unknown scenario: ' + scenarioName +
            '. Available: ' + Object.keys(scenarios).join(', ')));
    }

    this.log.debug({scenario: scenarioName}, 'loading Redis scenario');
    return (loader(callback));
};

/**
 * @brief Clear all data from Redis
 *
 * Flushes the Redis database to provide clean slate for testing.
 *
 * @param {function} callback Callback function (err)
 *
 * @return {void}
 *
 * @since 1.0.0
 */
RedisFixture.prototype._loadEmpty = function _loadEmpty(callback) {
    this.redis.flushdb(callback);
};

/**
 * @brief Load basic authentication test data
 *
 * Loads test-nodeletes.json which contains standard users, accounts,
 * and access keys for basic authentication testing.
 *
 * @param {function} callback Callback function (err)
 *
 * @return {void}
 *
 * @note Uses existing Transform pipeline from replicator
 *
 * @since 1.0.0
 */
RedisFixture.prototype._loadBasicAuth = function _loadBasicAuth(callback) {
    var dataPath = path.resolve(__dirname, '../data/test-nodeletes.json');
    this._loadFromJson(dataPath, callback);
};

/**
 * @brief Load STS roles test data
 *
 * Loads test data containing accounts with IAM roles and trust
 * policies for STS AssumeRole testing.
 *
 * @param {function} callback Callback function (err)
 *
 * @return {void}
 *
 * @note Currently uses test-nodeletes.json; can be extended with
 *       dedicated STS fixture file
 *
 * @since 1.0.0
 */
RedisFixture.prototype._loadStsRoles = function _loadStsRoles(callback) {
    var dataPath = path.resolve(__dirname, '../data/test-nodeletes.json');
    this._loadFromJson(dataPath, callback);
};

/**
 * @brief Load SigV4 users test data
 *
 * Loads test data containing users with active AWS access keys for
 * AWS Signature Version 4 authentication testing.
 *
 * @param {function} callback Callback function (err)
 *
 * @return {void}
 *
 * @note Uses test-nodeletes.json which includes access key data
 *
 * @since 1.0.0
 */
RedisFixture.prototype._loadSigv4Users = function _loadSigv4Users(callback) {
    var dataPath = path.resolve(__dirname, '../data/test-nodeletes.json');
    this._loadFromJson(dataPath, callback);
};

/**
 * @brief Load fixture data from JSON file
 *
 * Internal method to load and transform JSON fixture data into Redis
 * using the existing Transform pipeline.
 *
 * @param {string} filepath Path to JSON fixture file
 * @param {function} callback Callback function (err)
 *
 * @return {void}
 *
 * @note Uses Transform from replicator to populate Redis
 *
 * @since 1.0.0
 */
RedisFixture.prototype._loadFromJson = function _loadFromJson(filepath,
    callback) {
    var self = this;

    if (!fs.existsSync(filepath)) {
        callback(new Error('Fixture file not found: ' + filepath));
        return;
    }

    var data = fs.createReadStream(filepath);
    var json = new jsonstream();
    var transform = new Transform({
        redis: this.redis,
        log: this.log,
        typeTable: this.typeTable
    });

    transform.on('finish', function onFinish() {
        self.log.debug({file: filepath}, 'fixture loaded successfully');
        callback();
    });

    transform.on('error', function onError(err) {
        self.log.error({err: err, file: filepath},
            'error loading fixture');
        callback(err);
    });

    data.pipe(json).pipe(transform);
};

/**
 * @brief Get value from Redis by key
 *
 * Helper method for retrieving and asserting Redis values in tests.
 *
 * @param {string} key Redis key to retrieve
 * @param {function} callback Callback function (err, value)
 *
 * @return {void}
 *
 * @example
 * fixture.get('/account/testuser', function(err, accountUuid) {
 *     t.ok(accountUuid, 'account UUID should exist');
 *     t.done();
 * });
 *
 * @since 1.0.0
 */
RedisFixture.prototype.get = function get(key, callback) {
    assert.string(key, 'key');
    assert.func(callback, 'callback');

    this.redis.get(key, callback);
};

/**
 * @brief Set value in Redis
 *
 * Helper method for adding test data to Redis.
 *
 * @param {string} key Redis key to set
 * @param {string} value Value to store
 * @param {function} callback Callback function (err)
 *
 * @return {void}
 *
 * @example
 * fixture.set('/account/newuser', accountUuid, function(err) {
 *     // Account mapping now in Redis
 * });
 *
 * @since 1.0.0
 */
RedisFixture.prototype.set = function set(key, value, callback) {
    assert.string(key, 'key');
    assert.string(value, 'value');
    assert.func(callback, 'callback');

    this.redis.set(key, value, callback);
};

/**
 * @brief Check if key exists in Redis
 *
 * Helper method for asserting key existence in tests.
 *
 * @param {string} key Redis key to check
 * @param {function} callback Callback function (err, exists)
 *                            where exists is boolean
 *
 * @return {void}
 *
 * @example
 * fixture.exists('/account/testuser', function(err, exists) {
 *     t.ok(exists, 'account should exist in Redis');
 *     t.done();
 * });
 *
 * @since 1.0.0
 */
RedisFixture.prototype.exists = function exists(key, callback) {
    assert.string(key, 'key');
    assert.func(callback, 'callback');

    this.redis.exists(key, function (err, result) {
        if (err) {
            return (callback(err));
        }
        return (callback(null, result === 1));
    });
};

/**
 * @brief Flush all data from Redis
 *
 * Clears all data from Redis. Useful for cleanup in test teardown.
 *
 * @param {function} callback Callback function (err)
 *
 * @return {void}
 *
 * @example
 * after(function(cb) {
 *     this.fixture.flush(cb);
 * });
 *
 * @since 1.0.0
 */
RedisFixture.prototype.flush = function flush(callback) {
    assert.func(callback, 'callback');
    this.redis.flushdb(callback);
};

module.exports = RedisFixture;
