/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright (c) 2014, Joyent, Inc.
 */

/*
 * Library of functions for interfacing with the redis DB.
 */

var assert = require('assert-plus');
var errors = require('./errors.js');
var sprintf = require('util').format;
var vasync = require('vasync');

module.exports = {
    getObject: getObject,
    getAccount: getAccount,
    getUser: getUser,
    getRole: getRole,
    getPolicy: getPolicy,
    getAccountUuid: getAccountUuid,
    getUuid: getUuid,
    getRoles: getRoles,
    getRoleMembers: getRoleMembers,
    generateLookup: generateLookup
};


/**
 * Gets an object by UUID.
 *
 * uuid: object uuid
 * log: bunyan log
 * redis: redis client
 * cb: callback in the form f(err, obj) where obj is the requested object
 *
 * errors:
 * RedisError if an error occurs contacting redis
 * ObjectDoesNotExistError if specified object is not found
 */
function getObject(opts, cb) {
    assert.string(opts.uuid, 'uuid');
    assert.object(opts.log, 'log');
    assert.object(opts.redis, 'redis');

    var uuid = opts.uuid;
    var log = opts.log;
    var redis = opts.redis;

    log.debug({uuid: uuid}, 'getObject: done');
    redis.get('/uuid/' + uuid, function (err, blob) {
        if (err) {
            cb(new errors.RedisError(err));
            return;
        }

        if (!blob) {
            cb(new errors.ObjectDoesNotExistError(uuid));
            return;
        }

        var result = JSON.parse(blob);
        log.debug({object: result}, 'getObject: done');
        cb(null, result);
    });
}


/**
 * Gets an account by UUID.
 *
 * arguments:
 * uuid: account uuid
 * log: bunyan log
 * redis: redis client
 * cb: callback in the form f(err, obj) where obj is the requested account
 *
 * errors:
 * RedisError if an error occurs contacting redis
 * AccountIdDoesNotExistError if specified account is not found
 */
function getAccount(opts, cb) {
    assert.string(opts.uuid, 'uuid');
    assert.object(opts.log, 'log');
    assert.object(opts.redis, 'redis');

    var uuid = opts.uuid;
    var log = opts.log;

    log.debug({uuid: uuid}, 'getAccount: entered');
    getObject(opts, function (err, result) {
        if (err) {
            if (err.code === 'ObjectDoesNotExist') {
                cb(new errors.AccountIdDoesNotExistError(uuid));
                return;
            }
            cb(err);
            return;
        }

        if (result.type !== 'account') {
            cb(new errors.WrongTypeError(uuid, 'account', result.type));
            return;
        }

        result.isOperator = result.groups &&
            result.groups.indexOf('operators') >= 0;
        log.debug({account: result}, 'getAccount: done');
        cb(null, result);
    });
}


/**
 * Gets a user by UUID.
 *
 * arguments:
 * uuid: user uuid
 * log: bunyan log
 * redis: redis client
 * cb: callback in the form f(err, obj) where obj is the requested user
 *
 * errors:
 * RedisError if an error occurs contacting redis
 * UserIdDoesNotExistError if specified user is not found
 */
function getUser(opts, cb) {
    assert.string(opts.uuid, 'uuid');
    assert.object(opts.log, 'log');
    assert.object(opts.redis, 'redis');

    var uuid = opts.uuid;
    var log = opts.log;

    log.debug({uuid: uuid}, 'getUser: entered');
    getObject(opts, function (err, result) {
        if (err) {
            if (err.code === 'ObjectDoesNotExist') {
                cb(new errors.UserIdDoesNotExistError(uuid));
                return;
            }
            cb(err);
            return;
        }

        if (result.type !== 'user') {
            cb(new errors.WrongTypeError(uuid, 'user', result.type));
            return;
        }

        log.debug({user: result}, 'getUser: done');
        cb(null, result);
        return;
    });
}


/**
 * Gets a role by UUID.
 *
 * arguments:
 * uuid: role uuid
 * log: bunyan log
 * redis: redis client
 * cb: callback in the form f(err, obj) where obj is the requested role
 *
 * errors:
 * RedisError if an error occurs contacting redis
 * RoleIdDoesNotExistError if specified role is not found
 */
function getRole(opts, cb) {
    assert.string(opts.uuid, 'uuid');
    assert.object(opts.log, 'log');
    assert.object(opts.redis, 'redis');

    var uuid = opts.uuid;
    var log = opts.log;

    log.debug({uuid: uuid}, 'getRole: entered');
    getObject(opts, function (err, result) {
        if (err) {
            if (err.code === 'ObjectDoesNotExist') {
                cb(new errors.RoleIdDoesNotExistError(uuid));
                return;
            }
            cb(err);
            return;
        }

        if (result.type !== 'role') {
            cb(new errors.WrongTypeError(uuid, 'role', result.type));
            return;
        }

        log.debug({role: result}, 'getRole: done');
        cb(null, result);
        return;
    });
}


/**
 * Gets a policy by UUID.
 *
 * arguments:
 * uuid: policy uuid
 * log: bunyan log
 * redis: redis client
 * cb: callback in the form f(err, obj) where obj is the requested policy
 *
 * errors:
 * RedisError if an error occurs contacting redis
 * PolicyIdDoesNotExistError if specified policy is not found
 */
function getPolicy(opts, cb) {
    assert.string(opts.uuid, 'uuid');
    assert.object(opts.log, 'log');
    assert.object(opts.redis, 'redis');

    var uuid = opts.uuid;
    var log = opts.log;

    log.debug({uuid: uuid}, 'getPolicy: entered');
    getObject(opts, function (err, result) {
        if (err) {
            if (err.code === 'ObjectDoesNotExist') {
                cb(new errors.PolicyIdDoesNotExistError(uuid));
                return;
            }
            cb(err);
            return;
        }

        if (result.type !== 'policy') {
            cb(new errors.WrongTypeError(uuid, 'policy', result.type));
            return;
        }

        log.debug({policy: result}, 'getPolicy: done');
        cb(null, result);
        return;
    });
}


/**
 * Gets an account's uuid from it's login.
 *
 * arguments:
 * account: account login
 * log: bunyan log
 * redis: redis client
 * cb: callback in the form f(err, uuid) where uuid is the account's uuid
 *
 * errors:
 * RedisError if an error occurs contacting redis
 * AccountDoesNotExistError if the account login has no translation
 */
function getAccountUuid(opts, cb) {
    assert.string(opts.account, 'account');
    assert.object(opts.log, 'log');
    assert.object(opts.redis, 'redis');

    var account = opts.account;
    var log = opts.log;
    var redis = opts.redis;

    log.debug({account: account}, 'getAccountUuid: entered');
    redis.get('/account/' + account, function (err, uuid) {
        if (err) {
            cb(new errors.RedisError(err));
            return;
        }

        if (!uuid) {
            cb(new errors.AccountDoesNotExistError(account));
            return;
        }

        log.debug({uuid: uuid}, 'getAccountUuid: done');
        cb(null, uuid);
    });
}


/**
 * Gets an object's uuid based on it's name. Only works with objects scoped
 * under accounts (roles, users and policies).
 *
 * arguments:
 * accountUuid: account uuid the object is scoped under
 * name: object name
 * type: object type ('role', 'user', 'policy')
 * log: bunyan log
 * redis: redis client
 * cb: callback in the form f(err, uuid) where uuid is the object's uuid
 *
 * errors:
 * RedisError if an error occurs contacting redis
 * ObjectDoesNotExistError if the object name has no translation
 */
function getUuid(opts, cb) {
    assert.string(opts.accountUuid, 'accountUuid');
    assert.string(opts.name, 'name');
    assert.string(opts.type, 'type');
    assert.ok(['role', 'user', 'policy'].indexOf(opts.type) >= 0,
            'type must be role, user or policy');
    assert.object(opts.log, 'log');
    assert.object(opts.redis, 'redis');

    var accountUuid = opts.accountUuid;
    var name = opts.name;
    var type = opts.type;
    var log = opts.log;
    var redis = opts.redis;

    log.debug({
        type: type,
        account: accountUuid,
        name: name
    }, 'getUuid: entered');

    var key = sprintf('/%s/%s/%s', type, accountUuid, name);
    redis.get(key, function (err, uuid) {
        if (err) {
            cb(new errors.RedisError(err));
            return;
        }

        if (!uuid) {
            cb(new errors.ObjectDoesNotExistError(key));
            return;
        }

        log.debug({uuid: uuid}, 'getUuid: done');
        cb(null, uuid);
    });
}


/**
 * Loads policies for each role.
 *
 * arguments:
 *
 * errors:
 *
 */
function getRoles(opts, cb) {
    assert.arrayOfString(opts.roles, 'roles');
    assert.object(opts.log, 'log');
    assert.object(opts.redis, 'redis');

    var roles = opts.roles;
    var log = opts.log;
    var redis = opts.redis;
    var result = {};

    vasync.forEachParallel({
        func: function getOneRole(roleUuid, rolecb) {
            getRole({
                uuid: roleUuid,
                log: log,
                redis: redis
            }, function gotRole(err, role) {
                if (err) {
                    rolecb(err);
                    return;
                }

                result[roleUuid] = role;
                result[roleUuid].rules = [];

                vasync.forEachParallel({
                    func: function getOnePolicy(policyUuid, policycb) {
                        getPolicy({
                            uuid: policyUuid,
                            log: log,
                            redis: redis
                        }, function gotPolicy(err, policy) {
                            if (err) {
                                policycb(err);
                                return;
                            }

                            policy.rules.forEach(function (rule) {
                                result[roleUuid].rules.push(rule);
                            });
                            policycb();
                        });
                    },
                    inputs: role.policies || []
                }, function gotPolicies(err) {
                    if (err) {
                        rolecb(err);
                        return;
                    }

                    rolecb();
                });
            });
        },
        inputs: roles
    }, function gotRoles(err) {
        if (err) {
            cb(err);
            return;
        }
        log.debug({roles: result}, 'getRoles: done');
        cb(null, result);
    });
}


/**
 * Generates a lookup table for account logins and whether the account is
 * approved for provisioning.
 * {
 *      uuid: {
 *          approved: false,
 *          login: admin
 *      },
 *      uuid: {
 *          approved: true,
 *          login: poseidon
 *      },
 *      ...
 * }
 */
function generateLookup(opts, cb) {
    assert.object(opts.log, 'log');
    assert.object(opts.redis, 'redis');

    var log = opts.log;
    var redis = opts.redis;

    log.debug('generateLookup: entered');

    redis.smembers('/set/accounts', function (err, members) {
        vasync.forEachParallel({
            func: function (uuid, parallelcb) {
                getAccount({
                    uuid: uuid,
                    log: log,
                    redis: redis
                }, parallelcb);
            },
            inputs: members
        }, function (err, results) {
            if (err) {
                cb(err);
                return;
            }
            var lookup = {};
            results.successes.forEach(function (account) {
                lookup[account.uuid] = {
                    approved: account.approved_for_provisioning,
                    login: account.login
                };
            });
            cb(null, lookup);
            return;
        });
    });
}

/**
 * Gets information about the members of a role
 */
function getRoleMembers(opts, cb) {
    assert.string(opts.uuid, 'uuid');
    assert.object(opts.log, 'log');
    assert.object(opts.redis, 'redis');

    var log = opts.log;
    var redis = opts.redis;

    log.debug('getRoleMembers: entered');

    var key = sprintf('/uuid/%s/roles', opts.uuid);
    redis.smembers(key, function (err, members) {
        vasync.forEachParallel({
            func: function (uuid, parallelcb) {
                getObject({
                    uuid: uuid,
                    log: log,
                    redis: redis
                }, parallelcb);
            },
            inputs: members
        }, function (err, results) {
            if (err) {
                cb(err);
                return;
            }
            var lookup = {};
            results.successes.forEach(function (account) {
                lookup[account.uuid] = account;
            });
            cb(null, lookup);
            return;
        });
    });
}
