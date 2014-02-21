// Copyright (c) 2014, Joyent, Inc. All rights reserved.

var assert = require('assert-plus');
var bunyan = require('bunyan');
var errors = require('./errors.js');
var Redis = require('../redis.js');
var restify = require('restify');
var sprintf = require('util').format;
var vasync = require('vasync');

module.exports = {
    start: start
};

function start(opts) {
    assert.number(opts.port, 'port');
    assert.object(opts.redis, 'redis');
    assert.object(opts.log, 'log');

    var server = restify.createServer({
        name: 'mahi',
        log: opts.log,
        version: '0.0.0'
    });

    server.use(restify.requestLogger());
    server.use(function initHandler(req, res, next) {
        req.redis = opts.redis;
        req.auth = {};
        req.auth.roles = {};
        next();
    });

    server.get({
        name: 'getAccount',
        path: '/info/:account'
    }, [getAccount, checkAccount, auth]);

    server.get({
        name: 'getUser',
        path: '/info/:account/:user'
    }, [getAccount, checkAccount, getUser, userRoles, auth]);

    server.get({
        name: 'lookup',
        path: '/lookup/:type/:name'
    }, [lookup]);

    server.listen(opts.port, function () {
        server.log.info('server listening');
    });
}



// -- Handlers

function lookup(req, res, next) {
    req.log.debug('lookup');

    var type = req.params.type;
    var name = req.params.name;
    var key = sprintf('/%s/%s', type, name);
    req.redis.get(key, function (err, uuid) {
        res.send(uuid);
        next();
    });
}

function getAccount(req, res, next) {
    req.log.debug('getAccount');

    var account = req.params.account;
    req.redis.get('/account/' + account, function (err, uuid) {
        if (err) {
            next(new errors.RedisError(err));
            return;
        }
        if (!uuid) {
            next(new errors.AccountDoesNotExistError(account));
            return;
        }
        req.redis.get('/uuid/' + uuid, function (err, blob) {
            if (err) {
                next(new errors.RedisError(err));
                return;
            }
            req.auth.account = JSON.parse(blob);
            next();
            return;
        });
    });
}


function checkAccount(req, res, next) {
    req.log.debug('checkAccount');

    var isOperator = req.auth.account.groups.operators;
    if (!req.auth.account.approved_for_provisioning && !isOperator) {
        next(new errors.NotApprovedForProvisioningError(
            req.auth.account.login));
        return;
    }

    if (isOperator) {
        req.auth.account.isOperator = true;
    }

    next();
}


function getUser(req, res, next) {
    req.log.debug('getUser');

    var user = req.params.user;
    if (!user) {
        next();
        return;
    }

    var account = req.auth.account;
    var key = sprintf('/user/%s/%s', account.uuid, user);

    req.redis.get(key, function (err, uuid) {
        if (err) {
            next(new errors.RedisError(err));
            return;
        }
        if (!uuid) {
            next(new errors.UserDoesNotExistError(account.login, user));
            return;
        }
        req.redis.get('/uuid/' + uuid, function (err, blob) {
            if (err) {
                next(new errors.RedisError(err));
                return;
            }
            req.auth.user = JSON.parse(blob);
            next();
            return;
        });
    });
}


function userRoles(req, res, next) {
    req.log.debug('userRoles');

    vasync.forEachParallel({
        func: function getRoles(roleUUID, getRolecb) {
            var roleKey = '/uuid/' + roleUUID;
            req.redis.get(roleKey, function (err, res) {
                if (err) {
                    getRolecb(new errors.RedisError(err));
                    return;
                }

                var role = JSON.parse(res);
                req.auth.roles[roleUUID] = [];

                vasync.forEachParallel({
                    func: function getPolicies(policyUUID, getPolicycb) {
                        var policyKey = '/uuid/' + policyUUID;
                        req.redis.get(policyKey, function (err, res) {
                            if (err) {
                                getPolicycb(new errors.RedisError(err));
                                return;
                            }

                            var policy = JSON.parse(res);
                            policy.rules.forEach(function (rule) {
                                req.auth.roles[roleUUID].push(rule);
                            });
                            getPolicycb();
                            return;
                        });
                    },
                    inputs: role.policies
                }, function getPoliciesEnd(err, res) {
                    getRolecb(err, res);
                    return;
                });
            });
        },
        inputs: req.auth.user.roles
    }, function getRolesEnd(err) {
        if (err) {
            next(err);
            return;
        }
        next();
        return;
    });
}

function auth(req, res, next) {
    res.send(req.auth);
    next();
}


if (require.main === module) {
    (function () {
        var log = bunyan.createLogger({name: 'mahi'});
        var redis = require('../../etc/laptop.config.json').redis;
        redis.log = log;
        Redis.createClient(redis, function makeRedis(err, client) {
            start({
                port: 8080,
                log: log,
                redis: client
            });
        });
    }());
}
