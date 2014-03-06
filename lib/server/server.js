// Copyright (c) 2014, Joyent, Inc. All rights reserved.

var assert = require('assert-plus');
var bunyan = require('bunyan');
var dashdash = require('dashdash');
var errors = require('./errors.js');
var path = require('path');
var redis = require('../redis.js');
var restify = require('restify');
var sprintf = require('util').format;
var vasync = require('vasync');

module.exports = {
    Server: Server,
    createServer: createServer
};

function Server(opts) {
    assert.number(opts.port, 'port');
    assert.object(opts.redis, 'redis');
    assert.object(opts.log, 'log');

    var server = restify.createServer({
        name: 'mahi',
        log: opts.log,
        version: '0.0.0'
    });
    this.server = server;

    server.use(restify.requestLogger());
    server.use(restify.queryParser());
    server.use(restify.bodyParser());
    server.use(function initHandler(req, res, next) {
        req.redis = opts.redis;
        req.auth = {};
        req.auth.roles = {};
        next();
    });

    server.get({
        name: 'getAccount',
        path: '/account/:account'
    }, [getAccount, checkAccount, auth]);

    server.get({
        name: 'getUser',
        path: '/user/:account/:user'
    }, [getAccount, checkAccount, getUser, userRoles, auth]);

    server.post({
        name: 'translate',
        path: '/translate'
    }, [translate]);

    server.listen(opts.port, function () {
        server.log.info({port: opts.port}, 'server listening');
    });
}

Server.prototype.close = function close() {
    this.server.close();
};

function createServer(opts) {
    return (new Server(opts));
}


// -- Handlers


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
        req.redis.get('/uuidv2/' + uuid, function (err, blob) {
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
        req.redis.get('/uuidv2/' + uuid, function (err, blob) {
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
            var roleKey = '/uuidv2/' + roleUUID;
            req.redis.get(roleKey, function (err, res) {
                if (err) {
                    getRolecb(new errors.RedisError(err));
                    return;
                }

                var role = JSON.parse(res);
                req.auth.roles[roleUUID] = role;
                req.auth.roles[roleUUID].rules = [];

                vasync.forEachParallel({
                    func: function getPolicies(policyUUID, getPolicycb) {
                        var policyKey = '/uuidv2/' + policyUUID;
                        req.redis.get(policyKey, function (err, res) {
                            if (err) {
                                getPolicycb(new errors.RedisError(err));
                                return;
                            }

                            var policy = JSON.parse(res);
                            policy.rules.forEach(function (rule) {
                                req.auth.roles[roleUUID].rules.push(rule);
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

function translate(req, res, next) {
    if (!req.params.account) {
        next(new errors.AccountRequiredError());
        return;
    }

    req.log.debug('translate');

    var body = {};

    req.redis.get('/account/' + req.params.account, function (err, account) {
        vasync.forEachParallel({
            func: function (type, typecb) {
                body[type] = {};
                if (!req.params[type]) {
                    typecb();
                    return;
                }
                vasync.forEachParallel({
                    func: function (name, namecb) {
                        var key = sprintf('/%s/%s/%s', type, account, name);
                        req.redis.get(key, function (err, uuid) {
                            body[type][name] = uuid;
                            namecb();
                        });
                    },
                    inputs: req.params[type]
                }, function (err) {
                    if (err) {
                        typecb(err);
                        return;
                    }
                    typecb();
                });
            },
            inputs: ['role', 'user', 'policy']
        }, function (err) {
            if (err) {
                next(new errors.RedisError(err));
                return;
            }
            res.send(body);
            req.log.debug('translate: done');
            next();
        });
    });
}

function auth(req, res, next) {
    res.send(req.auth);
    next();
}



function main() {
    var options = [
        {
            names: ['help', 'h'],
            type: 'bool',
            help: 'Print this help and exit.'
        },
        {
            names: ['config', 'c'],
            type: 'string',
            env: 'MAHI_CONFIG',
            helpArg: 'PATH',
            default: path.resolve(__dirname, '../../etc/mahi.json'),
            help: 'configuration file with ufds and redis config settings'
        },
        {
            names: ['redis-host'],
            type: 'string',
            env: 'MAHI_REDIS_HOST',
            helpArg: 'HOST',
            help: 'redis host (overrides config)'
        },
        {
            names: ['redis-port'],
            type: 'number',
            env: 'MAHI_REDIS_PORT',
            helpArg: 'PORT',
            help: 'redis port (overrides config)'
        },
        {
            names: ['port', 'p'],
            type: 'number',
            env: 'MAHI_PORT',
            helpArg: 'PORT',
            default: 8080,
            help: 'listen port'
        }
    ];
    var parser = dashdash.createParser({options: options});
    var opts;
    try {
        opts = parser.parse(process.argv);
    } catch (e) {
        console.error('error: %s', e.message);
        process.exit(1);
    }

    if (opts.help) {
        var help = parser.help().trimRight();
        console.log('usage: \n' + help);
        process.exit(0);
    }

    var config = require(path.resolve(opts.config));
    var redisConfig = config.redis;
    var log = bunyan.createLogger({
        name: 'authcache-service',
        level: process.env.LOG_LEVEL || 'info'
    });
    redisConfig.log = log;
    redis.createClient(redisConfig, function (err, client) {
        createServer({
            port: opts.port,
            log: log,
            redis: client
        });
    });
}

if (require.main === module) {
    main();
}
