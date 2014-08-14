// Copyright (c) 2014, Joyent, Inc. All rights reserved.

var assert = require('assert-plus');
var bunyan = require('bunyan');
var dashdash = require('dashdash');
var errors = require('./errors.js');
var lib = require('./redislib.js');
var path = require('path');
var redis = require('../redis.js');
var restify = require('restify');
var vasync = require('vasync');

module.exports = {
    Server: Server,
    createServer: createServer
};

function Server(opts) {
    assert.number(opts.port, 'port');
    assert.object(opts.redis, 'redis');
    assert.object(opts.log, 'log');

    var wait = setInterval(poll, 1000);
    var replicatorReady = false;
    var isPolling = false;

    var server = restify.createServer({
        name: 'mahi',
        log: opts.log,
        version: '1.0.0'
    });

    var auditLogger = opts.log.child({
        audit: true,
        serializers: {
            err: bunyan.stdSerializers.err,
            req: function auditRequestSerializer(req) {
                var auth = {};

                var timers = {};
                (req.timers || []).forEach(function (time) {
                    var t = time.time;
                    var _t = Math.floor((1000000 * t[0]) +
                                        (t[1] / 1000));
                    timers[time.name] = _t;
                });

                if (req.auth) {
                    if (req.auth.account) {
                        auth.account = {
                            login: req.auth.account.login,
                            uuid: req.auth.account.uuid
                        };
                    }
                    if (req.auth.user) {
                        auth.user = {
                            login: req.auth.user.login,
                            uuid: req.auth.user.uuid
                        };
                    }

                    if (req.auth.roles) {
                        auth.roles = req.auth.roles;
                    }
                }

                return ({
                    method: req.method,
                    url: req.url,
                    headers: req.headers,
                    version: req.version,
                    auth: auth,
                    timers: timers
                });
            },
            res: function auditResponseSerializer(res) {
                if (!res) {
                    return (false);
                }

                return ({
                    statusCode: res.statusCode,
                    headers: res._headers
                });
            }
        }
    });

    this.server = server;

    /*
     * poll is called occasionally and on each request as long as the replicator
     * is not ready yet.
     */
    function poll(cb) {
        if (isPolling) {
            if (cb) {
                setImmediate(function () {
                    cb(null, false);
                });
            }
            return;
        }

        isPolling = true;

        opts.redis.get('virgin', function (err, res) {
            isPolling = false;
            if (err || res !== null) {
                if (cb) {
                    cb(null, false);
                }
                return;
            }
            clearInterval(wait);
            replicatorReady = true;
            if (cb) {
                cb(null, true);
            }
        });
    }

    server.pre(function check(req, res, next) {
        if (replicatorReady) {
            next();
        } else {
            poll(function (err, ready) {
                if (!ready) {
                    next(new errors.ReplicatorNotReadyError());
                } else {
                    next();
                }
            });
        }
    });

    server.use(restify.requestLogger());
    server.use(restify.queryParser());
    server.use(restify.bodyParser());
    server.use(function initHandler(req, res, next) {
        req.redis = opts.redis;
        req.auth = {
            roles: {}
        };
        next();
    });

    // /accounts/id
    // /accounts?login=x
    // /users/id
    // /users?account=x&login=y&fallback=true
    // /uuids?account=x&type=y&name=z1&name=z2
    // /names?uuid=x1&uuid=x2

    server.get({
        name: 'getAccountByUuid',
        path: '/accounts/:accountid'
    }, [getAccount, sendAuth]);

    server.get({
        name: 'getAccount',
        path: '/accounts'
    }, [getAccountUuid, getAccount, sendAuth]);

    server.get({
        name: 'getUserByUuid',
        path: '/users/:userid'
    }, [getUser, getAccount, getRoles, sendAuth]);

    server.get({
        name: 'getUser',
        path: '/users'
    }, [getAccountUuid, getAccount, getUserUuid, getUser, getRoles, sendAuth]);

    server.get({
        name: 'nameToUuid',
        path: '/uuids'
    }, [getUuid]);

    server.get({
        name: 'uuidToName',
        path: '/names'
    }, [getName]);

    server.get({
        name: 'ping',
        path: '/ping'
    }, ping);


    // deprecated

    server.get({
        name: 'getAccountOld',
        path: '/account/:account'
    }, [getAccountUuid, getAccount, sendAuth]);

    server.get({
        name: 'getUserOld',
        path: '/user/:account/:user'
    }, [getAccountUuid, getAccount, getUserUuid, getUser, getRoles, sendAuth]);

    server.post({
        name: 'nameToUuidOld',
        path: '/getUuid'
    }, [getUuid]);

    server.post({
        name: 'uuidToNameOld',
        path: '/getName'
    }, [getName]);


    server.on('uncaughtException', function (req, res, route, err) {
        if (!res._headerSent) {
            res.send(err);
        }
        audit(auditLogger, req, res, route, err);
    });


    server.on('after', audit.bind(null, auditLogger));

    server.listen(opts.port, function () {
        server.log.info({port: opts.port}, 'server listening');
    });

    return (server);
}


Server.prototype.close = function close() {
    this.server.close();
};


function createServer(opts) {
    return (new Server(opts));
}


// -- Handlers


/**
 * errors:
 * RedisError
 * AccountDoesNotExistError
 */
function getAccountUuid(req, res, next) {
    var account = req.params.account || req.params.login;
    req.log.debug({account: account}, 'getAccountUuid handler: entered');
    lib.getAccountUuid({
        account: account,
        log: req.log,
        redis: req.redis
    }, function (err, uuid) {
        if (err) {
            next(err);
            return;
        }
        req.accountUuid = uuid;
        req.log.debug({uuid: uuid}, 'getAccountUuid: done');
        next();
    });
}


/**
 * errors:
 * RedisError
 * AccountIdDoesNotExistError
 */
function getAccount(req, res, next) {
    var uuid = req.accountUuid || req.params.accountid;
    req.log.debug({uuid: uuid}, 'getAccount handler: entered');
    lib.getAccount({
        uuid: uuid,
        log: req.log,
        redis: req.redis
    }, function (err, info) {
        if (err) {
            next(err);
            return;
        }

        req.auth.account = info;
        req.log.debug({account: info}, 'getAccount: done');
        next();
    });
}


/**
 * errors:
 * RedisError
 * UserDoesNotExistError
 */
function getUserUuid(req, res, next) {
    var accountUuid = req.auth.account.uuid;
    var user = req.params.login || /* deprecated */ req.params.user;
    var fallback = typeof (req.params.fallback) === 'undefined' ||
            req.params.fallback === 'true';

    req.log.debug({
        accountid: accountUuid,
        user: user
    }, 'getUserUuid handler: entered');
    lib.getUuid({
        accountUuid: accountUuid,
        name: user,
        type: 'user',
        log: req.log,
        redis: req.redis
    }, function (err, uuid) {
        if (err) {
            if (err.name === 'ObjectDoesNotExist' &&
                    req.auth.account &&
                    fallback) { // don't error if fallback is set

                res.send(req.auth);
                next(false);
            } else if (err.name === 'ObjectDoesNotExist') {
                next(new errors.UserDoesNotExistError(user,
                        req.auth.account.login));
            } else {
                next(err);
            }
            return;
        }
        req.userUuid = uuid;
        req.log.debug({uuid: uuid}, 'getUserUuid: done');
        next();
    });
}


function getUser(req, res, next) {
    var uuid = req.userUuid || req.params.userid;
    req.log.debug({uuid: uuid}, 'getUser handler: entered');
    lib.getUser({
        uuid: uuid,
        log: req.log,
        redis: req.redis
    }, function (err, info) {
        if (err) {
            next(err);
            return;
        }

        req.auth.user = info;
        req.accountUuid = info.account;
        req.log.debug({user: info}, 'getUser: done');
        next();
    });
}


function getRoles(req, res, next) {
    var roles = req.auth.user.roles;
    req.log.debug({roles: roles}, 'getRoles handler: entered');
    lib.getRoles({
        roles: roles,
        log: req.log,
        redis: req.redis
    }, function (err, roles) {
        if (err) {
            next(err);
            return;
        }
        req.log.debug({roles: req.auth.roles}, 'getRoles: done');
        req.auth.roles = roles;
        next();
    });
}


function getName(req, res, next) {
    var uuids = req.params.uuid || /* deprecated */ req.params.uuids;
    if (uuids && !Array.isArray(uuids)) {
        uuids = [uuids];
    }
    req.log.debug({uuids: uuids}, 'getName handler: entered');

    var body = {};

    vasync.forEachParallel({
        func: function getOneName(uuid, cb) {
            lib.getObject({
                uuid: uuid,
                log: req.log,
                redis: req.redis
            }, function (err, obj) {
                if (err) {
                    if (err.name === 'ObjectDoesNotExist') {
                        cb();
                    } else {
                        cb(err);
                    }
                    return;
                }

                body[uuid] = obj.name || obj.login;
                cb();
            });
        },
        inputs: uuids
    }, function (err) {
        if (err) {
            next(err);
            return;
        }
        res.send(body);
        req.log.debug({body: body}, 'getName: done');
        next();
    });
}


/*
 * account: account login
 * type: role|user|policy
 * names: array of role|user|policy names to translate
 */
function getUuid(req, res, next) {
    var body = {};
    var account = req.params.account;
    var type = req.params.type;
    var names = req.params.name || /* deprecated */ req.params.names;
    if (names && !Array.isArray(names)) {
        names = [names];
    }

    req.log.debug({
        account: account,
        type: type,
        names: names
    }, 'getUuid handler: entered');

    lib.getAccountUuid({
        account: account,
        log: req.log,
        redis: req.redis
    }, function (err, accountUuid) {
        if (err) {
            next(err);
            return;
        }

        body.account = accountUuid;
        if (names) {
            body.uuids = {};
            vasync.forEachParallel({
                func: function getOneUuid(name, cb) {
                    lib.getUuid({
                        accountUuid: accountUuid,
                        name: name,
                        type: type,
                        log: req.log,
                        redis: req.redis
                    }, function gotOneUuid(err, uuid) {
                        if (err) {
                            if (err.name === 'ObjectDoesNotExist') {
                                cb();
                            } else {
                                cb(err);
                            }
                            return;
                        }

                        body.uuids[name] = uuid;
                        cb();
                    });
                },
                inputs: names
            }, function (err) {
                if (err) {
                    next(err);
                    return;
                }
                res.send(body);
                req.log.debug('getUuid: done');
                next();
            });
        } else {
            req.log.debug('getUuid: done');
            res.send(body);
            next();
        }
    });
}


function sendAuth(req, res, next) {
    res.send(req.auth);
    next();
}


function ping(req, res, next) {
    req.redis.ping(function (err) {
        if (err) {
            next(new errors.RedisError(err));
            return;
        }
        req.redis.get('virgin', function (err, redisRes) {
            if (err) {
                next(new errors.RedisError(err));
                return;
            }

            if (redisRes !== null) {
                next(new errors.ReplicatorNotReadyError());
                return;
            }

            res.send(204);
            next();
        });
    });
}


function audit(log, req, res, route, err) {
    if (req.path === '/ping') {
        return;
    }

    var obj = {
        _audit: true,
        operation: route ? (route.name || route) : 'unknown',
        req_id: req.id,
        req: req,
        res: res,
        err: err
    };
    log.info(obj, 'handled: %d', res.statusCode);
}


///--- main

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
            default: path.resolve(__dirname, '../../etc/mahi2.json'),
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
            help: 'listen port (overrides config)'
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
    var serverConfig = config.server || {};
    var log = bunyan.createLogger({
        name: 'authcache-service',
        level: process.env.LOG_LEVEL || 'info'
    });
    redisConfig.log = log;
    redis.createClient(redisConfig, function (err, client) {
        client.select(redisConfig.db || 0, function (err) {
            if (err) {
                log.fatal({err: err, db: redisConfig.db}, 'error selecting db');
                process.exit(1);
            }
            createServer({
                port: opts.port || serverConfig.port || 8080,
                log: log,
                redis: client
            });
        });
    });
}

if (require.main === module) {
    main();
}
