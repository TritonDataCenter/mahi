// Copyright (c) 2013, Joyent, Inc. All rights reserved.
var assert = require('assert-plus');
var bunyan = require('bunyan');
var errors = require('./errors.js');
var redis = require('../redis.js');
var restify = require('restify');
var sprintf = require('util').format;
var vasync = require('vasync');

module.exports = {
    AuthServer: AuthServer,
    createAuthServer: function (opts) {
        return (new AuthServer(opts));
    }
};

function AuthServer(opts) {
    assert.number(opts.port, 'port');
    assert.object(opts.redisCfg, 'redisCfg');

    var self = this;

    self.log = bunyan.createLogger({
        name: 'AuthServer.js',
        level: (process.env.LOG_LEVEL || 'info'),
        serializers: bunyan.stdSerializers,
        stream: process.stdout
    });

    self.server = restify.createServer({
        name: 'mahi',
        version: '0.0.0'
    });

    self.server.get('/:account/:user', getUser.bind(self));
    self.server.get('/:account', getAccount.bind(self));

    opts.redisCfg.log = self.log;
    console.log('here');
    redis.createClient(opts.redisCfg, function makeRedis(err, client) {
        if (err) {
            process.exit(1);
        }
        self.redis = client;
        self.server.listen(opts.port, function () {
            self.log.info('server listening');
        });
    });
}

function getAccount(req, res, next) {
    var self = this;
    self.log.info('getAccount');
    self.redis.get('/account/' + req.params.account, function (err, uuid) {
        self.log.info({err: err}, 'getAccount');
        self.log.info({uuid: uuid}, 'getAccount');
        if (!uuid) {
            res.send(new errors.AccountDoesNotExistError());
            next();
            return;
        }
        self.redis.get('/uuid/' + uuid, function (err, blob) {
            res.send(JSON.parse(blob));
            next();
            return;
        });
    });
}

function getUser(req, res, next) {
    var self = this;
    var account = req.params.account;
    var user = req.params.user;
    var userUUID;
    var accountUUID;
    var result;

    self.log.info('getUser');
    vasync.pipeline({funcs: [
        function getAccountUUID(_, pipelinecb) {
            var key = '/account/' + account;
            self.redis.get(key, function (err, uuid) {
                if (!uuid) {
                    pipelinecb(new errors.AccountDoesNotExistError());
                    return;
                }
                accountUUID = uuid;
                pipelinecb();
            });
        },
        function getuserUUID(_, pipelinecb) {
            var key = sprintf('/user/%s/%s/%s', accountUUID, accountUUID, user);
            self.redis.get(key, function (err, uuid) {
                if (!uuid) {
                    pipelinecb(new errors.UserDoesNotExistError());
                    return;
                }
                userUUID = uuid;
                pipelinecb();
            });
        },
        function getUser(_, pipelinecb) {
            self.redis.get('/uuid/' + userUUID, function (err, userBlob) {
                user = JSON.parse(userBlob);
                result = {
                    type: user.type,
                    uuid: userUUID,
                    login: user.login,
                    account: user.account,
                    keys: user.keys,
                    roles: {}
                };
                pipelinecb();
            });
        },
        function getPolicies(_, pipelinecb) {
            var barrier = vasync.barrier();
            barrier.start('groups');
            barrier.start('roles');
            barrier.on('drain', function () {
                pipelinecb();
            });

            function addPolicies(roles, cb) {
                assert.arrayOfString(roles);
                vasync.forEachParallel({
                    func: function addPolicies(roleUUID, parallelcb) {
                        var key = '/uuid/' + roleUUID;
                        self.redis.get(key, function (err, res) {
                            if (err) {
                                // TODO
                                console.log(err);
                            }
                            if (!result.roles[roleUUID]) {
                                var roleBlob = JSON.parse(res);
                                result.roles[roleUUID] = roleBlob.policies;
                            }
                            parallelcb();
                        });
                    },
                    inputs: roles
                }, function (err) {
                    if (err) {
                        // TODO
                        console.log(err);
                    }
                    cb();
                });
            }

            addPolicies(user.roles, function () {
                barrier.done('roles');
            });

            vasync.forEachParallel({
                func: function gotGroup(groupUUID, parallelcb) {
                    self.redis.get('/uuid/' + groupUUID,
                        function (err, groupBlob) {

                        var group = JSON.parse(groupBlob);
                        addPolicies(group.roles, function (err) {
                            if (err) {
                                // TODO
                                console.log(err);
                            }
                            parallelcb();
                        });
                    });
                },
                inputs: user.groups
            }, function (err) {
                if (err) {
                    // TODO
                    console.log(err);
                }
                barrier.done('groups');
            });
        }
    ]}, function (err, pipelineRes) {
        self.log.info({err: err, pipelineRes: pipelineRes});
        res.send(result);
        next();
        return;
    });
}
AuthServer({
    port: 8080,
    redisCfg: require('../../etc/laptop.config.json').redisCfg
});
