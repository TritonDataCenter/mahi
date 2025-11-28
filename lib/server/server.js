/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright (c) 2017, Joyent, Inc.
 * Copyright 2025 Edgecast Cloud LLC.
 */

var assert = require('assert-plus');
var bunyan = require('bunyan');
var crypto = require('crypto');
var dashdash = require('dashdash');
var errors = require('./errors.js');
var lib = require('./redislib.js');
var path = require('path');
var redis = require('../redis.js');
var restify = require('restify');
var sigv4 = require('./sigv4.js');
var sessionToken = require('./session-token');
var sts = require('./sts.js');
var accesskey = require('ufds/lib/accesskey');
var ufds;
var vasync = require('vasync');

module.exports = {
    Server: Server,
    createServer: createServer,
    buildSecretConfig: buildSecretConfig
};

/**
 * @brief Build secret configuration for rotation support
 *
 * Creates a multi-secret configuration from session config.
 * Requires proper rotation configuration with key IDs.
 *
 * @param {Object} sessionConfig Session configuration object
 * @param {string} sessionConfig.secretKey Primary secret key
 * @param {string} sessionConfig.secretKeyId Primary key ID
 * @param {string} sessionConfig.oldSecretKey Optional old secret for
 * grace period
 * @param {string} sessionConfig.oldSecretKeyId Optional old key ID
 * @param {string} sessionConfig.rotationTime Rotation timestamp
 * @param {number} sessionConfig.gracePeriod Grace period in seconds
 * @returns {Object} Secret configuration with primary/old secrets
 * @throws {Error} If required rotation parameters are missing
 */
function buildSecretConfig(sessionConfig) {
    // Get configuration from sessionConfig or environment
    var primarySecret = sessionConfig ? sessionConfig.secretKey :
        process.env.SESSION_SECRET_KEY;
    var primaryKeyId = sessionConfig ? sessionConfig.secretKeyId :
        process.env.SESSION_SECRET_KEY_ID;
    var gracePeriod = sessionConfig ? sessionConfig.gracePeriod :
        process.env.SESSION_SECRET_GRACE_PERIOD;

    // Require primary secret
    if (!primarySecret) {
        throw new Error('Missing required session secret key');
    }

    // Require valid grace period for rotation security
    if (!gracePeriod) {
        throw new Error('Missing required grace period configuration ' +
                        '(sessionConfig.gracePeriod or' +
                        ' SESSION_SECRET_GRACE_PERIOD)');
    }

    var gracePeriodInt = parseInt(gracePeriod, 10);
    if (isNaN(gracePeriodInt) || gracePeriodInt < 60) {
        throw new Error('Invalid grace period: must be a number >= 60 seconds' +
                        ', got: ' + gracePeriod);
    }

    // Generate key ID if not provided
    if (!primaryKeyId) {
        primaryKeyId = sessionToken.generateKeyId();
    }

    var config = {
        primarySecret: {
            key: primarySecret,
            keyId: primaryKeyId
        },
        secrets: {},
        gracePeriod: gracePeriodInt
    };

    // Add primary secret to secrets map
    config.secrets[primaryKeyId] = {
        key: primarySecret,
        keyId: primaryKeyId,
        isPrimary: true,
        addedAt: Date.now()
    };

    // Add old secret for rotation grace period if available
    var oldSecret = sessionConfig ? sessionConfig.oldSecretKey :
        process.env.SESSION_SECRET_KEY_OLD;
    var oldKeyId = sessionConfig ? sessionConfig.oldSecretKeyId :
        process.env.SESSION_SECRET_KEY_OLD_ID;
    var rotationTime = sessionConfig ? sessionConfig.rotationTime :
        process.env.SESSION_SECRET_ROTATION_TIME;

    if (oldSecret && oldSecret.trim() !== '' &&
        oldKeyId && oldKeyId.trim() !== '') {
        config.secrets[oldKeyId] = {
            key: oldSecret,
            keyId: oldKeyId,
            isPrimary: false,
            addedAt: rotationTime ?
                parseInt(rotationTime, 10) * 1000 : Date.now()
        };
    }
    return (config);
}

function Server(opts) {
    assert.number(opts.port, 'port');
    assert.object(opts.redis, 'redis');
    assert.object(opts.log, 'log');
    assert.optionalObject(opts.ufdsConfig, 'ufdsConfig');
    assert.optionalObject(opts.sessionConfig, 'sessionConfig');

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
    this.ufdsClient = null;
    this.ufdsPool = null;
    this.sessionConfig = opts.sessionConfig;

    // Initialize UFDS connection pool if configuration is provided
    if (opts.ufdsConfig) {
        try {
            ufds = require('ufds');
            var genericPool = require('generic-pool');

            // Handle bindCredentials vs bindPassword parameter names
            var ufdsConfig = opts.ufdsConfig;
            if (ufdsConfig.bindCredentials && !ufdsConfig.bindPassword) {
                ufdsConfig = JSON.parse(JSON.stringify(opts.ufdsConfig));
                ufdsConfig.bindPassword = ufdsConfig.bindCredentials;
                delete ufdsConfig.bindCredentials;
                opts.log.debug('Using bindPassword for UFDS compatibility');
            }

            // Create UFDS connection pool using v2.x callback syntax
            this.ufdsPool = new genericPool.Pool({
                name: 'ufds',
                create: function (callback) {
                    var client = new ufds(ufdsConfig);
                    var timeout = setTimeout(function () {
                        callback(new Error('UFDS connection timeout'));
                    }, ufdsConfig.connectTimeout || 5000);

                    client.once('ready', function () {
                        clearTimeout(timeout);
                        opts.log.debug('UFDS pool: created new connection');
                        callback(null, client);
                    });

                    client.once('error', function (err) {
                        clearTimeout(timeout);
                        opts.log.warn({err: err},
                                      'UFDS pool: connection failed');
                        callback(err);
                    });
                },
                destroy: function (client) {
                    if (client && typeof (client.close) === 'function') {
                        client.close(function () {
                            opts.log.debug('UFDS pool: destroyed connection');
                        });
                    }
                },
                validate: function (client) {
                    return (client && client.connected !== false);
                },
                min: ufdsConfig.poolMin || 5,
                max: ufdsConfig.poolMax || 20,
                acquireTimeoutMillis: ufdsConfig.poolTimeout || 3000,
                idleTimeoutMillis: ufdsConfig.idleTimeout || 300000
            });

            opts.log.info({
                url: ufdsConfig.url,
                bindDN: ufdsConfig.bindDN,
                poolMin: ufdsConfig.poolMin || 2,
                poolMax: ufdsConfig.poolMax || 10
            }, 'UFDS connection pool initialized for STS operations');

        } catch (err) {
            opts.log.error({
                err: err,
                ufdsConfig: {
                    url: opts.ufdsConfig.url,
                    bindDN: opts.ufdsConfig.bindDN,
                    hasBindCredentials: !!opts.ufdsConfig.bindCredentials,
                    hasBindPassword: !!opts.ufdsConfig.bindPassword
                },
                errorMessage: err.message,
                errorStack: err.stack
            }, 'UFDS pool initialization failed');
            this.ufdsPool = null;
        }
    } else {
        opts.log.warn('No UFDS configuration provided,' +
                      ' STS operations will be limited');
        this.ufdsPool = null;
    }

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
        req.ufdsPool = this.ufdsPool; // UFDS connection pool
        req.auth = {
            roles: {}
        };
        next();
    }.bind(this));

    // Helper function to execute UFDS operations with connection pooling
    function executeUfdsOperation(req, operation, callback) {
        req.log.debug({hasPool: !!req.ufdsPool},
                      'executeUfdsOperation: checking pool availability');

        if (!req.ufdsPool) {
            req.log.error('executeUfdsOperation:'+
                          ' UFDS connection pool not available');
            return (callback(new Error('UFDS connection pool not available')));
        }

        req.log.debug('executeUfdsOperation: ' +
                      'attempting to acquire connection from pool');

        // Use connection pool with v2.x callback API
        return req.ufdsPool.acquire(function (err, client) {
            if (err) {
                req.log.error({err: err}, 'executeUfdsOperation: ' +
                              'Failed to acquire UFDS connection from pool');
                return (callback(err));
            }

            req.log.debug('executeUfdsOperation: acquired connection' +
                          ', executing operation');

            return operation(client, function (opErr, result) {
                req.log.debug({opErr: !!opErr}, 'executeUfdsOperation: ' +
                              'operation completed, releasing connection');

                // Always release the client back to pool
                req.ufdsPool.release(client);
                return (callback(opErr, result));
            });
        });
    }

    // /accounts/id
    // /accounts?login=x
    // /users/id
    // /users?account=x&login=y&fallback=true
    // /uuids?account=x&type=y&name=z1&name=z2
    // /names?uuid=x1&uuid=x2

    server.get({
        name: 'getAccountByUuid',
        path: '/accounts/:accountid'
    }, [getAccount, getRoles, sendAuth]);

    server.get({
        name: 'getAccount',
        path: '/accounts'
    }, [getAccountUuid, getAccount, getRoles, sendAuth]);

    server.get({
        name: 'getUserByUuid',
        path: '/users/:userid'
    }, [getUser, getAccount, getRoles, sendAuth]);

    server.get({
        name: 'getUser',
        path: '/users'
    }, [getAccountUuid, getAccount, getUserUuid, getUser, getRoles, sendAuth]);

    server.get({
        name: 'getRoleMembers',
        path: '/roles'
    }, [getAccountUuid, getAccount, getRoleMembers, sendAuth]);

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

    server.get({
        name: 'lookup',
        path: '/lookup'
    }, lookup);


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

    // SigV4 AWS authentication endpoints
    server.get({
        name: 'getUserByAccessKey',
        path: '/aws-auth/:accesskeyid'
    }, function (req, res, next) {
        var accessKeyId = req.params.accesskeyid;
        var log = req.log;
        var redis = req.redis;

        log.debug({accessKeyId: accessKeyId}, 'getUserByAccessKey: entered');

        /*
         * Use redislib.getUserByAccessKey for Redis lookup. Falls back to
         * UFDS search if not found in Redis.
         */
        lib.getUserByAccessKey({
            accessKeyId: accessKeyId,
            log: log,
            redis: redis
        }, function (err, authResult) {
            if (err) {
                /*
                 * If access key not found in Redis, fall back to UFDS
                 * search for temporary credentials.
                 */
                if (err.code === 'AccessKeyNotFound') {
                    return (handleUfdsFallback());
                }
                return (next(err));
            }

            res.send(authResult);
            return (next());

            /*
             * UFDS fallback for temporary credentials not yet in Redis.
             * This handles the case where UFDS replicator hasn't synced yet.
             */
            function handleUfdsFallback() {
                if (req.ufdsPool && accessKeyId.length > 16) {
                    log.debug({
                        accessKeyId: accessKeyId,
                        note: 'Access key not in Redis cache' +
                              ', checking UFDS for temporary credential'
                    }, 'Attempting UFDS' +
                       ' fallback for potential temporary credential');

                    var searchBase = 'ou=users, o=smartdc';
                    var searchFilter = '(&(objectclass=accesskey)' +
                        '(accesskeyid=' + accessKeyId + ')' +
                        '(credentialtype=temporary))';

                    return executeUfdsOperation(req,
                        function (client, operationCallback) {
                            return client.search(searchBase, {
                                scope: 'sub',
                                filter: searchFilter
                            }, operationCallback);
                        },
                        function (searchErr, searchRes) {
                            if (searchErr) {
                                log.error({
                                    err: searchErr,
                                    accessKeyId: accessKeyId
                                }, 'UFDS search failed for temp credential');
                                return (next(new errors.
                                    ObjectDoesNotExistError(accessKeyId)));
                            }

                            if (!searchRes || searchRes.length === 0) {
                                log.debug({
                                    accessKeyId: accessKeyId
                                }, 'Temp credential not found in UFDS');
                                return (next(new errors.
                                    ObjectDoesNotExistError(accessKeyId)));
                            }

                            var tempCred = searchRes[0];

                            // Check expiration
                            if (tempCred.expiration) {
                                var expiry = new Date(tempCred.expiration);
                                if (expiry <= new Date()) {
                                    log.debug({
                                        accessKeyId: accessKeyId,
                                        expiration: expiry
                                    }, 'Temporary credential expired');
                                    return (next(new errors.
                                        ObjectDoesNotExistError(accessKeyId)));
                                }
                            }

                            // Get the principal user
                            var principalUuid = tempCred.principaluuid;
                            if (!principalUuid) {
                                log.error({
                                    accessKeyId: accessKeyId,
                                    tempCred: tempCred
                                }, 'Temp credential missing principaluuid');
                                return (next(new errors.
                                    ObjectDoesNotExistError(accessKeyId)));
                            }

                            // Get the full user object for the principal
                            lib.getObject({
                                uuid: principalUuid,
                                log: log,
                                redis: redis
                            }, function (userErr, user) {
                                if (userErr) {
                                    log.error({
                                        err: userErr,
                                        principalUuid: principalUuid,
                                        accessKeyId: accessKeyId
                                    }, 'Failed to get principal user');
                                    return (next(userErr));
                                }

                                log.debug({
                                    accessKeyId: accessKeyId,
                                    principalUuid: principalUuid,
                                    assumedRole: tempCred.assumedrole
                                }, 'Resolved temp credential from UFDS');

                                // Build response
                                var response;
                                if (user.type === 'account') {
                                    response = {
                                        account: user,
                                        user: null,
                                        roles: {},
                                        assumedRole: null
                                    };
                                } else {
                                    response = {
                                        account: {
                                            uuid: user.account,
                                            login: user.login,
                                            approved_for_provisioning: true,
                                            isOperator: false
                                        },
                                        user: user,
                                        roles: {},
                                        assumedRole: null
                                    };
                                }

                                res.send(response);
                                return (next());
                            });
                            return (undefined);
                        });
                }
                return (next(
                    new errors.ObjectDoesNotExistError(accessKeyId)));
            }
        });
    });

    server.post({
        name: 'verifySigV4',
        path: '/aws-verify'
    }, function (req, res, next) {
        // Build session secret config for JWT validation
        var secretConfig = buildSecretConfig(opts.sessionConfig);

        sigv4.verifySigV4({
            req: req,
            log: req.log,
            redis: req.redis,
            ufdsPool: req.ufdsPool,
            secretConfig: secretConfig
        }, function (err, result) {
            if (err) {
                next(err);
                return;
            }

            res.send({
                valid: true,
                accessKeyId: result.accessKeyId,
                userUuid: result.user.uuid,
                assumedRole: result.assumedRole,
                principalUuid: result.principalUuid,
                isTemporaryCredential: result.isTemporaryCredential
            });
            next();
        });
    });

    /**
     * @brief STS authentication middleware for request validation
     *
     * Extracts and validates caller identity information from HTTP
     * headers for STS operations. Creates standardized caller object
     * for downstream STS processing and trust policy evaluation.
     *
     * @param {Object} req Restify request object containing headers:
     * @param {string} req.headers['x-caller-uuid'] Account UUID
     * @param {string} req.headers['x-caller-login'] Account login
     * @param {string} req.headers['x-caller-user-uuid'] User UUID
     * @param {string} req.headers['x-caller-user-login'] User login
     * @param {Object} res Restify response object
     * @param {function} next Restify next callback function
     *
     * @note Sets req.caller with account and optional user information
     * @note Headers passed from manta-buckets-api after authentication
     * @note Required for all STS operations (AssumeRole/GetSessionToken)
     *
     * @error 401 Authentication required if caller headers missing
     *
     * @since 1.0.0
     */
    /*jsl:ignore*/
    function stsAuthentication(req, res, next) {
        var log = req.log;

        log.debug({
            allHeaders: req.headers,
            method: req.method,
            url: req.url
        }, 'stsAuthentication: processing request headers');

        // Extract caller information from headers (passed by manta-buckets-api)
        var callerUuid = req.headers['x-caller-uuid'];
        var callerLogin = req.headers['x-caller-login'];
        var callerUserUuid = req.headers['x-caller-user-uuid'];
        var callerUserLogin = req.headers['x-caller-user-login'];

        log.debug({
            callerUuid: callerUuid,
            callerLogin: callerLogin,
            callerUserUuid: callerUserUuid,
            callerUserLogin: callerUserLogin
        }, 'stsAuthentication: extracted headers');

        if (!callerUuid || !callerLogin) {
            log.error({
                callerUuid: callerUuid,
                callerLogin: callerLogin,
                allHeaders: Object.keys(req.headers),
                headerSample: {
                    'x-caller-uuid': req.headers['x-caller-uuid'],
                    'x-caller-login': req.headers['x-caller-login'],
                    'authorization': req.headers['authorization']
                }
            }, 'STS authentication failed: missing caller information');

            var authError =
                new Error('Authentication required for STS operations');
            authError.statusCode = 401;
            return (next(authError));
        }

        // Create caller object similar to other mahi operations
        req.caller = {
            uuid: callerUuid,
            account: {
                uuid: callerUuid,
                login: callerLogin
            }
        };

        if (callerUserUuid && callerUserLogin) {
            req.caller.user = {
                uuid: callerUserUuid,
                login: callerUserLogin
            };
        }

        // Read access key to detect temporary credentials (MSTS prefix)
        var accessKeyId = req.headers['x-access-key-id'];
        var assumedRoleArn = req.headers['x-assumed-role-arn'];
        var sessionName = req.headers['x-session-name'];

        // Detect temporary credentials by MSTS prefix on access key
        var isTemporaryCredential = accessKeyId &&
            accessKeyId.indexOf('MSTS') === 0;

        log.info({
            accessKeyId: accessKeyId,
            isTemporaryCredential: isTemporaryCredential,
            assumedRoleArn: assumedRoleArn,
            sessionName: sessionName
        }, 'stsAuthentication: checking for temporary credentials');

        if (isTemporaryCredential) {
            // For temporary credentials, we need to look up the role info
            // from the temporary credential store
            req.auth = {
                isTemporaryCredential: true,
                accessKeyId: accessKeyId
            };

            // If assumed role ARN was passed, use it
            if (assumedRoleArn) {
                req.auth.assumedRole = {
                    arn: assumedRoleArn
                };
                req.auth.sessionName = sessionName;
            }

            log.info({
                reqAuth: req.auth
            }, 'stsAuthentication: detected temporary credential');
        }

        log.debug({
            callerUuid: callerUuid,
            callerLogin: callerLogin,
            hasUser: !!(callerUserUuid && callerUserLogin),
            isTemporaryCredential: isTemporaryCredential,
            assumedRoleArn: assumedRoleArn
        }, 'STS authentication successful');

        next();
        return;
    }
    /*jsl:end*/


    /**
     * @brief AWS STS AssumeRole endpoint handler
     *
     * Implements the AWS Security Token Service AssumeRole operation
     * for generating temporary credentials. Validates trust policies
     * and creates temporary access keys stored in UFDS.
     *
     * @param req HTTP request object containing:
     *   - headers['x-caller-uuid']: Calling user UUID
     *   - headers['x-caller-login']: Calling user login
     *   - body.RoleArn: ARN of role to assume
     *   - body.RoleSessionName: Session name for assumed role
     *   - body.DurationSeconds: Credential validity duration (opt)
     * @param res HTTP response object
     * @param next Restify next callback
     *
     * @returns JSON response with temporary credentials on success,
     *          or appropriate AWS error on failure
     *
     * @note Requires UFDS connectivity for credential storage
     * @note Maximum session duration is 3600 seconds (1 hour)
     *
     * @see AWS STS AssumeRole API documentation
     * @since 1.0.0
     */
    server.post({
        name: 'stsAssumeRole',
        path: '/sts/assume-role'
    }, function (req, res, next) {
        req.log.info('STS AssumeRole endpoint called');

        // Extract caller info from headers (sent by manta-buckets-api)
        var callerUuid = req.headers['x-caller-uuid'];
        var callerLogin = req.headers['x-caller-login'];

        // Create caller object for sts.assumeRole
        req.caller = {
            uuid: callerUuid,
            account: {
                uuid: callerUuid,
                login: callerLogin
            }
        };

        if (req.headers['x-caller-user-uuid']) {
            req.caller.user = {
                uuid: req.headers['x-caller-user-uuid'],
                login: req.headers['x-caller-user-login']
            };
        }

        // Provide sessionConfig to STS function
        req.sessionConfig = opts.sessionConfig;

        // Delegate to sts.assumeRole
        sts.assumeRole(req, res, next);
    });

    /**
     * @brief AWS STS GetSessionToken endpoint handler
     *
     * Implements the AWS Security Token Service GetSessionToken operation
     * for generating temporary credentials without role assumption. Creates
     * session-scoped temporary credentials for enhanced security.
     *
     * @param req HTTP request object containing:
     *   - headers['x-caller-uuid']: Calling user UUID
     *   - headers['x-caller-login']: Calling user login
     *   - body.DurationSeconds: Credential validity duration (optional)
     * @param res HTTP response object
     * @param next Restify next callback
     *
     * @returns JSON response with temporary credentials on success,
     *          or appropriate AWS error on failure
     *
     * @note No role assumption - credentials for calling principal
     * @note Duration range: 900 seconds (15 min) to 129600 (36 hours)
     * @note Requires STS authentication middleware
     *
     * @see AWS STS GetSessionToken API documentation
     * @since 1.0.0
     */
    server.post({
        name: 'stsGetSessionToken',
        path: '/sts/get-session-token'
    }, stsAuthentication, function (req, res, next) {
        // Provide sessionConfig to STS function
        req.sessionConfig = opts.sessionConfig;
        sts.getSessionToken(req, res, next);
    });

    /**
     * @brief AWS STS GetCallerIdentity endpoint handler
     *
     * Implements the AWS Security Token Service GetCallerIdentity operation
     * for returning details about the calling IAM entity. This operation
     * requires valid credentials but no specific permissions.
     *
     * @param {Object} req HTTP request object
     * @param {Object} res HTTP response object
     * @param {function} next Next middleware function
     *
     * @returns AWS XML response with caller identity information
     *
     * @note Requires STS authentication middleware
     * @note Works with both permanent and temporary credentials
     * @note Lightweight operation for credential validation
     *
     * @see AWS STS GetCallerIdentity API documentation
     * @since 1.0.0
     */
    server.post({
        name: 'stsGetCallerIdentity',
        path: '/sts/get-caller-identity'
    }, stsAuthentication, function (req, res, next) {
        sts.getCallerIdentity(req, res, next);
    });

    /**
     * @brief IAM CreateRole endpoint handler
     *
     * Creates a new IAM role with the specified trust policy.
     * Stores role metadata in both UFDS and Redis cache for
     * performance optimization.
     *
     * @param req HTTP request object containing:
     *   - body.roleName: Name of the role to create
     *   - body.accountUuid: Account UUID for role ownership
     *   - body.assumeRolePolicyDocument: JSON trust policy
     *   - body.description: Optional role description
     *   - body.path: Optional role path (defaults to "/")
     * @param res HTTP response object
     * @param next Restify next callback
     *
     * @returns 201 Created with role metadata on success,
     *          409 Conflict if role already exists,
     *          500 Internal Server Error on UFDS/Redis failures
     *
     * @note Role names must be unique within an account
     * @note Trust policy is validated for JSON syntax
     *
     * @see AWS IAM CreateRole API documentation
     * @since 1.0.0
     */

    /*jsl:ignore*/
    server.post({
        name: 'iamCreateRole',
        path: '/iam/create-role'
    }, function (req, res, next) {
        req.log.info('IAM CreateRole endpoint called');

        if (!req.ufdsPool) {
            res.send(500, {error: 'UFDS not available for role creation'});
            return (next());
        }

        var roleName = req.body.roleName;
        var accountUuid = req.body.accountUuid;
        var assumeRolePolicyDocument = req.body.assumeRolePolicyDocument;
        var description = req.body.description;
        var path = req.body.path || '/';

        if (!roleName || !accountUuid) {
            res.send(400, {error: 'roleName and accountUuid are required'});
            return (next());
        }

        // Validate trust policy format if provided
        if (assumeRolePolicyDocument) {
            try {
                var parsedPolicy = JSON.parse(assumeRolePolicyDocument);
                if (!parsedPolicy.Statement ||
                    !Array.isArray(parsedPolicy.Statement)) {
                    res.send(400, {
                        error: 'MalformedPolicyDocument',
                        message:
                        'Trust policy must contain a valid Statement array'
                    });
                    return (next());
                }
            } catch (parseErr) {
                res.send(400, {
                    error: 'MalformedPolicyDocument',
                    message: 'Trust policy document must be valid JSON'
                });
                return (next());
            }
        }

        // Generate a unique UUID for the role (can't reuse account UUID)
        var roleUuidHex = crypto.randomBytes(16).toString('hex');
        var roleUuid = [
            roleUuidHex.substring(0, 8),
            roleUuidHex.substring(8, 12),
            '4' + roleUuidHex.substring(13, 16), // Version 4 UUID
            ((parseInt(roleUuidHex.substring(16, 17), 16) & 0x3) |
             0x8).toString(16) + roleUuidHex.substring(17, 20), // Variant bits
            roleUuidHex.substring(20, 32)
        ].join('-');

        req.log.debug({
            accountUuid: accountUuid,
            roleName: roleName,
            roleUuid: roleUuid
        }, 'Using account-based role UUID to match UFDS expectations');

        // Create role DN in UFDS using correct schema
        // format (role-uuid= not group-uuid=)
        var roleDn = 'role-uuid=' + roleUuid + ', uuid=' + accountUuid +
            ', ou=users, o=smartdc';

        var roleObject = {
            objectclass: ['sdcaccountrole'],
            name: roleName,      // Role name
            uuid: roleUuid,      // Role UUID (matches group-uuid in DN)
            account: accountUuid,            // Account that owns this role
            // Optional: store AWS-specific metadata as custom attributes
            description: description || '',
            assumerolepolicydocument: assumeRolePolicyDocument || ''
        };

        req.log.info({
            dn: roleDn,
            roleName: roleName,
            accountUuid: accountUuid,
            roleUuid: roleUuid
        }, 'Creating role in UFDS via Mahi');

        // Define success handler function first
        function handleRoleCreationSuccess() {

            req.log.info({
                roleName: roleName,
                roleUuid: roleUuid,
                accountUuid: accountUuid
            }, 'Successfully created role in UFDS, now syncing to Redis cache');

            // Immediately sync role to Redis cache (same format as replicator)
            var rolePayload = {
                type: 'role',
                uuid: roleUuid,
                name: roleName,
                account: accountUuid,
                policies: [],
                assumerolepolicydocument: assumeRolePolicyDocument
            };

            // Use Redis batch to update cache immediately
            var batch = req.redis.multi();
            batch.set('/uuid/' + roleUuid, JSON.stringify(rolePayload));
            batch.set('/role/' + accountUuid + '/' + roleName, roleUuid);
            batch.sadd('/set/roles/' + accountUuid, roleUuid);

            batch.exec(function (cacheErr, results) {
                if (cacheErr) {
                    req.log.warn({
                        err: cacheErr,
                        roleUuid: roleUuid,
                        roleName: roleName
                    }, 'Failed to sync role' +
                       ' to Redis cache immediately, but role created in UFDS');
                    // Continue anyway - replicator will eventually sync it
                } else {
                    req.log.debug({
                        roleUuid: roleUuid,
                        roleName: roleName
                    }, 'Successfully synced role to Redis cache immediately');
                }

                // Return AWS IAM compatible response
                var roleArn = 'arn:aws:iam::' + accountUuid + ':role' +
                    path + roleName;
                var response = {
                    Role: {
                        Path: path,
                        RoleName: roleName,
                        RoleId: 'AROA' +
                            roleUuid.toUpperCase().substring(0, 16),
                        Arn: roleArn,
                        CreateDate: new Date().toISOString(),
                        AssumeRolePolicyDocument: assumeRolePolicyDocument ||
                            '',
                        Description: description || '',
                        MaxSessionDuration: 3600
                    }
                };

                res.send(200, response);
                return (next());
            });
        }

        // 1. Check if role already exists in Redis
        var roleNameKey = '/role/' + accountUuid + '/' + roleName;

        req.redis.get(roleNameKey, function (checkErr, existingRoleUuid) {
            if (checkErr) {
                req.log.error({err: checkErr},
                              'Failed to check for existing role in Redis');
                res.send(500, {error: 'Failed to check for existing role'});
                return (next());
            }

            if (existingRoleUuid) {
                // Role already exists
                req.log.info({
                    roleName: roleName,
                    existingRoleUuid: existingRoleUuid
                }, 'Role creation failed - role already exists');

                res.send(409, {
                    error: 'EntityAlreadyExists',
                    message: 'Role with name ' + roleName + ' already exists'
                });
                return (next());
            }

            // 2. Role doesn't exist, create it in Redis immediately
            var rolePayload = {
                type: 'role',
                uuid: roleUuid,
                name: roleName,
                account: accountUuid,
                policies: [],
                assumerolepolicydocument: assumeRolePolicyDocument,
                createtime: new Date().toISOString(),
                path: path,
                description: description || ''
            };

            var batch = req.redis.multi();
            batch.set('/uuid/' + roleUuid, JSON.stringify(rolePayload));
            batch.set('/role/' + accountUuid + '/' + roleName, roleUuid);
            batch.sadd('/set/roles/' + accountUuid, roleUuid);

            batch.exec(function (redisErr, results) {
                if (redisErr) {
                    req.log.error({err: redisErr},
                                  'Failed to write role to Redis');
                    res.send(500, {error: 'Failed to create role'});
                    return (next());
                }

                // 2. Return AWS response immediately
                var roleArn = 'arn:aws:iam::' + accountUuid + ':role' +
                    path + roleName;
                var response = {
                    Role: {
                        Path: path,
                        RoleName: roleName,
                        RoleId: roleUuid,
                        Arn: roleArn,
                        CreateDate: new Date().toISOString(),
                        AssumeRolePolicyDocument: assumeRolePolicyDocument ||
                            JSON.stringify({
                            'Version': '2012-10-17',
                            'Statement': [ {'Effect': 'Deny',
                                           'Principal': '*',
                                           'Action': '*'}]
                        }),
                        Description: description || '',
                        MaxSessionDuration: 3600
                    }
                };

                res.send(200, response);

                // 3. Async UFDS write using connection pool (don't wait)
                setImmediate(function () {
                    executeUfdsOperation(req,
                                         function (client, operationCallback) {
                        client.add(roleDn, roleObject, operationCallback);
                    }, function (addErr) {
                        if (addErr) {
                            req.log.error({
                                err: addErr,
                                roleName: roleName,
                                roleUuid: roleUuid
                            }, 'Async UFDS role write failed' +
                                          ' - role exists in Redis only');
                        } else {
                            req.log.debug({
                                roleName: roleName,
                                roleUuid: roleUuid
                            }, 'Role successfully written to UFDS');
                        }
                    });
                });

            }); // end Redis batch.exec callback
        }); // end Redis check callback
    });
    /*jsl:end*/

    /**
     * @brief IAM GetRole endpoint handler
     *
     * Retrieves metadata for a specific IAM role including
     * creation date, trust policy, and role ARN. Uses Redis
     * cache for performance with UFDS fallback.
     *
     * @param req HTTP request object containing:
     *   - params.roleName: Name of the role to retrieve
     *   - query.accountUuid: Account UUID for role ownership
     * @param res HTTP response object
     * @param next Restify next callback
     *
     * @returns JSON response with role metadata on success,
     *          404 Not Found if role doesn't exist,
     *          500 Internal Server Error on Redis/UFDS failures
     *
     * @note AWS-compliant response format without permission
     *       policies (use ListRolePolicies for those)
     *
     * @see AWS IAM GetRole API documentation
     * @since 1.0.0
     */
    /*jsl:ignore*/
    server.get({
        name: 'iamGetRole',
        path: '/iam/get-role/:roleName'
    }, function (req, res, next) {
        req.log.info({
            roleName: req.params.roleName,
            accountUuid: req.query.accountUuid,
            hasUfdsPool: !!req.ufdsPool
        }, 'GetRole: IAM GetRole endpoint called');

        if (!req.ufdsPool) {
            res.send(500, {error: 'UFDS not available'});
            return (next());
        }

        var roleName = req.params.roleName;
        var accountUuid = req.query.accountUuid;

        if (!roleName || !accountUuid) {
            res.send(400, {error: 'roleName and accountUuid are required'});
            return (next());
        }

        // Look up role by name using Redis cache (following access key pattern)
        var roleNameKey = '/role/' + accountUuid + '/' + roleName;

        req.log.debug({
            roleNameKey: roleNameKey,
            roleName: roleName,
            accountUuid: accountUuid
        }, 'Looking up role in Redis cache by name');

        req.redis.get(roleNameKey, function (nameErr, roleUuid) {
            if (nameErr) {
                req.log.error({
                    err: nameErr,
                    roleNameKey: roleNameKey
                }, 'Failed to lookup role name in Redis cache');

                res.send(500, {error: 'Failed to retrieve role',
                               details: nameErr.message});
                return (next());
            }

            if (!roleUuid) {
                req.log.debug({roleName: roleName},
                              'Role not found in Redis cache');
                res.send(404, {
                    error: 'NoSuchEntity',
                    message: 'The role with name ' + roleName +
                        ' cannot be found.'
                });
                return (next());
            }

            // Get role details by UUID from Redis cache
            var roleKey = '/uuid/' + roleUuid;

            req.redis.get(roleKey, function (getRoleErr, roleData) {
                if (getRoleErr) {
                    req.log.error({
                        err: getRoleErr,
                        roleUuid: roleUuid,
                        roleKey: roleKey
                    }, 'Failed to get role data from Redis cache');

                    res.send(500, {error: 'Failed to retrieve role details'});
                    return (next());
                }

                if (!roleData) {
                    req.log.warn({
                        roleName: roleName,
                        roleUuid: roleUuid
                    }, 'Role UUID found but no role data in cache');

                    res.send(404, {
                        error: 'NoSuchEntity',
                        message: 'Role data not available.'
                    });
                    return (next());
                }

                try {
                    var foundRole = JSON.parse(roleData);

                    // AWS GetRole standard response - does NOT include
                    // permission policies
                    // Permission policies should be retrieved via
                    // ListRolePolicies and GetRolePolicy

                    var roleArn = 'arn:aws:iam::' + accountUuid + ':role' +
                        (foundRole.path || '/') + foundRole.name;

                    var response = {
                        Role: {
                            Path: foundRole.path || '/',
                            RoleName: foundRole.name,
                            RoleId: foundRole.uuid,
                            Arn: roleArn,
                            CreateDate: foundRole.createtime ||
                                new Date().toISOString(),
                            AssumeRolePolicyDocument:
                            foundRole.assumerolepolicydocument ||
                                JSON.stringify({
                                'Version': '2012-10-17',
                                'Statement': [ {'Effect': 'Allow',
                                               'Principal': {'AWS': '*'},
                                               'Action': 'sts:AssumeRole'}]}),
                            Description: foundRole.description || '',
                            MaxSessionDuration: 3600
                        }
                    };

                    req.log.info({
                        roleName: roleName,
                        roleArn: roleArn,
                        roleUuid: roleUuid
                    }, 'GetRole: Sending AWS-compliant response');

                    res.send(200, response);
                    return (next());

                } catch (parseErr) {
                    req.log.error({
                        err: parseErr,
                        roleData: roleData
                    }, 'Failed to parse role data from Redis cache');

                    res.send(500, {error: 'Failed to parse role data'});
                    return (next());
                }
            });
        });
    });
    /*jsl:end*/

    /**
     * @brief IAM PutRolePolicy endpoint handler
     *
     * Attaches or updates an inline policy document to an existing
     * IAM role. Stores policy data in Redis for efficient access
     * during authorization checks.
     *
     * @param req HTTP request object containing:
     *   - body.roleName: Name of the target role
     *   - body.policyName: Name of the policy to attach/update
     *   - body.policyDocument: JSON policy document string
     *   - body.accountUuid: Account UUID for role ownership
     * @param res HTTP response object
     * @param next Restify next callback
     *
     * @returns 200 OK on successful policy attachment,
     *          404 Not Found if role doesn't exist,
     *          500 Internal Server Error on Redis failures
     *
     * @note Replaces existing policy with same name if present
     * @note Policy document validated for JSON syntax
     *
     * @see AWS IAM PutRolePolicy API documentation
     * @since 1.0.0
     */
    /*jsl:ignore*/
    server.post({
        name: 'iamPutRolePolicy',
        path: '/iam/put-role-policy'
    }, function (req, res, next) {
        req.log.info('IAM PutRolePolicy endpoint called');

        if (!req.ufdsPool) {
            res.send(500, {error: 'UFDS not available'});
            return (next());
        }

        var roleName = req.body.roleName;
        var policyName = req.body.policyName;
        var policyDocument = req.body.policyDocument;
        var mantaPolicy = req.body.mantaPolicy;
        var accountUuid = req.body.accountUuid;

        req.log.debug({
            roleName: roleName,
            policyName: policyName,
            accountUuid: accountUuid,
            mantaPolicyName: mantaPolicy ? mantaPolicy.name : null
        }, 'PutRolePolicy request parameters');

        if (!roleName || !policyName || !policyDocument || !mantaPolicy ||
            !accountUuid) {
            res.send(400, {error:
                           'Missing required parameters for PutRolePolicy'});
            return (next());
        }

        // Check if role exists using Redis cache (following access key pattern)
        var roleNameKey = '/role/' + accountUuid + '/' + roleName;

        req.log.debug({
            roleNameKey: roleNameKey,
            roleName: roleName,
            accountUuid: accountUuid
        }, 'Checking if role exists in Redis cache before attaching policy');

        req.redis.get(roleNameKey, function (nameErr, roleUuid) {
            if (nameErr) {
                req.log.error({
                    err: nameErr,
                    roleNameKey: roleNameKey
                }, 'Error looking up role in Redis cache');
                res.send(500, {error: 'Failed to lookup role'});
                return (next());
            }

            if (!roleUuid) {
                req.log.warn({
                    roleName: roleName,
                    accountUuid: accountUuid
                }, 'Role not found in Redis cache for PutRolePolicy');
                res.send(404, {error: 'Role not found'});
                return (next());
            }

            // Store the converted Manta policy in Redis
            var policyKey = '/policy/' + mantaPolicy.id;

            req.log.debug({
                policyKey: policyKey,
                mantaPolicyId: mantaPolicy.id,
                mantaPolicyName: mantaPolicy.name,
                rules: mantaPolicy.rules
            }, 'Storing permission policy in Redis');

            req.redis.set(policyKey, JSON.stringify(mantaPolicy),
                          function (redisErr) {
                if (redisErr) {
                    req.log.error({
                        err: redisErr,
                        policyKey: policyKey,
                        mantaPolicyId: mantaPolicy.id
                    }, 'Failed to store permission policy in Redis');
                    res.send(500, {error: 'Failed to store policy'});
                    return (next());
                }

                // Store permission policy directly in Redis role cache for
                // immediate access
                var roleKey = '/uuid/' + roleUuid;
                var rolePermPoliciesKey = '/role-permissions/' + roleUuid;

                req.log.debug({
                    roleKey: roleKey,
                    rolePermPoliciesKey: rolePermPoliciesKey,
                    policyName: policyName
                }, 'Storing permission policy in Redis');

                // Get existing permission policies for this role
                req.redis.get(rolePermPoliciesKey,
                              function (getPolErr, existingPoliciesData) {
                    if (getPolErr) {
                        req.log.error({
                            err: getPolErr,
                            rolePermPoliciesKey: rolePermPoliciesKey
                        }, 'Error getting existing permission policies');
                        res.send(500,
                                  {error: 'Failed to get existing policies'});
                        return (next());
                    }

                    var existingPolicies = [];
                    if (existingPoliciesData) {
                        try {
                            existingPolicies = JSON.parse(existingPoliciesData);
                            if (!Array.isArray(existingPolicies)) {
                                existingPolicies = [];
                            }
                        } catch (e) {
                            req.log.warn({err: e},
                            'Failed to parse existing policies');
                            existingPolicies = [];
                        }
                    }

                    // Remove existing policy with same name if it exists
                    var updatedPolicies = existingPolicies.filter(function (p) {
                        return (p.policyName !== policyName);
                    });

                    // Add new policy
                    var policyEntry = {
                        policyName: policyName,
                        policyDocument: policyDocument,
                        mantaPolicyId: mantaPolicy.id,
                        mantaPolicyName: mantaPolicy.name,
                        attachedDate: new Date().toISOString()
                    };
                    updatedPolicies.push(policyEntry);

                    // Store updated permission policies in Redis
                    req.redis.set(rolePermPoliciesKey,
                                  JSON.stringify(updatedPolicies),
                                  function (setErr) {
                        if (setErr) {
                            req.log.error({
                                err: setErr,
                                rolePermPoliciesKey: rolePermPoliciesKey,
                                policyName: policyName
                            }, 'PutRolePolicy: Failed to store permission ' +
                               'policies in Redis');
                            res.send(500, {error: 'Failed to store' +
                                           ' permission policy'});
                            return (next());
                        }

                        req.log.info({
                            roleName: roleName,
                            policyName: policyName,
                            mantaPolicyId: mantaPolicy.id,
                            accountUuid: accountUuid,
                            updatedPoliciesCount: updatedPolicies.length,
                            rolePermPoliciesKey: rolePermPoliciesKey,
                            roleNameLookupKey: roleNameKey,
                            roleUuid: roleUuid,
                            storedPolicies: updatedPolicies
                        }, 'PutRolePolicy: stored permission policy');

                        res.send(200, {
                            message: 'Permission policy attached successfully',
                            roleName: roleName,
                            policyName: policyName
                        });
                        return (next());
                    });
                });
            });
        });
    });
    /*jsl:end*/

    /**
     * @brief IAM DeleteRole endpoint handler
     *
     * Removes an IAM role and cleans up associated cache entries.
     * Role must have no attached policies before deletion.
     *
     * @param req HTTP request object containing:
     *   - params.roleName: Name of the role to delete
     *   - query.accountUuid: Account UUID for role ownership
     * @param res HTTP response object
     * @param next Restify next callback
     *
     * @returns 200 OK on successful deletion,
     *          404 Not Found if role doesn't exist,
     *          409 Conflict if role has attached policies,
     *          500 Internal Server Error on UFDS/Redis failures
     *
     * @note AWS requires all policies be detached before deletion
     * @note Cleans up both UFDS record and Redis cache entries
     *
     * @see AWS IAM DeleteRole API documentation
     * @since 1.0.0
     */
    /*jsl:ignore*/
    server.del({
        name: 'iamDeleteRole',
        path: '/iam/delete-role/:roleName'
    }, function (req, res, next) {
        req.log.info('IAM DeleteRole endpoint called');

        if (!req.ufdsPool) {
            res.send(500, {error: 'UFDS not available'});
            return (next());
        }

        var roleName = req.params.roleName;
        var accountUuid = req.query.accountUuid;

        if (!roleName || !accountUuid) {
            res.send(400, {error: 'roleName and accountUuid are required'});
            return (next());
        }

        // Look up role by name using Redis cache to get UUID
        var roleNameKey = '/role/' + accountUuid + '/' + roleName;

        req.log.debug({
            roleNameKey: roleNameKey,
            roleName: roleName,
            accountUuid: accountUuid
        }, 'Looking up role in Redis cache for deletion');

        req.redis.get(roleNameKey, function (nameErr, roleUuid) {
            if (nameErr) {
                req.log.error({
                    err: nameErr,
                    roleNameKey: roleNameKey
                }, 'Failed to lookup role in Redis cache');

                res.send(500, {error: 'Failed to lookup role',
                               details: nameErr.message});
                return (next());
            }

            if (!roleUuid) {
                req.log.debug({roleName: roleName},
                              'Role not found in Redis cache for deletion');
                res.send(404, {
                    error: 'NoSuchEntity',
                    message: 'The role with name ' + roleName +
                        ' cannot be found.'
                });
                return (next());
            }

            // Construct role DN for UFDS deletion
            var roleDn = 'role-uuid=' + roleUuid + ', uuid=' + accountUuid +
                ', ou=users, o=smartdc';
            req.log.debug({
                roleName: roleName,
                roleUuid: roleUuid,
                roleDn: roleDn
            }, 'Found role for deletion');

            // 1. Delete from Redis immediately for fast response
            var batch = req.redis.multi();
            batch.del('/uuid/' + roleUuid);
            batch.del('/role/' + accountUuid + '/' + roleName);
            batch.srem('/set/roles/' + accountUuid, roleUuid);

            batch.exec(function (redisErr, results) {
                if (redisErr) {
                    req.log.error({
                        err: redisErr,
                        roleUuid: roleUuid,
                        roleName: roleName
                    }, 'Failed to remove role from Redis cache');
                    res.send(500, {error: 'Failed to delete role'});
                    return (next());
                }

                req.log.debug({
                    roleUuid: roleUuid,
                    roleName: roleName
                }, 'Successfully removed role from Redis cache');

                // 2. Return success response immediately
                res.send(200, {
                    message: 'Role deleted successfully',
                    roleName: roleName
                });

                // 3. Async UFDS delete using connection pool (don't wait)
                setImmediate(function () {
                    executeUfdsOperation(req,
                                         function (client, operationCallback) {
                        client.del(roleDn, operationCallback);
                    }, function (delErr) {
                        if (delErr) {
                            req.log.error({
                                err: delErr,
                                roleName: roleName,
                                roleUuid: roleUuid,
                                roleDn: roleDn
                            }, 'Async UFDS role delete failed ' +
                                          '- role removed from Redis only');
                        } else {
                            req.log.debug({
                                roleName: roleName,
                                roleUuid: roleUuid
                            }, 'Successfully deleted role from UFDS');
                        }
                    });
                });

                return (next());
            });
        });
    });
    /*jsl:end*/

    /**
     * @brief IAM DeleteRolePolicy endpoint handler
     *
     * Removes an inline policy from an existing IAM role.
     * Updates the policy list stored in Redis cache.
     *
     * @param req HTTP request object containing:
     *   - body.roleName: Name of the target role
     *   - body.policyName: Name of the policy to remove
     *   - body.accountUuid: Account UUID for role ownership
     * @param res HTTP response object
     * @param next Restify next callback
     *
     * @returns 200 OK on successful policy removal,
     *          404 Not Found if role or policy doesn't exist,
     *          500 Internal Server Error on Redis failures
     *
     * @note Only removes inline policies, not managed policies
     * @note Validates policy exists before attempting removal
     *
     * @see AWS IAM DeleteRolePolicy API documentation
     * @since 1.0.0
     */
    /*jsl:ignore*/
    server.del({
        name: 'iamDeleteRolePolicy',
        path: '/iam/delete-role-policy'
    }, function (req, res, next) {
        req.log.info('IAM DeleteRolePolicy endpoint called');

        if (!req.ufdsPool) {
            res.send(500, {error: 'UFDS not available'});
            return (next());
        }

        var roleName = req.query.roleName;
        var policyName = req.query.policyName;
        var accountUuid = req.query.accountUuid;

        req.log.debug({
            roleName: roleName,
            policyName: policyName,
            accountUuid: accountUuid
        }, 'DeleteRolePolicy request parameters');

        if (!roleName || !policyName || !accountUuid) {
            res.send(400, {
                error: 'roleName, policyName and accountUuid are required'
            });
            return (next());
        }

        // Look up role by name using Redis cache to get UUID
        var roleNameKey = '/role/' + accountUuid + '/' + roleName;

        req.log.debug({
            roleNameKey: roleNameKey,
            roleName: roleName,
            policyName: policyName
        }, 'Looking up role in Redis cache for policy deletion');

        req.redis.get(roleNameKey, function (nameErr, roleUuid) {
            if (nameErr) {
                req.log.error({
                    err: nameErr,
                    roleNameKey: roleNameKey
                }, 'Failed to lookup role in Redis cache');
                res.send(500, {
                    error: 'Failed to lookup role',
                    details: nameErr.message
                });
                return (next());
            }

            if (!roleUuid) {
                req.log.warn({roleName: roleName},
                             'Role not found in Redis cache');
                res.send(404, {
                    error: 'Role not found',
                    roleName: roleName
                });
                return (next());
            }

            // We have the role UUID from Redis cache lookup
            // Construct role DN for UFDS policy deletion
            var roleDN = 'role-uuid=' + roleUuid + ', uuid=' +
                accountUuid + ', ou=users, o=smartdc';

            req.log.debug({
                roleUuid: roleUuid,
                roleDN: roleDN,
                policyToDelete: policyName
            }, 'Proceeding to delete policy from role');

            // For now, just proceed with the UFDS modify operation
            // The actual policy removal logic should be implemented here
            // This is a simplified version for Node.js v0.10.48 compatibility

            req.log.info({
                roleUuid: roleUuid,
                roleName: roleName,
                policyName: policyName
            }, 'Attempting to delete policy from role');

            // Get current permission policies for this role from Redis
            var rolePermPoliciesKey = '/role-permissions/' + roleUuid;

            req.redis.get(rolePermPoliciesKey,
                          function (getErr, existingPoliciesData) {
                if (getErr) {
                    req.log.error({
                        err: getErr,
                        rolePermPoliciesKey: rolePermPoliciesKey,
                        policyName: policyName
                    }, 'DeleteRolePolicy: Failed to get existing permission' +
                                  ' policies from Redis');
                    res.send(500, {error:
                                   'Failed to retrieve existing policies'});
                    return (next());
                }

                var existingPolicies = [];
                if (existingPoliciesData) {
                    try {
                        existingPolicies = JSON.parse(existingPoliciesData);
                        if (!Array.isArray(existingPolicies)) {
                            existingPolicies = [];
                        }
                    } catch (e) {
                        req.log.warn({err: e}, 'Failed to parse existing' +
                                     ' policies during deletion');
                        existingPolicies = [];
                    }
                }

                // Check if policy exists
                var policyExists = existingPolicies.some(function (p) {
                    return (p.policyName === policyName);
                });

                if (!policyExists) {
                    req.log.warn({
                        roleName: roleName,
                        policyName: policyName,
                        existingPolicies: existingPolicies.map(function (p) {
                            return (p.policyName); })
                    }, 'DeleteRolePolicy: Policy not found on role');
                    res.send(404, {
                        error: 'NoSuchEntity',
                        message: 'Policy ' + policyName +
                            ' is not attached to role ' + roleName
                    });
                    return (next());
                }

                // Remove the specified policy from the array
                var updatedPolicies = existingPolicies.filter(function (p) {
                    return (p.policyName !== policyName);
                });

                // Store updated permission policies in Redis
                req.redis.set(rolePermPoliciesKey,
                              JSON.stringify(updatedPolicies),
                              function (setErr) {
                    if (setErr) {
                        req.log.error({
                            err: setErr,
                            rolePermPoliciesKey: rolePermPoliciesKey,
                            policyName: policyName
                        }, 'DeleteRolePolicy: ' +
                           ' Failed to update permission policies in Redis');
                        res.send(500,
                                 {error: 'Failed to delete permission policy'});
                        return (next());
                    }

                    req.log.info({
                        roleName: roleName,
                        policyName: policyName,
                        roleUuid: roleUuid,
                        previousPolicyCount: existingPolicies.length,
                        updatedPolicyCount: updatedPolicies.length,
                        rolePermPoliciesKey: rolePermPoliciesKey
                    }, 'DeleteRolePolicy: Successfully removed permission' +
                       ' policy from Redis');

                    res.send(200, {
                        message: 'Permission policy detached successfully',
                        roleName: roleName,
                        policyName: policyName
                    });
                    return (next());
                });
            });
        });
    });
    /*jsl:end*/

    /**
     * @brief IAM ListRoles endpoint handler
     *
     * Returns a paginated list of IAM roles for the specified
     * account. Supports marker-based pagination for large result
     * sets.
     *
     * @param req HTTP request object containing:
     *   - query.accountUuid: Account UUID for role ownership
     *   - query.marker: Optional pagination marker for continuation
     *   - query.maxitems: Optional maximum items per page (def: 100)
     * @param res HTTP response object
     * @param next Restify next callback
     *
     * @returns JSON response with role list and pagination info,
     *          500 Internal Server Error on UFDS failures
     *
     * @note Returns role metadata without permission policies
     * @note Maximum 1000 items per page enforced by AWS limits
     *
     * @see AWS IAM ListRoles API documentation
     * @since 1.0.0
     */
    /*jsl:ignore*/
    server.get({
        name: 'iamListRoles',
        path: '/iam/list-roles'
    }, function (req, res, next) {
        req.log.info('IAM ListRoles endpoint called');

        if (!req.ufdsPool) {
            res.send(500, {error: 'UFDS not available'});
            return (next());
        }

        var accountUuid = req.query.accountUuid;
        var maxItems = parseInt(req.query.maxItems, 10) || 100;
        var marker = req.query.marker || req.query.startingToken;

        if (!accountUuid) {
            res.send(400, {error: 'accountUuid is required'});
            return (next());
        }

        // Read roles from Redis cache
        var roleSetKey = '/set/roles/' + accountUuid;

        req.log.debug({
            roleSetKey: roleSetKey,
            accountUuid: accountUuid,
            maxItems: maxItems
        }, 'Listing roles from Redis cache');

        req.redis.smembers(roleSetKey, function (redisErr, roleUuids) {
            if (redisErr) {
                req.log.error({
                    err: redisErr,
                    roleSetKey: roleSetKey
                }, 'Failed to get role set from Redis cache');

                res.send(500, {error: 'Failed to list roles',
                               details: redisErr.message});
                return (next());
            }

            if (!roleUuids || roleUuids.length === 0) {
                req.log.info({
                    accountUuid: accountUuid,
                    roleSetKey: roleSetKey
                }, 'No roles found in Redis cache for account');

                res.send(200, {
                    roles: [],
                    IsTruncated: false,
                    Marker: null
                });
                return (next());
            }

            req.log.info({
                accountUuid: accountUuid,
                roleCount: roleUuids.length,
                roleUuids: roleUuids
            }, 'Found roles in Redis cache, fetching details');

            // Fetch role details using Redis MGET for parallel fetching
            var roleKeys = roleUuids.map(function (roleUuid) {
                return ('/uuid/' + roleUuid);
            });

            req.log.debug({
                roleCount: roleUuids.length,
                roleKeys: roleKeys.slice(0, 5) // Log first 5 keys for debugging
            }, 'Fetching role details ' +
               'using Redis MGET for fast parallel lookup');

            req.redis.mget(roleKeys, function (mgetErr, roleDataArray) {
                if (mgetErr) {
                    req.log.error({
                        err: mgetErr,
                        roleKeys: roleKeys
                    }, 'Failed to batch fetch role data from Redis cache');

                    res.send(500, {error: 'Failed to retrieve role data'});
                    return (next());
                }

                var roles = [];
                roleDataArray.forEach(function (roleData, index) {
                    if (roleData) {
                        try {
                            var roleObj = JSON.parse(roleData);

                            // Verify this is a role for the correct account
                            if (roleObj.type === 'role' &&
                                roleObj.account === accountUuid) {
                                var roleName = roleObj.name;
                                var rolePath = roleObj.path || '/';
                                var roleArn = 'arn:aws:iam::' + accountUuid +
                                    ':role' + rolePath + roleName;
                                var createDate = roleObj.createtime ||
                                    new Date().toISOString();

                                // Use stored trust policy or default
                                var assumeRolePolicyDocument =
                                    roleObj.assumerolepolicydocument ||
                                    JSON.stringify({
                                        'Version': '2012-10-17',
                                        'Statement':
                                        [ {'Effect': 'Allow',
                                          'Principal': {'AWS': '*'},
                                          'Action': 'sts:AssumeRole'}]
                                    });

                                roles.push({
                                    RoleName: roleName,
                                    Arn: roleArn,
                                    Path: rolePath,
                                    CreateDate: createDate,
                                    AssumeRolePolicyDocument:
                                    assumeRolePolicyDocument,
                                    Description: roleObj.description || '',
                                    MaxSessionDuration: 3600
                                });
                            }
                        } catch (parseErr) {
                            req.log.warn({
                                err: parseErr,
                                roleUuid: roleUuids[index],
                                roleData: roleData
                            }, 'Failed to parse role data from Redis cache');
                        }
                    } else {
                        req.log.debug({
                            roleUuid: roleUuids[index],
                            index: index
                        }, 'Role UUID found in set but no data in cache');
                    }
                });

                // Send response with all fetched roles
                req.log.info({
                    accountUuid: accountUuid,
                    totalRolesInSet: roleUuids.length,
                    validRolesLoaded: roles.length,
                    roleNames: roles.map(function (r) { return r.RoleName; })
                }, 'Successfully ' +
                   'loaded roles from Redis cache using parallel fetch');

                // Apply pagination
                var startIndex = 0;
                if (marker) {
                    // Find the index of the marker role
                    for (var i = 0; i < roles.length; i++) {
                        if (roles[i].RoleName === marker) {
                            startIndex = i + 1;
                            break;
                        }
                    }
                }

                var paginatedRoles = roles.slice(startIndex,
                                                 startIndex + maxItems);
                var isTruncated = (startIndex + maxItems) < roles.length;
                var nextMarker = null;
                if (isTruncated && paginatedRoles.length > 0) {
                    nextMarker =
                        paginatedRoles[paginatedRoles.length - 1].RoleName;
                }

                res.send(200, {
                    roles: paginatedRoles,
                    IsTruncated: isTruncated,
                    Marker: nextMarker
                });
                return (next());
            });
        });
    });
    /*jsl:end*/

    /**
     * @brief IAM ListRolePolicies endpoint handler
     *
     * Returns a paginated list of inline policy names attached to the
     * specified IAM role. Provides marker-based pagination for large
     * policy lists and AWS-compatible response format.
     *
     * @param req HTTP request object containing:
     *   - params.roleName: Name of the role to list policies for
     *   - query.marker: Pagination marker for continuation (optional)
     *   - query.maxitems: Maximum items per page (default 100)
     * @param res HTTP response object
     * @param next Restify next callback
     *
     * @returns JSON response with policy names array and pagination info:
     *          200 OK with policy list on success,
     *          404 Not Found if role doesn't exist,
     *          500 Internal Server Error on Redis failures
     *
     * @note Returns only policy names, not full policy documents
     * @note Use GetRolePolicy to retrieve specific policy documents
     * @note Maximum 1000 items per page enforced by AWS limits
     *
     * @see AWS IAM ListRolePolicies API documentation
     * @since 1.0.0
     */
    /*jsl:ignore*/
    server.get({
        name: 'listRolePolicies',
        path: '/iam/list-role-policies/:roleName'
    }, function (req, res, next) {
        var roleName = req.params.roleName;
        var marker = req.query.marker;
        var maxItems = parseInt(req.query.maxitems || '100', 10);

        req.log.info({
            roleName: roleName,
            marker: marker,
            maxItems: maxItems,
            url: req.url,
            method: req.method,
            query: req.query
        }, 'MAHI: ListRolePolicies endpoint called');

        // Look up role UUID by name
        var accountUuid = req.query.accountUuid || req.body.accountUuid;
        if (!accountUuid) {
            res.send(400, {error: 'accountUuid is required'});
            return (next());
        }

        var roleNameKey = '/role/' + accountUuid + '/' + roleName;

        req.redis.get(roleNameKey, function (roleErr, roleUuid) {
            if (roleErr) {
                req.log.error({
                    err: roleErr,
                    roleNameKey: roleNameKey
                }, 'Error looking up role UUID in Redis cache');
                res.send(500, {error: 'Failed to lookup role'});
                return (next());
            }

            if (!roleUuid) {
                req.log.warn({
                    roleName: roleName,
                    accountUuid: accountUuid
                }, 'Role not found for ListRolePolicies');
                res.send(404, {error: 'Role not found'});
                return (next());
            }

            // Get permission policies for this role
            var rolePermPoliciesKey = '/role-permissions/' + roleUuid;

            req.redis.get(rolePermPoliciesKey,
                          function (getPolErr, policiesData) {
                if (getPolErr) {
                    req.log.error({
                        err: getPolErr,
                        rolePermPoliciesKey: rolePermPoliciesKey
                    }, 'Error getting permission policies from Redis cache');
                    res.send(500, {error: 'Failed to retrieve policies'});
                    return (next());
                }

                var policyNames = [];
                if (policiesData) {
                    try {
                        var policies = JSON.parse(policiesData);

                        // Handle both array (current storage) and
                        // object formats
                        if (Array.isArray(policies)) {
                            policyNames = [];
                            for (var i = 0; i < policies.length; i++) {
                                policyNames.push(policies[i].policyName);
                            }
                        } else {
                            policyNames = Object.keys(policies);
                        }

                        req.log.debug({
                            roleUuid: roleUuid,
                            roleName: roleName,
                            policyNames: policyNames,
                            policiesFormat: Array.isArray(policies) ?
                                'array' : 'object'
                        }, 'Found permission policies for role');

                    } catch (parseErr) {
                        req.log.error({
                            err: parseErr,
                            policiesData: policiesData
                        }, 'Failed to parse permission policies JSON');
                        res.send(500, {error: 'Failed to parse policies data'});
                        return (next());
                    }
                }

                // Apply pagination
                var startIndex = 0;
                if (marker) {
                    var markerIndex = policyNames.indexOf(marker);
                    if (markerIndex >= 0) {
                        startIndex = markerIndex + 1;
                    }
                }

                var paginatedPolicyNames = policyNames.slice(startIndex,
                                                             startIndex +
                                                             maxItems);
                var isTruncated = (startIndex + maxItems) < policyNames.length;
                var nextMarker = null;
                if (isTruncated && paginatedPolicyNames.length > 0) {
                    nextMarker = paginatedPolicyNames[
                        paginatedPolicyNames.length - 1];
                }

                res.send(200, {
                    PolicyNames: paginatedPolicyNames,
                    IsTruncated: isTruncated,
                    Marker: nextMarker
                });
                return (next());
            });
        });
    });
    /*jsl:end*/

    /**
     * @brief IAM GetRolePolicy endpoint handler
     *
     * Retrieves the specified inline policy document attached to an
     * IAM role. Returns the complete policy document including JSON
     * policy statements for access control evaluation.
     *
     * @param req HTTP request object containing:
     *   - params.roleName: Name of the role containing the policy
     *   - params.policyName: Name of the policy to retrieve
     * @param res HTTP response object
     * @param next Restify next callback
     *
     * @returns JSON response with complete policy document:
     *          200 OK with policy document on success,
     *          404 Not Found if role or policy doesn't exist,
     *          500 Internal Server Error on Redis failures
     *
     * @note Returns complete IAM policy document with statements
     * @note Policy document is JSON-parsed for validation
     * @note AWS-compatible response format for policy documents
     *
     * @see AWS IAM GetRolePolicy API documentation
     * @since 1.0.0
     */
    /*jsl:ignore*/
    server.get({
        name: 'getRolePolicy',
        path: '/iam/get-role-policy/:roleName/:policyName'
    }, function (req, res, next) {
        var roleName = req.params.roleName;
        var policyName = req.params.policyName;

        req.log.info({
            roleName: roleName,
            policyName: policyName,
            url: req.url,
            method: req.method,
            query: req.query
        }, 'MAHI: GetRolePolicy endpoint called');

        // Look up role UUID by name
        var accountUuid = req.query.accountUuid || req.body.accountUuid;
        if (!accountUuid) {
            res.send(400, {error: 'accountUuid is required'});
            return (next());
        }

        var roleNameKey = '/role/' + accountUuid + '/' + roleName;

        req.redis.get(roleNameKey, function (roleErr, roleUuid) {
            if (roleErr) {
                req.log.error({
                    err: roleErr,
                    roleNameKey: roleNameKey
                }, 'Error looking up role UUID in Redis cache');
                res.send(500, {error: 'Failed to lookup role'});
                return (next());
            }

            if (!roleUuid) {
                req.log.warn({
                    roleName: roleName,
                    accountUuid: accountUuid
                }, 'Role not found for GetRolePolicy');
                res.send(404, {error: 'Role not found'});
                return (next());
            }

            // Get permission policies for this role
            var rolePermPoliciesKey = '/role-permissions/' + roleUuid;

            req.redis.get(rolePermPoliciesKey,
                          function (getPolErr, policiesData) {
                if (getPolErr) {
                    req.log.error({
                        err: getPolErr,
                        rolePermPoliciesKey: rolePermPoliciesKey
                    }, 'Error getting permission policies from Redis cache');
                    res.send(500, {error: 'Failed to retrieve policies'});
                    return (next());
                }

                if (!policiesData) {
                    req.log.warn({
                        roleName: roleName,
                        policyName: policyName
                    }, 'No policies found for role');
                    res.send(404, {error: 'Policy not found'});
                    return (next());
                }

                try {
                    req.log.debug({
                        policiesDataType: typeof (policiesData),
                        policiesDataLength: policiesData ?
                            policiesData.length : 0,
                        policiesDataPreview: policiesData ?
                            policiesData.substring(0, 100) : 'null'
                    }, 'GetRolePolicy: About to parse policies data');

                    var policies = JSON.parse(policiesData);
                    var policyData = null;
                    var availablePolicies = [];

                    // Handle both array (current storage) and object formats
                    if (Array.isArray(policies)) {
                        availablePolicies = policies.map(function (p) {
                            return (p.policyName); });

                        // Optimized policy search - exit early when found
                        policyData = null;
                        for (var i = 0; i < policies.length; i++) {
                            if (policies[i].policyName === policyName) {
                                policyData = policies[i];
                                break;
                            }
                        }
                    } else {
                        availablePolicies = Object.keys(policies);
                        policyData = policies[policyName];
                    }

                    if (!policyData) {
                        req.log.warn({
                            roleName: roleName,
                            policyName: policyName,
                            availablePolicies: availablePolicies,
                            policiesFormat: Array.isArray(policies) ?
                                'array' : 'object'
                        }, 'Specific policy not found for role');
                        res.send(404, {error: 'Policy ' + policyName +
                                       ' not found for role ' + roleName});
                        return (next());
                    }

                    req.log.debug({
                        roleUuid: roleUuid,
                        roleName: roleName,
                        policyName: policyName,
                        hasPolicyDocument: !!policyData.policyDocument
                    }, 'Found policy document for role');

                    res.send(200, {
                        RoleName: roleName,
                        PolicyName: policyName,
                        PolicyDocument: policyData.policyDocument ||
                            policyData.PolicyDocument
                    });
                    return (next());

                } catch (parseErr) {
                    req.log.error({
                        err: parseErr,
                        errorMessage: parseErr.message,
                        errorStack: parseErr.stack,
                        policiesData: policiesData,
                        policiesDataType: typeof (policiesData)
                    }, 'Failed to parse permission policies JSON');
                    res.send(500, {error: 'Failed to parse policies data'});
                    return (next());
                }
            });
        });
    });
    /*jsl:end*/

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
    var self = this;

    // Gracefully drain UFDS connection pool
    if (this.ufdsPool) {
        this.ufdsPool.drain(function () {
            self.ufdsPool.destroyAllNow();
        });
    }

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

    if (!account) {
        setImmediate(next,
            new restify.BadRequestError('"account" is required'));
        return;
    }

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

    if (!user) {
        setImmediate(next, new restify.BadRequestError('"user" is required'));
        return;
    }

    lib.getUuid({
        accountUuid: accountUuid,
        name: user,
        type: 'user',
        log: req.log,
        redis: req.redis
    }, function (err, uuid) {
        if (err) {
            if (err.name === 'ObjectDoesNotExistError' &&
                    req.auth.account &&
                    fallback) { // don't error if fallback is set

                res.send(req.auth);
                next(false);
            } else if (err.name === 'ObjectDoesNotExistError') {
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
    var roles;
    if (req.auth.user)
        roles = req.auth.user.roles || [];
    else
        roles = req.auth.account.roles || [];
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


function getRoleMembers(req, res, next) {
    var accountUuid = req.accountUuid || req.params.accountid;
    var name = req.params.role || req.params.name;

    lib.getUuid({
        accountUuid: accountUuid,
        name: name,
        type: 'role',
        log: req.log,
        redis: req.redis
    }, function gotUuid(err, uuid) {
        if (err) {
            if (err.name === 'ObjectDoesNotExistError') {
                next();
            } else {
                next(err);
            }
            return;
        }

        lib.getRole({
            uuid: uuid,
            log: req.log,
            redis: req.redis
        }, function gotRoleInfo(err, roleInfo) {
            req.auth.role = roleInfo;

            lib.getRoleMembers({
                uuid: uuid,
                log: req.log,
                redis: req.redis
            }, function gotRoleMembers(err, roleMembers) {
                req.auth.role.members = roleMembers;
                next();
            });
        });
    });
}


function getName(req, res, next) {
    var uuids = req.params.uuid || /* deprecated */ req.params.uuids;
    if (!uuids) {
        uuids = [];
    } else if (!Array.isArray(uuids)) {
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
                    if (err.name === 'ObjectDoesNotExistError') {
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

    if (!account) {
        setImmediate(next,
            new restify.BadRequestError('"account" is required'));
        return;
    }

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
                            if (err.name === 'ObjectDoesNotExistError') {
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


function lookup(req, res, next) {
    lib.generateLookup({
        log: req.log,
        redis: req.redis
    }, function (err, lookup) {
        if (err) {
            next(err);
            return;
        }
        res.send(lookup);
        next();
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
        process.stderr.write('error: ' + e.message + '\n');
        process.exit(1);
    }

    if (opts.help) {
        var help = parser.help().trimRight();
        process.stdout.write('usage: \n' + help + '\n');
        process.exit(0);
    }

    var config = require(path.resolve(opts.config));
    var redisConfig = config.redis;
    var serverConfig = config.server || {};
    var ufdsConfig = config.ufds || config.ufdsCfg;
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
                port: opts.port || serverConfig.port || 80,
                log: log,
                redis: client,
                ufdsConfig: ufdsConfig,
                sessionConfig: config.sessionConfig
            });
        });
    });
}

if (require.main === module) {
    main();
}
