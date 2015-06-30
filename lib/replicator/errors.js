/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright (c) 2014, Joyent, Inc.
 */

var RestError = require('restify').RestError;
var WError = require('verror').WError;
var util = require('util');
var sprintf = util.format;

function MahiReplicatorError(cause, message) {
    var off = 0;
    if (cause instanceof Error) {
        off = 1;
    }

    var args = Array.prototype.slice.call(arguments, off);
    args.unshift({
        cause: off ? cause : undefined,
        constructorOpt: MahiReplicatorError
    });
    WError.apply(this, args);
}
util.inherits(MahiReplicatorError, WError);
MahiReplicatorError.prototype.name = 'MahiReplicatorError';

function UnsupportedOperationError(operation, type) {
    MahiReplicatorError.call(this,
        sprintf('unsupported operation "%s" for type "%s"', operation, type));
}
util.inherits(UnsupportedOperationError, MahiReplicatorError);
UnsupportedOperationError.prototype.name = 'UnsupportedOperationError';



function MahiReplicatorServerError(obj) {
    obj.contructorOpts = this.contructor;
    RestError.call(this, obj);
}
util.inherits(MahiReplicatorServerError, RestError);
MahiReplicatorServerError.prototype.name = 'MahiReplicatorServerError';

function RedisError(err) {
    MahiReplicatorServerError.call(this, {
        restCode: 'RedisError',
        statusCode: 500,
        message: 'redis error',
        cause: err
    });
}
util.inherits(RedisError, MahiReplicatorServerError);
RedisError.prototype.name = 'RedisError';

function RedisUnavailableError() {
    MahiReplicatorServerError.call(this, {
        restCode: 'RedisUnavailableError',
        statusCode: 500,
        message: 'redis unavailable'
    });
}
util.inherits(RedisUnavailableError, MahiReplicatorServerError);
RedisUnavailableError.prototype.name = 'RedisUnavailable';

function NotCaughtUpError() {
    MahiReplicatorServerError.call(this, {
        restCode: 'NotCaughtUp',
        statusCode: 503,
        message: 'replication not caught up'
    });
}
util.inherits(NotCaughtUpError, MahiReplicatorServerError);
NotCaughtUpError.prototype.name = 'NotCaughtUp';

module.exports = {
    MahiReplicatorError: MahiReplicatorError,
    UnsupportedOperationError: UnsupportedOperationError,

    MahiReplicatorServerError: MahiReplicatorServerError,
    RedisError: RedisError,
    RedisUnavailableError: RedisUnavailableError,
    NotCaughtUpError: NotCaughtUpError
};
