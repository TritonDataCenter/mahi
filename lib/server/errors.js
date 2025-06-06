/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright (c) 2014, Joyent, Inc.
 * Copyright 2025 Edgecast Cloud LLC.
 */

var restify = require('restify');
var util = require('util');

var sprintf = util.format;
var RestError = restify.RestError;

function MahiError(obj) {
        obj.contructorOpts = this.contructor;
        RestError.call(this, obj);
}
util.inherits(MahiError, RestError);
MahiError.prototype.name = 'MahiError';

function AccountDoesNotExistError(account) {
        MahiError.call(this, {
                restCode: 'AccountDoesNotExist',
                statusCode: 404,
                message: sprintf('%s does not exist', account)
        });
}
util.inherits(AccountDoesNotExistError, MahiError);
AccountDoesNotExistError.prototype.name = 'AccountDoesNotExistError';

function AccountIdDoesNotExistError(uuid) {
        MahiError.call(this, {
                restCode: 'AccountIdDoesNotExist',
                statusCode: 404,
                message: sprintf('%s does not exist', uuid)
        });
}
util.inherits(AccountIdDoesNotExistError, MahiError);
AccountIdDoesNotExistError.prototype.name = 'AccountIdDoesNotExistError';

function GroupDoesNotExistError(group, account) {
        MahiError.call(this, {
                restCode: 'GroupDoesNotExist',
                statusCode: 404,
                message: sprintf('%s does not exist in account %s',
                        group, account)
        });
}
util.inherits(GroupDoesNotExistError, MahiError);
GroupDoesNotExistError.prototype.name = 'GroupDoesNotExistError';

function ObjectDoesNotExistError(obj) {
        MahiError.call(this, {
                restCode: 'ObjectDoesNotExist',
                statusCode: 404,
                message: sprintf('%s not found', obj)
        });
}
util.inherits(ObjectDoesNotExistError, MahiError);
ObjectDoesNotExistError.prototype.name = 'ObjectDoesNotExistError';

function RedisError(err) {
        MahiError.call(this, {
                restCode: 'RedisError',
                statusCode: 503,
                message: err.message
        });
}
util.inherits(RedisError, MahiError);
RedisError.prototype.name = 'RedisError';

function ReplicatorNotReadyError() {
        MahiError.call(this, {
                restCode: 'ReplicatorNotReady',
                statusCode: 503,
                message: 'Mahi replicator not caught up with UFDS'
        });
}
util.inherits(ReplicatorNotReadyError, MahiError);
ReplicatorNotReadyError.prototype.name = 'ReplicatorNotReadyError';

function RoleDoesNotExistError(role, account) {
        MahiError.call(this, {
                restCode: 'RoleDoesNotExist',
                statusCode: 404,
                message: sprintf('%s does not exist in account %s',
                        role, account)
        });
}
util.inherits(RoleDoesNotExistError, MahiError);
RoleDoesNotExistError.prototype.name = 'RoleDoesNotExistError';

function UserDoesNotExistError(user, account) {
        MahiError.call(this, {
                restCode: 'UserDoesNotExist',
                statusCode: 404,
                message: sprintf('user %s does not exist in account %s',
                        user, account)
        });
}
util.inherits(UserDoesNotExistError, MahiError);
UserDoesNotExistError.prototype.name = 'UserDoesNotExistError';

function UserIdDoesNotExistError(uuid) {
        MahiError.call(this, {
                restCode: 'UserIdDoesNotExist',
                statusCode: 404,
                message: sprintf('%s does not exist', uuid)
        });
}
util.inherits(UserIdDoesNotExistError, MahiError);
UserIdDoesNotExistError.prototype.name = 'UserIdDoesNotExistError';

function WrongTypeError(uuid, expected, actual) {
        MahiError.call(this, {
                restCode: 'WrongType',
                statusCode: 400,
                message: sprintf(
                        '%s expected to be type % but was actually type %s',
                        uuid, expected, actual)
        });
}
util.inherits(WrongTypeError, MahiError);
WrongTypeError.prototype.name = 'WrongTypeError';

/*
 * Error types to support SigV4 authentication scheme.
 */
function InvalidSignatureError(message) {
        MahiError.call(this, {
                restCode: 'InvalidSignature',
                statusCode: 403,
                message: message ||
                'The request signature we calculated does not match ' +
                'the signature you provided'
        });
}
util.inherits(InvalidSignatureError, MahiError);
InvalidSignatureError.prototype.name = 'InvalidSignatureError';

function AccessKeyNotFoundError(accessKeyId) {
        MahiError.call(this, {
                restCode: 'AccessKeyNotFound',
                statusCode: 404,
                message: sprintf('Access key %s not found', accessKeyId)
        });
}
util.inherits(AccessKeyNotFoundError, MahiError);
AccessKeyNotFoundError.prototype.name = 'AccessKeyNotFoundError';

function RequestTimeTooSkewedError() {
        MahiError.call(this, {
                restCode: 'RequestTimeTooSkewed',
                statusCode: 403,
                message:
                'The difference between the request time and the ' +
                'current time is too large'
        });
}
util.inherits(RequestTimeTooSkewedError, MahiError);
RequestTimeTooSkewedError.prototype.name = 'RequestTimeTooSkewedError';

module.exports = {
        MahiError: MahiError,
        AccountDoesNotExistError: AccountDoesNotExistError,
        GroupDoesNotExistError: GroupDoesNotExistError,
        ObjectDoesNotExistError: ObjectDoesNotExistError,
        RedisError: RedisError,
        ReplicatorNotReadyError: ReplicatorNotReadyError,
        RoleDoesNotExistError: RoleDoesNotExistError,
        UserDoesNotExistError: UserDoesNotExistError,
        WrongTypeError: WrongTypeError,
        InvalidSignatureError: InvalidSignatureError,
        AccessKeyNotFoundError: AccessKeyNotFoundError,
        RequestTimeTooSkewedError: RequestTimeTooSkewedError
};
