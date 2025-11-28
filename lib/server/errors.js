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

function RoleIdDoesNotExistError(uuid) {
        MahiError.call(this, {
                restCode: 'RoleIdDoesNotExist',
                statusCode: 404,
                message: sprintf('role %s does not exist', uuid)
        });
}
util.inherits(RoleIdDoesNotExistError, MahiError);
RoleIdDoesNotExistError.prototype.name = 'RoleIdDoesNotExistError';

function PolicyIdDoesNotExistError(uuid) {
        MahiError.call(this, {
                restCode: 'PolicyIdDoesNotExist',
                statusCode: 404,
                message: sprintf('policy %s does not exist', uuid)
        });
}
util.inherits(PolicyIdDoesNotExistError, MahiError);
PolicyIdDoesNotExistError.prototype.name = 'PolicyIdDoesNotExistError';

function WrongTypeError(uuid, expected, actual) {
        MahiError.call(this, {
                restCode: 'WrongType',
                statusCode: 400,
                message: sprintf(
                        '%s expected to be type %s but was actually type %s',
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

/**
 * @brief AWS-compatible access denied error for STS operations
 *
 * Represents authentication or authorization failures in
 * STS/IAM operations, returning appropriate HTTP 403 status
 * with AWS-compatible error format.
 *
 * @param message Optional custom error message string
 *
 * @property {string} name Error class name "AccessDeniedError"
 * @property {string} restCode AWS error code "AccessDenied"
 * @property {number} statusCode HTTP status code (403)
 * @property {string} message Human-readable error description
 *
 * @extends MahiError
 *
 * @example
 * throw new AccessDeniedError("Trust policy denies access");
 *
 * @see AWS IAM Error Codes documentation
 * @since 1.0.0
 */
function AccessDeniedError(message) {
        MahiError.call(this, {
                restCode: 'AccessDenied',
                statusCode: 403,
                message: message || 'Access denied'
        });
}
util.inherits(AccessDeniedError, MahiError);
AccessDeniedError.prototype.name = 'AccessDeniedError';

/**
 * @brief AWS-compatible invalid parameter error
 *
 * Represents parameter validation failures in IAM/STS
 * operations with AWS-standard error format and HTTP 400
 * status code.
 *
 * @param message Optional custom error message string
 *
 * @property {string} name Error class name "InvalidParameterError"
 * @property {string} restCode AWS error code "InvalidParameterValue"
 * @property {number} statusCode HTTP status code (400)
 * @property {string} message Human-readable error description
 *
 * @extends MahiError
 *
 * @example
 * throw new InvalidParameterError("RoleArn is required");
 *
 * @see AWS IAM Error Codes documentation
 * @since 1.0.0
 */
function InvalidParameterError(message) {
        MahiError.call(this, {
                restCode: 'InvalidParameterValue',
                statusCode: 400,
                message: message || 'Invalid parameter value'
        });
}
util.inherits(InvalidParameterError, MahiError);
InvalidParameterError.prototype.name = 'InvalidParameterError';

/**
 * @brief AWS-compatible entity not found error
 *
 * Represents resource lookup failures (roles, policies, users)
 * in IAM operations with AWS-standard error format and HTTP
 * 404 status code.
 *
 * @param message Optional custom error message string
 *
 * @property {string} name Error class name "NoSuchEntityError"
 * @property {string} restCode AWS error code "NoSuchEntity"
 * @property {number} statusCode HTTP status code (404)
 * @property {string} message Human-readable error description
 *
 * @extends MahiError
 *
 * @example
 * throw new NoSuchEntityError("Role 'test-role' does not exist");
 *
 * @see AWS IAM Error Codes documentation
 * @since 1.0.0
 */
function NoSuchEntityError(message) {
        MahiError.call(this, {
                restCode: 'NoSuchEntity',
                statusCode: 404,
                message: message || 'The request was rejected because ' +
                    'it referenced an entity that does not exist'
        });
}
util.inherits(NoSuchEntityError, MahiError);
NoSuchEntityError.prototype.name = 'NoSuchEntityError';

/**
 * @brief AWS-compatible internal server error
 *
 * Represents unexpected server-side failures in IAM/STS
 * operations with AWS-standard error format and HTTP 500
 * status code.
 *
 * @param message Optional custom error message string
 *
 * @property {string} name Error class name "InternalError"
 * @property {string} restCode AWS error code "InternalError"
 * @property {number} statusCode HTTP status code (500)
 * @property {string} message Human-readable error description
 *
 * @extends MahiError
 *
 * @example
 * throw new InternalError("Database connection failed");
 *
 * @see AWS IAM Error Codes documentation
 * @since 1.0.0
 */
function InternalError(message) {
        MahiError.call(this, {
                restCode: 'InternalError',
                statusCode: 500,
                message: message || 'Internal server error'
        });
}
util.inherits(InternalError, MahiError);
InternalError.prototype.name = 'InternalError';

module.exports = {
        MahiError: MahiError,
        AccountDoesNotExistError: AccountDoesNotExistError,
        AccountIdDoesNotExistError: AccountIdDoesNotExistError,
        GroupDoesNotExistError: GroupDoesNotExistError,
        ObjectDoesNotExistError: ObjectDoesNotExistError,
        RedisError: RedisError,
        ReplicatorNotReadyError: ReplicatorNotReadyError,
        RoleDoesNotExistError: RoleDoesNotExistError,
        RoleIdDoesNotExistError: RoleIdDoesNotExistError,
        PolicyIdDoesNotExistError: PolicyIdDoesNotExistError,
        UserDoesNotExistError: UserDoesNotExistError,
        UserIdDoesNotExistError: UserIdDoesNotExistError,
        WrongTypeError: WrongTypeError,
        InvalidSignatureError: InvalidSignatureError,
        AccessKeyNotFoundError: AccessKeyNotFoundError,
        RequestTimeTooSkewedError: RequestTimeTooSkewedError,
        AccessDeniedError: AccessDeniedError,
        InvalidParameterError: InvalidParameterError,
        NoSuchEntityError: NoSuchEntityError,
        InternalError: InternalError
};
