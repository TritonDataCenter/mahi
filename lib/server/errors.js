// Copyright 2014 Joyent, Inc.  All rights reserved.

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
        statusCode: 403,
        message: sprintf('%s does not exist', account)
    });
}
util.inherits(AccountDoesNotExistError, MahiError);

function GroupDoesNotExistError(group, account) {
    MahiError.call(this, {
        restCode: 'GroupDoesNotExist',
        statusCode: 403,
        message: sprintf('%s does not exist in account %s', group, account)
    });
}
util.inherits(GroupDoesNotExistError, MahiError);

function NotApprovedForProvisioningError(account) {
    MahiError.call(this, {
        restCode: 'NotApprovedForProvisioning',
        statusCode: 403,
        message: sprintf('%s is not approved for provisioning', account)
    });
}
util.inherits(NotApprovedForProvisioningError, MahiError);

function RedisError(err) {
    MahiError.call(this, {
        restCode: 'RedisError',
        statusCode: 500,
        message: err.message,
        cause: err
    });
}
util.inherits(RedisError, MahiError);

function RoleDoesNotExistError(role, account) {
    MahiError.call(this, {
        restCode: 'RoleDoesNotExist',
        statusCode: 403,
        message: sprintf('%s does not exist in account %s', role, account)
    });
}
util.inherits(RoleDoesNotExistError, MahiError);

function UserDoesNotExistError(user, account) {
    MahiError.call(this, {
        restCode: 'UserDoesNotExist',
        statusCode: 403,
        message: sprintf('user %s does not exist in account %s', user, account)
    });
}
util.inherits(UserDoesNotExistError, MahiError);


module.exports = {
    MahiError: MahiError,
    AccountDoesNotExistError: AccountDoesNotExistError,
    GroupDoesNotExistError: GroupDoesNotExistError,
    NotApprovedForProvisioningError: NotApprovedForProvisioningError,
    RedisError: RedisError,
    RoleDoesNotExistError: RoleDoesNotExistError,
    UserDoesNotExistError: UserDoesNotExistError
};
