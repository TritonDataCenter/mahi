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
        message: sprintf('%s does not exist in account %s', group, account)
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
        message: sprintf('%s does not exist in account %s', role, account)
    });
}
util.inherits(RoleDoesNotExistError, MahiError);
RoleDoesNotExistError.prototype.name = 'RoleDoesNotExistError';

function UserDoesNotExistError(user, account) {
    MahiError.call(this, {
        restCode: 'UserDoesNotExist',
        statusCode: 404,
        message: sprintf('user %s does not exist in account %s', user, account)
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
        message: sprintf('%s expected to be type % but was actually type %s',
            uuid, expected, actual)
    });
}
util.inherits(WrongTypeError, MahiError);
WrongTypeError.prototype.name = 'WrongTypeError';

module.exports = {
    MahiError: MahiError,
    AccountDoesNotExistError: AccountDoesNotExistError,
    GroupDoesNotExistError: GroupDoesNotExistError,
    ObjectDoesNotExistError: ObjectDoesNotExistError,
    RedisError: RedisError,
    ReplicatorNotReadyError: ReplicatorNotReadyError,
    RoleDoesNotExistError: RoleDoesNotExistError,
    UserDoesNotExistError: UserDoesNotExistError,
    WrongTypeError: WrongTypeError
};
