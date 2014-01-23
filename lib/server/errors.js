var util = require('util');
var sprintf = util.format;

var WError = require('verror').WError;

function MahiError(cause, message) {
    var off = 0;
    if (cause instanceof Error) {
        off = 1;
    }

    var args = Array.prototype.slice.call(arguments, off);
    args.unshift({
        cause: off ? cause : undefined,
        constructorOpt: MahiError
    });
    WError.apply(this, args);
}
util.inherits(MahiError, WError);
MahiError.prototype.name = 'MahiError';

function UserDoesNotExistError(cause, message) {
    MahiError.apply(this, arguments);
}
util.inherits(UserDoesNotExistError, MahiError);
UserDoesNotExistError.prototype.name = 'UserDoesNotExistError';

function AccountDoesNotExistError(cause, message) {
    MahiError.apply(this, arguments);
}
util.inherits(AccountDoesNotExistError, MahiError);
AccountDoesNotExistError.prototype.name = 'AccountDoesNotExistError';

function RoleDoesNotExistError(cause, message) {
    MahiError.apply(this, arguments);
}
util.inherits(RoleDoesNotExistError, MahiError);
RoleDoesNotExistError.prototype.name = 'RoleDoesNotExistError';

function GroupDoesNotExistError(cause, message) {
    MahiError.apply(this, arguments);
}
util.inherits(GroupDoesNotExistError, MahiError);
GroupDoesNotExistError.prototype.name = 'GroupDoesNotExistError';

module.exports = {
    MahiError: MahiError,
    UserDoesNotExistError: UserDoesNotExistError,
    AccountDoesNotExistError: AccountDoesNotExistError,
    RoleDoesNotExistError: RoleDoesNotExistError,
    GroupDoesNotExistError: GroupDoesNotExistError
};
