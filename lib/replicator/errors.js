// Copyright (c) 2014, Joyent, Inc. All rights reserved.

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

function UnsupportedOperationError(cause, operation, type) {
    MahiReplicatorError.call(this, cause,
        sprintf('unsupported operation %s for type %s', operation, type));
}
util.inherits(UnsupportedOperationError, MahiReplicatorError);
UnsupportedOperationError.prototype.name = 'UnsupportedOperationError';

module.exports = {
    MahiReplicatorError: MahiReplicatorError,
    UnsupportedOperationError: UnsupportedOperationError
};
