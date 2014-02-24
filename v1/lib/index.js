/*
* Copyright (c) 2012, Joyent, Inc. All rights reserved.
*/

var AuthCache = require('./auth_cache');

module.exports = {
    createAuthCache: function createAuthCache(options) {
        return new AuthCache(options);
    }
};
