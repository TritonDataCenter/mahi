var assert = require('assert-plus');
var ldap = require('ldapjs');
var sprintf = require('util').format;

module.exports = {
    Transformer: Transformer
};

function Transformer(opts) {
    assert.object(opts, 'opts');
    assert.object(opts.redis, 'opts.redis');
    assert.object(opts.log, 'opts.log');

    var self = this;
    self.redis = opts.redis;
    self.log = opts.log;
}

Transformer.prototype.transform = function (opts, cb) {
    assert.object(opts, 'opts');
    assert.object(opts.entry, 'opts.entry');
    assert.object(opts.changes, 'opts.changes');
    assert.func(cb, 'callback');

    var self = this;

    var entry = opts.entry;
    var changes = opts.changes;
    var changetype = entry.object.changetype;


};


Transformer.prototype.putUser = function (entry, changes) {
    assert.object(changes, 'changes');

    var self = this;

    var key = sprintf('/uuid/%s' + changes.uuid[0]);
    var parentAccount = changes.account[0];

    var payload = {
        uuid: changes.uuid[0],
        account: parentAccount,
        login: changes.login,
        groups: {}
    };


};


Transformer.prototype.putRole = function (entry, changes) {
    assert.object(changes, 'changes');

    var self = this;

    var key = sprintf('/uuid/%s' + changes.uuid[0]);
    var payload = {
        uuid: changes.uuid[0],
        policies: changes.policydocument
    };

    var batch = self.redis.multi();
    batch.set(key, JSON.stringify(payload));
    cb(null, batch);
};


/*
addUser(changes) {
    blob = {
        login: changes.login
        account: changes.account
        key: changes.keys
        roles: changes.roles
        groups: change.groups
    }

    set /uuid/changes.uuid blob
    blob = get /uuid/change.account
    blob.users[changes.uuid] = true
    set /uuid/changes.account
}

addRoleToUser(useruuid, roleuuid) {
    blob = get /uuid/useruuid
    groups.roles.roleuuid= true
    set /uuid/useruuid blob
}

delRoleFromUser(useruuid, roleuuid) {
    blob = get /uuid/useruuid
    del blob.roleuuid
    set /uuid/useruuid blob
}

renameUser(useruuid, name) {
    set /user/name useruuid
    blob = get /uuid/useruuid
    del /user/blob.login
    blob.login = name
    set /uuid/useruuid blob
}

addRole(change) {

}

modRole(change) {

}

delRole(change) {

}

renameRole(roleuuid, name) {

}

*/

