/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright (c) 2025, Joyent, Inc.
 */

/**
 * Mock UFDS/LDAP Server for Testing
 *
 * Provides an in-memory LDAP server for testing replicator and STS
 * operations without requiring a real UFDS instance. Supports changelog
 * streaming, search operations, and basic LDAP operations.
 */

var assert = require('assert-plus');
var ldap = require('ldapjs');
var fs = require('fs');
var util = require('util');
var EventEmitter = require('events').EventEmitter;

var CHANGELOG_DN = 'cn=changelog';

/**
 * @brief Mock UFDS/LDAP server for testing
 *
 * Creates an in-memory LDAP server that can load LDIF fixtures and
 * respond to LDAP operations. Suitable for testing code that interacts
 * with UFDS without requiring a real LDAP server.
 *
 * @constructor
 * @param {object} opts Configuration options
 * @param {object} opts.log Bunyan logger instance
 * @param {number} [opts.port] Port to listen on (default: 1389)
 * @param {string} [opts.bindDN] Bind DN for authentication (default:
 *                                 cn=root)
 *
 * @example
 * var MockUfdsServer = require('./mock-ufds');
 *
 * var ufds = new MockUfdsServer({
 *     log: bunyan.createLogger({name: 'test', level: 'fatal'}),
 *     port: 1389
 * });
 *
 * ufds.start(function(err) {
 *     // LDAP server now running
 *     ufds.loadLdif('./test/data/test.ldif', callback);
 * });
 *
 * @since 1.0.0
 */
function MockUfdsServer(opts) {
    assert.object(opts, 'opts');
    assert.object(opts.log, 'opts.log');
    assert.optionalNumber(opts.port, 'opts.port');
    assert.optionalString(opts.bindDN, 'opts.bindDN');

    EventEmitter.call(this);

    this.log = opts.log.child({component: 'MockUfdsServer'}, true);
    this.port = opts.port || 1389;
    this.bindDN = opts.bindDN || 'cn=root';

    this._directory = {}; // DN -> entry mapping
    this._changelog = []; // Changelog entries
    this._changenumber = 0;
    this._server = null;
    this._running = false;
}
util.inherits(MockUfdsServer, EventEmitter);

/**
 * @brief Start the LDAP server
 *
 * Starts the mock LDAP server listening on the configured port.
 * Registers handlers for bind, search, add, modify, and delete
 * operations.
 *
 * @param {function} callback Callback function (err)
 *
 * @return {void}
 *
 * @example
 * ufds.start(function(err) {
 *     if (err) throw err;
 *     console.log('LDAP server listening on port 1389');
 * });
 *
 * @since 1.0.0
 */
MockUfdsServer.prototype.start = function start(callback) {
    assert.func(callback, 'callback');

    if (this._running) {
        callback(new Error('Server already running'));
        return;
    }

    var self = this;
    this._server = ldap.createServer();

    // Bind operation - always allow
    this._server.bind(this.bindDN, function (req, res, next) {
        self.log.debug({bindDN: req.dn.toString()}, 'bind request');
        res.end();
        return (next());
    });

    // Search operation
    this._server.search('', this._handleSearch.bind(this));

    // Add operation
    this._server.add('', this._handleAdd.bind(this));

    // Modify operation
    this._server.modify('', this._handleModify.bind(this));

    // Delete operation
    this._server.del('', this._handleDelete.bind(this));

    // Start listening
    this._server.listen(this.port, function () {
        self.log.info({port: self.port}, 'mock UFDS server started');
        self._running = true;
        self.emit('listening');
        callback();
    });

    this._server.on('error', function (err) {
        self.log.error({err: err}, 'LDAP server error');
        self.emit('error', err);
    });
};

/**
 * @brief Stop the LDAP server
 *
 * Stops the mock LDAP server and closes all connections.
 *
 * @param {function} callback Callback function (err)
 *
 * @return {void}
 *
 * @example
 * after(function(cb) {
 *     ufds.stop(cb);
 * });
 *
 * @since 1.0.0
 */
MockUfdsServer.prototype.stop = function stop(callback) {
    assert.func(callback, 'callback');

    if (!this._running) {
        callback();
        return;
    }

    var self = this;
    this._server.close(function () {
        self.log.info('mock UFDS server stopped');
        self._running = false;
        self.emit('close');
        callback();
    });
};

/**
 * @brief Load LDIF fixture file
 *
 * Parses and loads an LDIF file into the mock LDAP directory.
 * Supports standard LDIF format with DN, objectclass, and attributes.
 *
 * @param {string} filepath Path to LDIF file
 * @param {function} callback Callback function (err)
 *
 * @return {void}
 *
 * @note Creates changelog entries for loaded objects
 *
 * @example
 * ufds.loadLdif('./test/data/test.ldif', function(err) {
 *     if (err) throw err;
 *     // Directory now populated with test data
 * });
 *
 * @since 1.0.0
 */
MockUfdsServer.prototype.loadLdif = function loadLdif(filepath, callback) {
    assert.string(filepath, 'filepath');
    assert.func(callback, 'callback');

    var self = this;

    fs.readFile(filepath, 'utf8', function (err, data) {
        if (err) {
            return (callback(err));
        }

        try {
            var entries = self._parseLdif(data);
            entries.forEach(function (entry) {
                var dn = entry.dn;
                delete entry.dn;
                self._addEntry(dn, entry);
            });

            self.log.info({file: filepath, count: entries.length},
                'LDIF file loaded');
            return (callback());
        } catch (parseErr) {
            return (callback(parseErr));
        }
    });
};

/**
 * @brief Parse LDIF file content
 *
 * Internal method to parse LDIF format into entry objects.
 *
 * @param {string} ldifText LDIF file content
 *
 * @return {array} Array of entry objects
 *
 * @note Supports multi-line attributes and base64 encoded values
 *
 * @since 1.0.0
 */
MockUfdsServer.prototype._parseLdif = function _parseLdif(ldifText) {
    var entries = [];
    var currentEntry = null;
    var currentAttr = null;

    var lines = ldifText.split('\n');
    lines.forEach(function (line) {
        // Skip comments and empty lines
        if (line.match(/^#/) || line.trim() === '') {
            return;
        }

        // Continuation line (starts with space)
        if (line.match(/^ /)) {
            if (currentAttr && currentEntry) {
                currentEntry[currentAttr] += line.substring(1);
            }
            return;
        }

        // Parse attribute: value
        var match = line.match(/^([^:]+):\s*(.*)$/);
        if (!match) {
            return;
        }

        var attr = match[1].toLowerCase();
        var value = match[2];

        // Handle base64 encoded values (attr:: value)
        if (attr.match(/:$/)) {
            attr = attr.substring(0, attr.length - 1);
            value = new Buffer(value, 'base64').toString('utf8');
        }

        // New entry starts with 'dn'
        if (attr === 'dn') {
            if (currentEntry) {
                entries.push(currentEntry);
            }
            currentEntry = {dn: value};
            currentAttr = null;
        } else if (currentEntry) {
            // Add attribute to current entry
            if (currentEntry[attr]) {
                // Multi-valued attribute
                if (!Array.isArray(currentEntry[attr])) {
                    currentEntry[attr] = [currentEntry[attr]];
                }
                currentEntry[attr].push(value);
            } else {
                currentEntry[attr] = value;
            }
            currentAttr = attr;
        }
    });

    // Add last entry
    if (currentEntry) {
        entries.push(currentEntry);
    }

    return (entries);
};

/**
 * @brief Add entry to directory
 *
 * Internal method to add an entry to the in-memory directory and
 * create a changelog entry.
 *
 * @param {string} dn Distinguished name
 * @param {object} entry Entry attributes
 *
 * @return {void}
 *
 * @since 1.0.0
 */
MockUfdsServer.prototype._addEntry = function _addEntry(dn, entry) {
    this._directory[dn] = entry;

    // Add changelog entry
    this._changenumber++;
    this._changelog.push({
        changenumber: this._changenumber,
        changetype: 'add',
        targetdn: dn,
        changetime: new Date().toISOString(),
        changes: JSON.stringify(entry)
    });
};

/**
 * @brief Handle LDAP search request
 *
 * Internal handler for LDAP search operations. Supports changelog
 * queries and standard directory searches.
 *
 * @param {object} req LDAP request object
 * @param {object} res LDAP response object
 * @param {function} next Next middleware function
 *
 * @return {void}
 *
 * @since 1.0.0
 */
MockUfdsServer.prototype._handleSearch = function _handleSearch(req, res,
    next) {
    var self = this;
    var baseDN = req.dn.toString();

    self.log.debug({
        base: baseDN,
        scope: req.scope,
        filter: req.filter.toString()
    }, 'search request');

    // Handle changelog queries
    if (baseDN === CHANGELOG_DN) {
        self._changelog.forEach(function (entry) {
            if (req.filter.matches(entry)) {
                res.send({
                    dn: CHANGELOG_DN,
                    attributes: entry
                });
            }
        });
        res.end();
        return (next());
    }

    // Handle regular directory searches
    Object.keys(self._directory).forEach(function (dn) {
        // Check if DN matches scope
        if (!self._dnMatchesScope(dn, baseDN, req.scope)) {
            return;
        }

        var entry = self._directory[dn];
        if (req.filter.matches(entry)) {
            res.send({
                dn: dn,
                attributes: entry
            });
        }
    });

    res.end();
    return (next());
};

/**
 * @brief Check if DN matches search scope
 *
 * Internal method to determine if a DN matches the search base and
 * scope.
 *
 * @param {string} dn DN to check
 * @param {string} baseDN Search base DN
 * @param {string} scope Search scope (base, one, sub)
 *
 * @return {boolean} True if DN matches scope
 *
 * @since 1.0.0
 */
MockUfdsServer.prototype._dnMatchesScope = function _dnMatchesScope(dn,
    baseDN, scope) {
    var dnLower = dn.toLowerCase();
    var baseLower = baseDN.toLowerCase();

    if (scope === 'base') {
        return (dnLower === baseLower);
    }

    if (scope === 'one') {
        // Entry must be direct child
        if (dnLower === baseLower) {
            return (false);
        }
        var parent = dn.substring(dn.indexOf(',') + 1);
        return (parent.toLowerCase() === baseLower);
    }

    // scope === 'sub' - subtree search
    return dnLower === baseLower ||
        dnLower.indexOf(',' + baseLower) !== -1;
};

/**
 * @brief Handle LDAP add request
 *
 * Internal handler for LDAP add operations.
 *
 * @param {object} req LDAP request object
 * @param {object} res LDAP response object
 * @param {function} next Next middleware function
 *
 * @return {void}
 *
 * @since 1.0.0
 */
MockUfdsServer.prototype._handleAdd = function _handleAdd(req, res, next) {
    var dn = req.dn.toString();

    this.log.debug({dn: dn}, 'add request');

    if (this._directory[dn]) {
        return (next(new ldap.EntryAlreadyExistsError(dn)));
    }

    this._addEntry(dn, req.toObject().attributes);
    res.end();
    return (next());
};

/**
 * @brief Handle LDAP modify request
 *
 * Internal handler for LDAP modify operations.
 *
 * @param {object} req LDAP request object
 * @param {object} res LDAP response object
 * @param {function} next Next middleware function
 *
 * @return {void}
 *
 * @since 1.0.0
 */
MockUfdsServer.prototype._handleModify = function _handleModify(req, res,
    next) {
    var dn = req.dn.toString();

    this.log.debug({dn: dn}, 'modify request');

    if (!this._directory[dn]) {
        return (next(new ldap.NoSuchObjectError(dn)));
    }

    // Apply changes
    req.changes.forEach(function (change) {
        var mod = change.modification;
        var attr = mod.type;
        var vals = mod.vals;

        switch (change.operation) {
        case 'replace':
            this._directory[dn][attr] = vals.length === 1 ?
                vals[0] : vals;
            break;
        case 'add':
            if (!this._directory[dn][attr]) {
                this._directory[dn][attr] = vals[0];
            } else if (Array.isArray(this._directory[dn][attr])) {
                this._directory[dn][attr] =
                    this._directory[dn][attr].concat(vals);
            } else {
                this._directory[dn][attr] = [this._directory[dn][attr]]
                    .concat(vals);
            }
            break;
        case 'delete':
            delete this._directory[dn][attr];
            break;
        default:
            // Unknown operation - ignore
            break;
        }
    }.bind(this));

    // Add changelog entry
    this._changenumber++;
    this._changelog.push({
        changenumber: this._changenumber,
        changetype: 'modify',
        targetdn: dn,
        changetime: new Date().toISOString(),
        changes: JSON.stringify(req.changes)
    });

    res.end();
    return (next());
};

/**
 * @brief Handle LDAP delete request
 *
 * Internal handler for LDAP delete operations.
 *
 * @param {object} req LDAP request object
 * @param {object} res LDAP response object
 * @param {function} next Next middleware function
 *
 * @return {void}
 *
 * @since 1.0.0
 */
MockUfdsServer.prototype._handleDelete = function _handleDelete(req, res,
    next) {
    var dn = req.dn.toString();

    this.log.debug({dn: dn}, 'delete request');

    if (!this._directory[dn]) {
        return (next(new ldap.NoSuchObjectError(dn)));
    }

    delete this._directory[dn];

    // Add changelog entry
    this._changenumber++;
    this._changelog.push({
        changenumber: this._changenumber,
        changetype: 'delete',
        targetdn: dn,
        changetime: new Date().toISOString()
    });

    res.end();
    return (next());
};

/**
 * @brief Get current changelog number
 *
 * Returns the current changelog sequence number.
 *
 * @return {number} Current changenumber
 *
 * @since 1.0.0
 */
MockUfdsServer.prototype.getChangenumber = function getChangenumber() {
    return (this._changenumber);
};

/**
 * @brief Get all changelog entries
 *
 * Returns array of all changelog entries.
 *
 * @return {array} Changelog entries
 *
 * @since 1.0.0
 */
MockUfdsServer.prototype.getChangelog = function getChangelog() {
    return (this._changelog.slice()); // Return copy
};

module.exports = MockUfdsServer;
