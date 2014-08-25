#!/usr/bin/env node
/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright (c) 2014, Joyent, Inc.
 */

/*
 * Start a mahi server backed by fakeredis, an in-memory redis implementation
 * written in node.
 * example:
 * $ node bin/mahi-server-in-memory.js -c test/data/test-nodeletes.json -p 8080
 */
var bunyan = require('bunyan');
var dashdash = require('dashdash');
var fs = require('fs');
var redis = require('fakeredis');
var jsonstream = require('../test/jsonparsestream.js');

var Transform = require('../lib/replicator/transform.js');
var Server = require('../lib/server/server.js').Server;

function setup(opts, cb) {
    var path = opts.path;
    var client = opts.client;
    var typeTable = {
        ip: 'ip'
    };
    var data = fs.createReadStream(path);
    var json = new jsonstream();
    var transform = new Transform({
        redis: client,
        log: bunyan.createLogger({
            name: 'transform',
            level: 'info'
        }),
        typeTable: typeTable
    });
    data.pipe(json).pipe(transform);
    transform.on('finish', function () {
        cb();
    });
}

function main() {
    var options = [
        {
            names: ['help', 'h'],
            type: 'bool',
            help: 'Print this help and exit.'
        },
        {
            names: ['port', 'p'],
            type: 'number',
            env: 'MAHI_PORT',
            helpArg: 'PORT',
            default: 8080,
            help: 'listen port'
        },
        {
            names: ['changelog', 'c'],
            type: 'string',
            helpArgs: 'PATH',
            help: 'newline-delimited JSON changelog file'
        }
    ];
    var parser = dashdash.createParser({options: options});
    var opts;
    try {
        opts = parser.parse(process.argv);
    } catch (e) {
        console.error('error: %s', e.message);
        process.exit(1);
    }

    var help = parser.help().trimRight();
    if (opts.help) {
        console.log('usage: \n' + help);
        process.exit(0);
    }

    if (!opts.changelog) {
        console.error('changelog required');
        console.log('usage: \n' + help);
        process.exit(1);
    }

    var client = redis.createClient();
    var server;

    setup({
        client: client,
        path: opts.changelog
    }, function () {
        server = new Server({
            redis: client,
            log: bunyan.createLogger({
                name: 'server',
                level: process.env.LOG_LEVEL || 'info'
            }),
            port: 8080
        });
    });
}

if (require.main === module) {
    main();
}
