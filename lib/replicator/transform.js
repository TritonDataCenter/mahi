// Copyright (c) 2014, Joyent, Inc. All rights reserved.
//
// Transforms ldapjs JSON changelog entries into key/value pairs in redis.
//

var stream = require('stream');
var util = require('util');

var aperture = require('aperture');
var assert = require('assert-plus');
var binarySearch = require('binary-search');
var vasync = require('vasync');



///--- Globals

var sprintf = util.format;



///--- API

function Transform(opts) {
    stream.Transform.call(this, {
        objectMode: true;
    });


}
util.inherits(Transform, stream.Transform);
module.exports = Transform;


Transform.prototype.toString = function toString() {
    var str = '[object Transform <';
    str += '>]';

    return (str);
};



///--- Tests