// Copyright (c) 2014, Joyent, Inc. All rights reserved.

var common = require('../lib/replicator/transforms').common;
var multi = require('../lib/replicator/MultiCache.js');
var redis = require('fakeredis');

var nodeunit = require('nodeunit-plus');
var before = nodeunit.before;
var after = nodeunit.after;
var test = nodeunit.test;

var UUID = '6123a6de-98cd-11e3-95c9-8fcb0fa87330';

function isSorted(arr) {
    var i;
    for(i = 0; i < arr.length - 1; i++) {
        if (arr[i] > arr[i + 1]) {
            return (false);
        }
    }
    return (true);
}

before(function (cb) {
    var self = this;
    this.log = nodeunit.createLogger('common', process.stderr);
    this.redis = redis.createClient();
    self.redis.set('/uuid/' + UUID, JSON.stringify({
        name: 'name'
    }), function (err) {
        if (err) {
            cb(err);
            return;
        }
        self.redis.set('/uuid/array', JSON.stringify({
            'array': ['b', 'f', 'g']
        }), function (err) {
            if (err) {
                cb(err);
                return;
            }
            self.redis.sadd('/uuid/b/array', 'array', function (err) {
                if (err) {
                    cb(err);
                    return;
                }
                self.redis.sadd('/uuid/f/array', 'array',
                        function (err) {

                    if (err) {
                        cb(err);
                        return;
                    }
                    self.redis.sadd('/uuid/g/array', 'array',
                        function (err) {

                        if (err) {
                            cb(err);
                            return;
                        }
                        cb();
                    });
                });
            });
        });
    });
});

after(function (cb) {
    var self = this;
    this.redis.flushdb(function (err, res) {
        self.redis.quit();
        cb(err, res);
    });
});

test('getDNValue', function (t) {
    var dn = 'cn=admins, ou=groups, o=smartdc';
    t.equal(common.getDNValue(dn, 0), 'admins');
    t.equal(common.getDNValue(dn, 1), 'groups');
    t.equal(common.getDNValue(dn, 2), 'smartdc');
    t.done();
});

test('addToGroup beginning', function (t) {
    var self = this;
    var batch = multi.multi(this.redis);
    common.addToGroup({
        member: 'array',
        group: 'a',
        type: 'array',
        batch: batch,
        log: this.log,
        redis: this.redis
    }, function (err, res) {
        if (err) {
            t.fail(err);
            return;
        }
        res.exec(function (err) {
            if (err) {
                t.fail(err);
                return;
            }
            self.redis.get('/uuid/array', function (err, res) {
                var array = JSON.parse(res).array;
                t.ok(isSorted(array));
                t.ok(array.indexOf('a') >= 0);
                self.redis.sismember('/uuid/a/array', 'array',
                        function (err, res) {

                    t.equal(res, 1);
                    t.done();
                });
            });
        });
    });
});

test('addToGroup middle', function (t) {
    var self = this;
    var batch = multi.multi(this.redis);
    common.addToGroup({
        member: 'array',
        group: 'c',
        type: 'array',
        batch: batch,
        log: this.log,
        redis: this.redis
    }, function (err, res) {
        if (err) {
            t.fail(err);
            return;
        }
        res.exec(function (err) {
            if (err) {
                t.fail(err);
                return;
            }
            self.redis.get('/uuid/array', function (err, res) {
                var array = JSON.parse(res).array;
                t.ok(isSorted(array));
                t.ok(array.indexOf('c') >= 0);
                self.redis.sismember('/uuid/c/array', 'array',
                        function (err, res) {

                    t.equal(res, 1);
                    t.done();
                });
            });
        });
    });
});

test('addToGroup end', function (t) {
    var self = this;
    var batch = multi.multi(this.redis);
    common.addToGroup({
        member: 'array',
        group: 'h',
        type: 'array',
        batch: batch,
        log: this.log,
        redis: this.redis
    }, function (err, res) {
        if (err) {
            t.fail(err);
            return;
        }
        res.exec(function (err) {
            if (err) {
                t.fail(err);
                return;
            }
            self.redis.get('/uuid/array', function (err, res) {
                var array = JSON.parse(res).array;
                t.ok(isSorted(array));
                t.ok(array.indexOf('h') >= 0);
                self.redis.sismember('/uuid/h/array', 'array',
                        function (err, res) {

                    t.equal(res, 1);
                    t.done();
                });
            });
        });
    });
});

test('addToGroup duplicate', function (t) {
    var self = this;
    var batch = multi.multi(this.redis);
    common.addToGroup({
        member: 'array',
        group: 'b',
        type: 'array',
        batch: batch,
        log: this.log,
        redis: this.redis
    }, function (err, res) {
        if (err) {
            t.fail(err);
            return;
        }
        res.exec(function (err) {
            if (err) {
                t.fail(err);
                return;
            }
            self.redis.get('/uuid/array', function (err, res) {
                var array = JSON.parse(res).array;
                t.ok(isSorted(array));
                t.ok(array.indexOf('b') >= 0);
                t.equal(array.length, 3);
                self.redis.sismember('/uuid/b/array', 'array',
                        function (err, res) {

                    t.equal(res, 1);
                    t.done();
                });
            });
        });
    });
});

test('delFromGroup beginning', function (t) {
    var self = this;
    var batch = multi.multi(this.redis);
    common.delFromGroup({
        member: 'array',
        group: 'b',
        type: 'array',
        batch: batch,
        log: this.log,
        redis: this.redis
    }, function (err, res) {
        if (err) {
            t.fail(err);
            return;
        }
        res.exec(function (err) {
            if (err) {
                t.fail(err);
                return;
            }
            self.redis.get('/uuid/array', function (err, res) {
                var array = JSON.parse(res).array;
                t.ok(isSorted(array));
                t.ok(array.indexOf('b') < 0);
                self.redis.sismember('/uuid/b/array', 'array',
                        function (err, res) {

                    t.equal(res, 0);
                    t.done();
                });
            });
        });
    });
});

test('delFromGroup middle', function (t) {
    var self = this;
    var batch = multi.multi(this.redis);
    common.delFromGroup({
        member: 'array',
        group: 'f',
        type: 'array',
        batch: batch,
        log: this.log,
        redis: this.redis
    }, function (err, res) {
        if (err) {
            t.fail(err);
            return;
        }
        res.exec(function (err) {
            if (err) {
                t.fail(err);
                return;
            }
            self.redis.get('/uuid/array', function (err, res) {
                var array = JSON.parse(res).array;
                t.ok(isSorted(array));
                t.ok(array.indexOf('f') < 0);
                self.redis.sismember('/uuid/f/array', 'array',
                        function (err, res) {

                    t.equal(res, 0);
                    t.done();
                });
            });
        });
    });
});

test('delFromGroup end', function (t) {
    var self = this;
    var batch = multi.multi(this.redis);
    common.delFromGroup({
        member: 'array',
        group: 'g',
        type: 'array',
        batch: batch,
        log: this.log,
        redis: this.redis
    }, function (err, res) {
        if (err) {
            t.fail(err);
            return;
        }
        res.exec(function (err) {
            if (err) {
                t.fail(err);
                return;
            }
            self.redis.get('/uuid/array', function (err, res) {
                var array = JSON.parse(res).array;
                t.ok(isSorted(array));
                t.ok(array.indexOf('g') < 0);
                self.redis.sismember('/uuid/g/array', 'array',
                        function (err, res) {

                    t.equal(res, 0);
                    t.done();
                });
            });
        });
    });
});

test('delFromGroup nonexistent', function (t) {
    var self = this;
    var batch = multi.multi(this.redis);
    common.delFromGroup({
        member: 'array',
        group: 'c',
        type: 'array',
        batch: batch,
        log: this.log,
        redis: this.redis
    }, function (err, res) {
        if (err) {
            t.fail(err);
            return;
        }
        res.exec(function (err) {
            if (err) {
                t.fail(err);
                return;
            }
            self.redis.get('/uuid/array', function (err, res) {
                var array = JSON.parse(res).array;
                t.ok(isSorted(array));
                t.equal(array.length,  3);
                self.redis.sismember('/uuid/c/array', 'array',
                        function (err, res) {

                    t.equal(res, 0);
                    t.done();
                });
            });
        });
    });
});


test('replaceGroup', function (t) {
    var self = this;
    var batch = multi.multi(this.redis);
    common.replaceGroup({
        members: [ 'array1', 'array2' ],
        group: 'g',
        type: 'array',
        batch: batch,
        log: this.log,
        redis: this.redis
    }, function (err, res) {
        if (err) {
            t.fail(err);
            return;
        }
        res.exec(function(err) {
            if (err) {
                t.fail(err);
                return;
            }
            self.redis.get('/uuid/array', function (err, res) {
                var array = JSON.parse(res).array;
                t.ok(isSorted(array));
                t.deepEqual(array, ['b', 'f']);
                self.redis.sismember('/uuid/b/array', 'array',
                        function (err, res) {

                    t.equal(res, 1);
                    self.redis.sismember('/uuid/f/array', 'array',
                            function (err, res) {

                        t.equal(res, 1);
                        self.redis.smembers('/uuid/g/array',
                                function (err, res) {

                            t.ok(res.indexOf('array1') >= 0);
                            t.ok(res.indexOf('array2') >= 0);
                            t.equal(res.length, 2);
                            t.done();
                        });
                    });
                });
            });
        });
    });
});


test('setUnion longer', function (t) {
    var self = this;
    var batch = multi.multi(this.redis);
    common.setUnion({
        group: 'array',
        members: ['a', 'b', 'c', 'h'],
        type: 'array',
        batch: batch,
        log: this.log
    }, function (err, res) {
        if (err) {
            t.fail(err);
            return;
        }
        res.exec(function (err) {
            if (err) {
                t.fail(err);
                return;
            }
            self.redis.get('/uuid/array', function (err, res) {
                var array = JSON.parse(res).array;
                t.ok(isSorted(array));
                t.equal(array.length,  6);
                t.done();
            });
        });
    });
});

test('setUnion shorter', function (t) {
    var self = this;
    var batch = multi.multi(this.redis);
    common.setUnion({
        group: 'array',
        members: ['c'],
        type: 'array',
        batch: batch,
        log: this.log,
        redis: this.redis
    }, function (err, res) {
        if (err) {
            t.fail(err);
            return;
        }
        res.exec(function (err) {
            if (err) {
                t.fail(err);
                return;
            }
            self.redis.get('/uuid/array', function (err, res) {
                var array = JSON.parse(res).array;
                t.ok(isSorted(array));
                t.equal(array.length,  4);
                t.done();
            });
        });
    });
});

test('setDifference longer', function (t) {
    var self = this;
    var batch = multi.multi(this.redis);
    common.setDifference({
        group: 'array',
        type: 'array',
        members: ['b', 'f', 'h', 'i'],
        batch: batch,
        log: this.log,
        redis: this.redis
    }, function (err, res) {
        if (err) {
            t.fail(err);
            return;
        }
        res.exec(function (err) {
            if (err) {
                t.fail(err);
                return;
            }
            self.redis.get('/uuid/array', function (err, res) {
                var array = JSON.parse(res).array;
                t.ok(isSorted(array));
                t.equal(array.length,  1);
                t.done();
            });
        });
    });
});

test('setDifference shorter', function (t) {
    var self = this;
    var batch = multi.multi(this.redis);
    common.setDifference({
        group: 'array',
        type: 'array',
        members: ['f'],
        batch: batch,
        log: this.log,
        redis: this.redis
    }, function (err, res) {
        if (err) {
            t.fail(err);
            return;
        }
        res.exec(function (err) {
            if (err) {
                t.fail(err);
                return;
            }
            self.redis.get('/uuid/array', function (err, res) {
                var array = JSON.parse(res).array;
                t.ok(isSorted(array));
                t.equal(array.length,  2);
                t.done();
            });
        });
    });
});

test('setValue', function (t)  {
    var self = this;
    var batch = multi.multi(this.redis);
    common.setValue({
        key: '/uuid/' + UUID,
        property: 'name',
        value: 'newname',
        batch: batch,
        log: this.log,
        redis: this.redis
    }, function (err, res) {
        if (err) {
            t.fail(err);
            return;
        }
        res.exec(function (err) {
            if (err) {
                t.fail(err);
                return;
            }
            self.redis.get('/uuid/' + UUID, function (err, res) {
                var name = JSON.parse(res).name;
                t.equal(name, 'newname');
                t.done();
            });
        });
    });
});


test('rename', function (t) {
    var self = this;
    var batch = multi.multi(this.redis);
    common.rename({
        name: 'newname',
        uuid: UUID,
        batch: batch,
        type: 'user',
        log: this.log,
        redis: this.redis
    }, function (err, res) {
        if (err) {
            t.fail(err);
            return;
        }
        res.exec(function (err) {
            if (err) {
                t.fail(err);
                return;
            }
            self.redis.get('/uuid/' + UUID, function (err, res) {
                var name = JSON.parse(res).name;
                t.equal(name, 'newname');
                t.done();
            });
        });
    });
});
