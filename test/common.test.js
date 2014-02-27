// Copyright (c) 2014, Joyent, Inc. All rights reserved.

var common = require('../lib/replicator/transforms').common;
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
    self.redis.set('/uuidv2/' + UUID, JSON.stringify({
        name: 'name'
    }), function (err) {
        if (err) {
            cb(err);
            return;
        }
        self.redis.set('array', JSON.stringify({
            'array': ['b', 'f', 'g']
        }), function (err) {
            if (err) {
                cb(err);
                return;
            }
            self.redis.set('map', JSON.stringify({
                'map': {
                    'first': true,
                    'second': true,
                    'third': true
                }
            }), function (err) {
                cb(err);
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

test('addToSet beginning', function (t) {
    var self = this;
    var batch = this.redis.multi();
    common.addToSet({
        key: 'array',
        set: 'array',
        element: 'a',
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
            self.redis.get('array', function (err, res) {
                var array = JSON.parse(res).array;
                t.ok(isSorted(array));
                t.ok(array.indexOf('a') >= 0);
                t.done();
            });
        });
    });
});

test('addToSet middle', function (t) {
    var self = this;
    var batch = this.redis.multi();
    common.addToSet({
        key: 'array',
        set: 'array',
        element: 'b',
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
            self.redis.get('array', function (err, res) {
                var array = JSON.parse(res).array;
                t.ok(isSorted(array));
                t.ok(array.indexOf('b') >= 0);
                t.done();
            });
        });
    });
});

test('addToSet end', function (t) {
    var self = this;
    var batch = this.redis.multi();
    common.addToSet({
        key: 'array',
        set: 'array',
        element: 'h',
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
            self.redis.get('array', function (err, res) {
                var array = JSON.parse(res).array;
                t.ok(isSorted(array));
                t.ok(array.indexOf('h') >= 0);
                t.done();
            });
        });
    });
});

test('addToSet duplicate', function (t) {
    var self = this;
    var batch = this.redis.multi();
    common.addToSet({
        key: 'array',
        set: 'array',
        element: 'b',
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
            self.redis.get('array', function (err, res) {
                var array = JSON.parse(res).array;
                t.ok(isSorted(array));
                t.ok(array.indexOf('b') >= 0);
                t.equal(array.length, 3);
                t.done();
            });
        });
    });
});

test('delFromSet beginning', function (t) {
    var self = this;
    var batch = this.redis.multi();
    common.delFromSet({
        key: 'array',
        set: 'array',
        element: 'b',
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
            self.redis.get('array', function (err, res) {
                var array = JSON.parse(res).array;
                t.ok(isSorted(array));
                t.ok(array.indexOf('b') < 0);
                t.done();
            });
        });
    });
});

test('delFromSet middle', function (t) {
    var self = this;
    var batch = this.redis.multi();
    common.delFromSet({
        key: 'array',
        set: 'array',
        element: 'f',
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
            self.redis.get('array', function (err, res) {
                var array = JSON.parse(res).array;
                t.ok(isSorted(array));
                t.ok(array.indexOf('f') < 0);
                t.done();
            });
        });
    });
});

test('delFromSet end', function (t) {
    var self = this;
    var batch = this.redis.multi();
    common.delFromSet({
        key: 'array',
        set: 'array',
        element: 'g',
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
            self.redis.get('array', function (err, res) {
                var array = JSON.parse(res).array;
                t.ok(isSorted(array));
                t.ok(array.indexOf('g') < 0);
                t.done();
            });
        });
    });
});

test('delFromSet nonexistent', function (t) {
    var self = this;
    var batch = this.redis.multi();
    common.delFromSet({
        key: 'array',
        set: 'array',
        element: 'c',
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
            self.redis.get('array', function (err, res) {
                var array = JSON.parse(res).array;
                t.ok(isSorted(array));
                t.equal(array.length,  3);
                t.done();
            });
        });
    });
});


test('setUnion longer', function (t) {
    var self = this;
    var batch = this.redis.multi();
    common.setUnion({
        key: 'array',
        set: 'array',
        elements: ['a', 'b', 'c', 'h'],
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
            self.redis.get('array', function (err, res) {
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
    var batch = this.redis.multi();
    common.setUnion({
        key: 'array',
        set: 'array',
        elements: ['c'],
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
            self.redis.get('array', function (err, res) {
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
    var batch = this.redis.multi();
    common.setDifference({
        key: 'array',
        set: 'array',
        elements: ['b', 'f', 'h', 'i'],
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
            self.redis.get('array', function (err, res) {
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
    var batch = this.redis.multi();
    common.setDifference({
        key: 'array',
        set: 'array',
        elements: ['f'],
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
            self.redis.get('array', function (err, res) {
                var array = JSON.parse(res).array;
                t.ok(isSorted(array));
                t.equal(array.length,  2);
                t.done();
            });
        });
    });
});

test('addToMapSet', function (t)  {
    var self = this;
    var batch = this.redis.multi();
    common.addToMapSet({
        key: 'map',
        set: 'map',
        element: 'fourth',
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
            self.redis.get('map', function (err, res) {
                var map = JSON.parse(res).map;
                t.ok(map.fourth);
                t.done();
            });
        });
    });
});

test('delFromMapSet', function (t)  {
    var self = this;
    var batch = this.redis.multi();
    common.delFromMapSet({
        key: 'map',
        set: 'map',
        element: 'third',
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
            self.redis.get('map', function (err, res) {
                var map = JSON.parse(res).map;
                t.notOk(map.third);
                t.done();
            });
        });
    });
});

test('setValue', function (t)  {
    var self = this;
    var batch = this.redis.multi();
    common.setValue({
        key: '/uuidv2/' + UUID,
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
            self.redis.get('/uuidv2/' + UUID, function (err, res) {
                var name = JSON.parse(res).name;
                t.equal(name, 'newname');
                t.done();
            });
        });
    });
});


test('rename', function (t) {
    var self = this;
    var batch = this.redis.multi();
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
            self.redis.get('/uuidv2/' + UUID, function (err, res) {
                var name = JSON.parse(res).name;
                t.equal(name, 'newname');
                t.done();
            });
        });
    });
});
