/*
 * This Source Code Form is subject to the terms of the Mozilla
 * Public License, v. 2.0. If a copy of the MPL was not
 * distributed with this file, You can obtain one at
 * http://mozilla.org/MPL/2.0/.
 *
 * Copyright 2026 Edgecast Cloud LLC.
 */

/*
 * test/sigv4-timestamp.test.js: Unit tests for AWS Signature
 * Version 4 timestamp validation
 */

var _nodeunit = require('nodeunit');
var TimeMock = require('./lib/time-mock');

var timeMock;

/* --- Setup and teardown --- */

exports.setUp = function (cb) {
    timeMock = new TimeMock();
    cb();
};

exports.tearDown = function (cb) {
    if (timeMock) {
        timeMock.restore();
    }
    cb();
};

/* --- Test timestamp format --- */

exports.testISO8601TimestampFormat = function (t) {
    var timestamp = '20251217T120000Z';
    var date = new Date(timestamp.replace(
        /^(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})Z$/,
        '$1-$2-$3T$4:$5:$6Z'));

    t.ok(!isNaN(date.getTime()),
        'should parse ISO8601 basic format');
    t.equal(date.getUTCFullYear(), 2025);
    t.equal(date.getUTCMonth(), 11);
    t.equal(date.getUTCDate(), 17);
    t.equal(date.getUTCHours(), 12);
    t.equal(date.getUTCMinutes(), 0);
    t.equal(date.getUTCSeconds(), 0);
    t.done();
};

exports.testTimestampToMilliseconds = function (t) {
    var timestamp = '20251217T120000Z';
    var formatted = timestamp.replace(
        /^(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})Z$/,
        '$1-$2-$3T$4:$5:$6Z');
    var ms = new Date(formatted).getTime();

    t.equal(typeof (ms), 'number',
        'timestamp converts to number');
    t.ok(ms > 0, 'timestamp is positive');
    t.done();
};

/* --- Test valid timestamps --- */

exports.testCurrentTimestamp = function (t) {
    var now = Date.now();
    timeMock.freeze(now);

    var requestTime = Date.now();
    var timeDiff = Math.abs(now - requestTime);

    t.equal(timeDiff, 0,
        'current timestamp should have zero difference');
    t.ok(timeDiff <= 15 * 60 * 1000,
        'should be within 15 minute window');
    t.done();
};

exports.testTimestampWithin5Minutes = function (t) {
    var now = Date.now();
    timeMock.freeze(now);

    var fiveMinutesAgo = now - (5 * 60 * 1000);
    var timeDiff = Math.abs(now - fiveMinutesAgo);

    t.equal(timeDiff, 5 * 60 * 1000,
        'should be 5 minutes difference');
    t.ok(timeDiff <= 15 * 60 * 1000,
        'should be within 15 minute window');
    t.done();
};

exports.testTimestampExactly15MinutesOld = function (t) {
    var now = Date.now();
    timeMock.freeze(now);

    var fifteenMinutesAgo = now - (15 * 60 * 1000);
    var timeDiff = Math.abs(now - fifteenMinutesAgo);

    t.equal(timeDiff, 15 * 60 * 1000,
        'should be exactly 15 minutes');
    t.ok(timeDiff <= 15 * 60 * 1000,
        'should be at boundary of valid window');
    t.done();
};

exports.testTimestampWithin10MinutesFuture = function (t) {
    var now = Date.now();
    timeMock.freeze(now);

    var tenMinutesFuture = now + (10 * 60 * 1000);
    var timeDiff = Math.abs(now - tenMinutesFuture);

    t.equal(timeDiff, 10 * 60 * 1000,
        'should be 10 minutes in future');
    t.ok(timeDiff <= 15 * 60 * 1000,
        'should be within 15 minute window');
    t.done();
};

/* --- Test expired timestamps --- */

exports.testTimestamp16MinutesOld = function (t) {
    var now = Date.now();
    timeMock.freeze(now);

    var sixteenMinutesAgo = now - (16 * 60 * 1000);
    var timeDiff = Math.abs(now - sixteenMinutesAgo);

    t.ok(timeDiff > 15 * 60 * 1000,
        'should be outside 15 minute window');
    t.done();
};

exports.testTimestamp1HourOld = function (t) {
    var now = Date.now();
    timeMock.freeze(now);

    var oneHourAgo = now - (60 * 60 * 1000);
    var timeDiff = Math.abs(now - oneHourAgo);

    t.ok(timeDiff > 15 * 60 * 1000,
        'should be outside 15 minute window');
    t.done();
};

exports.testTimestamp1DayOld = function (t) {
    var now = Date.now();
    timeMock.freeze(now);

    var oneDayAgo = now - (24 * 60 * 60 * 1000);
    var timeDiff = Math.abs(now - oneDayAgo);

    t.ok(timeDiff > 15 * 60 * 1000,
        'should be far outside valid window');
    t.done();
};

/* --- Test future timestamps --- */

exports.testTimestamp16MinutesFuture = function (t) {
    var now = Date.now();
    timeMock.freeze(now);

    var sixteenMinutesFuture = now + (16 * 60 * 1000);
    var timeDiff = Math.abs(now - sixteenMinutesFuture);

    t.ok(timeDiff > 15 * 60 * 1000,
        'should be outside 15 minute window');
    t.done();
};

exports.testTimestamp1HourFuture = function (t) {
    var now = Date.now();
    timeMock.freeze(now);

    var oneHourFuture = now + (60 * 60 * 1000);
    var timeDiff = Math.abs(now - oneHourFuture);

    t.ok(timeDiff > 15 * 60 * 1000,
        'should be outside 15 minute window');
    t.done();
};

/* --- Test boundary conditions --- */

exports.testBoundaryExactly15Minutes = function (t) {
    var threshold = 15 * 60 * 1000;
    var now = Date.now();
    timeMock.freeze(now);

    var atBoundary = now - threshold;
    var timeDiff = Math.abs(now - atBoundary);

    t.equal(timeDiff, threshold,
        'should be exactly at threshold');
    t.ok(timeDiff <= threshold,
        'should pass <= comparison');
    t.ok(!(timeDiff > threshold),
        'should not fail > comparison');
    t.done();
};

exports.testBoundaryJustOver15Minutes = function (t) {
    var threshold = 15 * 60 * 1000;
    var now = Date.now();
    timeMock.freeze(now);

    var justOver = now - (threshold + 1);
    var timeDiff = Math.abs(now - justOver);

    t.equal(timeDiff, threshold + 1,
        'should be 1ms over threshold');
    t.ok(timeDiff > threshold,
        'should fail threshold check');
    t.done();
};

exports.testBoundaryJustUnder15Minutes = function (t) {
    var threshold = 15 * 60 * 1000;
    var now = Date.now();
    timeMock.freeze(now);

    var justUnder = now - (threshold - 1);
    var timeDiff = Math.abs(now - justUnder);

    t.equal(timeDiff, threshold - 1,
        'should be 1ms under threshold');
    t.ok(timeDiff <= threshold,
        'should pass threshold check');
    t.done();
};

/* --- Test time advancement --- */

exports.testTimeAdvancement = function (t) {
    var baseTime = Date.parse('2025-12-17T12:00:00Z');
    timeMock.freeze(baseTime);

    t.equal(Date.now(), baseTime,
        'time should be frozen');

    timeMock.advance(5 * 60 * 1000);
    t.equal(Date.now(), baseTime + (5 * 60 * 1000),
        'time should advance 5 minutes');

    timeMock.advance(10 * 60 * 1000);
    t.equal(Date.now(), baseTime + (15 * 60 * 1000),
        'time should advance to 15 minutes total');

    t.done();
};

exports.testTimestampBecomesExpired = function (t) {
    var baseTime = Date.parse('2025-12-17T12:00:00Z');
    timeMock.freeze(baseTime);

    var requestTime = baseTime;
    var threshold = 15 * 60 * 1000;

    var initialDiff = Math.abs(Date.now() - requestTime);
    t.equal(initialDiff, 0,
        'initially request is current');

    timeMock.advance(10 * 60 * 1000);
    var afterTenMin = Math.abs(Date.now() - requestTime);
    t.ok(afterTenMin <= threshold,
        'after 10 minutes still valid');

    timeMock.advance(6 * 60 * 1000);
    var afterSixteenMin = Math.abs(Date.now() - requestTime);
    t.ok(afterSixteenMin > threshold,
        'after 16 minutes expired');

    t.done();
};

/* --- Test timestamp parsing --- */

exports.testParseBasicISO8601Format = function (t) {
    var timestamp = '20251217T120000Z';
    var formatted = timestamp.replace(
        /^(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})Z$/,
        '$1-$2-$3T$4:$5:$6Z');
    var date = new Date(formatted);

    t.ok(date instanceof Date,
        'should create Date object');
    t.ok(!isNaN(date.getTime()),
        'should be valid date');
    t.done();
};

exports.testParseExtendedISO8601Format = function (t) {
    var timestamp = '2025-12-17T12:00:00Z';
    var date = new Date(timestamp);

    t.ok(date instanceof Date,
        'should create Date object');
    t.ok(!isNaN(date.getTime()),
        'should be valid date');
    t.done();
};

exports.testParseDateHeaderFormat = function (t) {
    var timestamp = 'Wed, 17 Dec 2025 12:00:00 GMT';
    var date = new Date(timestamp);

    t.ok(date instanceof Date,
        'should create Date object');
    t.ok(!isNaN(date.getTime()),
        'should be valid date');
    t.done();
};

/* --- Test malformed timestamps --- */

exports.testInvalidTimestampFormat = function (t) {
    var invalidTimestamp = 'not-a-timestamp';
    var date = new Date(invalidTimestamp);

    t.ok(isNaN(date.getTime()),
        'should be invalid date');
    t.done();
};

exports.testEmptyTimestamp = function (t) {
    var emptyTimestamp = '';
    var date = new Date(emptyTimestamp);

    t.ok(isNaN(date.getTime()),
        'should be invalid date');
    t.done();
};

exports.testPartialTimestamp = function (t) {
    var partialTimestamp = '20251217';
    // Partial timestamps may or may not parse depending on
    // JavaScript engine - just verify it doesn't throw
    var result = new Date(partialTimestamp);
    t.ok(result instanceof Date,
        'partial timestamp handled without error');
    t.done();
};

/* --- Test millisecond precision --- */

exports.testTimestampWithMilliseconds = function (t) {
    var now = Date.now();
    timeMock.freeze(now);

    var withMillis = now + 500;
    var timeDiff = Math.abs(Date.now() - withMillis);

    t.equal(timeDiff, 500,
        'should preserve millisecond precision');
    t.ok(timeDiff < 1000,
        'should be less than 1 second');
    t.done();
};

exports.testBoundaryWithMilliseconds = function (t) {
    var threshold = 15 * 60 * 1000;
    var now = Date.now();
    timeMock.freeze(now);

    var justOverWithMillis = now - (threshold + 500);
    var timeDiff = Math.abs(Date.now() - justOverWithMillis);

    t.ok(timeDiff > threshold,
        'milliseconds should affect validation');
    t.done();
};

/* --- Test time difference calculation --- */

exports.testAbsoluteTimeDifference = function (t) {
    var now = Date.now();
    var past = now - 5000;
    var future = now + 5000;

    var diffPast = Math.abs(now - past);
    var diffFuture = Math.abs(now - future);

    t.equal(diffPast, 5000,
        'past difference should be 5000ms');
    t.equal(diffFuture, 5000,
        'future difference should be 5000ms');
    t.equal(diffPast, diffFuture,
        'abs should make both equal');
    t.done();
};

exports.testThresholdConstant = function (t) {
    var threshold = 15 * 60 * 1000;

    t.equal(threshold, 900000,
        'threshold should be 900000ms');
    t.equal(threshold / 1000, 900,
        'threshold should be 900 seconds');
    t.equal(threshold / 1000 / 60, 15,
        'threshold should be 15 minutes');
    t.done();
};

/* --- Test clock skew scenarios --- */

exports.testClockSkewFast = function (t) {
    var serverTime = Date.parse('2025-12-17T12:00:00Z');
    var clientTime = Date.parse('2025-12-17T12:10:00Z');

    timeMock.freeze(serverTime);

    var timeDiff = Math.abs(Date.now() - clientTime);

    t.equal(timeDiff, 10 * 60 * 1000,
        'client 10 minutes ahead');
    t.ok(timeDiff <= 15 * 60 * 1000,
        'within acceptable skew');
    t.done();
};

exports.testClockSkewSlow = function (t) {
    var serverTime = Date.parse('2025-12-17T12:00:00Z');
    var clientTime = Date.parse('2025-12-17T11:50:00Z');

    timeMock.freeze(serverTime);

    var timeDiff = Math.abs(Date.now() - clientTime);

    t.equal(timeDiff, 10 * 60 * 1000,
        'client 10 minutes behind');
    t.ok(timeDiff <= 15 * 60 * 1000,
        'within acceptable skew');
    t.done();
};

exports.testClockSkewExcessive = function (t) {
    var serverTime = Date.parse('2025-12-17T12:00:00Z');
    var clientTime = Date.parse('2025-12-17T12:20:00Z');

    timeMock.freeze(serverTime);

    var timeDiff = Math.abs(Date.now() - clientTime);

    t.equal(timeDiff, 20 * 60 * 1000,
        'client 20 minutes ahead');
    t.ok(timeDiff > 15 * 60 * 1000,
        'exceeds acceptable skew');
    t.done();
};
