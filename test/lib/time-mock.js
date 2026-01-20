/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright (c) 2025, Joyent, Inc.
 */

/**
 * Time Mocking Utilities for Deterministic Testing
 *
 * Provides utilities for freezing and advancing time in tests to
 * enable deterministic testing of time-dependent operations such as
 * AWS SigV4 timestamp validation and JWT token expiration.
 */

var assert = require('assert-plus');

/**
 * @brief Time mocking utility for deterministic testing
 *
 * Mocks the Date object and Date.now() function to enable
 * deterministic time-based testing. Allows freezing time at a
 * specific timestamp and advancing time programmatically.
 *
 * @constructor
 *
 * @example
 * var TimeMock = require('./time-mock');
 * var tm = new TimeMock();
 *
 * // Freeze time at specific timestamp
 * tm.freeze(Date.parse('2025-01-16T12:00:00Z'));
 * console.log(Date.now()); // Always returns 1736683200000
 *
 * // Advance time by 1 hour
 * tm.advance(3600 * 1000);
 * console.log(Date.now()); // Returns 1736686800000
 *
 * // Restore original Date implementation
 * tm.restore();
 *
 * @note Must call restore() after tests to avoid affecting other
 *       tests
 * @note Not thread-safe - intended for sequential test execution
 *
 * @since 2.1.0
 */
function TimeMock() {
    this._originalDate = Date;
    this._originalNow = Date.now;
    this._frozenTime = null;
    this._isFrozen = false;
}

/**
 * @brief Freeze time at a specific timestamp
 *
 * Mocks the Date object and Date.now() function to return a fixed
 * timestamp. All subsequent calls to Date.now() and new Date()
 * (without arguments) will return the frozen timestamp.
 *
 * @param {number} timestamp Unix timestamp in milliseconds to freeze
 *                            at. If not provided, freezes at current
 *                            time.
 *
 * @return {void}
 *
 * @note Overwrites global Date object
 * @note Must call restore() to undo this change
 *
 * @example
 * var tm = new TimeMock();
 * tm.freeze(Date.parse('2025-01-16T12:00:00Z'));
 * var now = new Date();
 * console.log(now.toISOString()); // "2025-01-16T12:00:00.000Z"
 *
 * @since 2.1.0
 */
TimeMock.prototype.freeze = function freeze(timestamp) {
    var self = this;

    if (this._isFrozen) {
        throw new Error(
            'Time is already frozen. Call restore() first.');
    }

    // Default to current time if no timestamp provided
    this._frozenTime = timestamp ||
        this._originalNow.call(this._originalDate);

    assert.number(this._frozenTime, 'timestamp must be a number');

    // Mock Date.now()
    var mockNowFunc = function mockNow() {
        return (self._frozenTime);
    };
    Date.now = mockNowFunc;

    // Mock Date constructor
    /* BEGIN JSSTYLED */
    global.Date = function MockDate() {
        // If called with no arguments, return frozen time
        if (arguments.length === 0) {
            return new self._originalDate(self._frozenTime);
        }

        // If called with arguments, pass through to original Date
        // This preserves Date.parse(), new Date('2025-01-16'), etc.
        var args = Array.prototype.slice.call(arguments);
        var BoundDate = Function.prototype.bind.apply(
            self._originalDate,
            [null].concat(args)
        );
        return new BoundDate();
    };
    /* END JSSTYLED */

    // Copy static methods from original Date
    global.Date.now = mockNowFunc;
    global.Date.parse = this._originalDate.parse;
    global.Date.UTC = this._originalDate.UTC;
    global.Date.prototype = this._originalDate.prototype;

    this._isFrozen = true;
};

/**
 * @brief Advance frozen time by specified milliseconds
 *
 * Advances the frozen timestamp forward by the specified number of
 * milliseconds. Time must be frozen before calling this method.
 *
 * @param {number} milliseconds Number of milliseconds to advance time
 *                               by (must be positive)
 *
 * @return {void}
 *
 * @note Time must be frozen before calling this method
 * @note Does not restore time - call restore() to undo freeze
 *
 * @example
 * var tm = new TimeMock();
 * tm.freeze(Date.parse('2025-01-16T12:00:00Z'));
 * tm.advance(3600 * 1000); // Advance 1 hour
 * console.log(new Date().toISOString());
 * // "2025-01-16T13:00:00.000Z"
 *
 * @since 2.1.0
 */
TimeMock.prototype.advance = function advance(milliseconds) {
    assert.number(milliseconds, 'milliseconds must be a number');
    assert.ok(milliseconds >= 0, 'milliseconds must be non-negative');

    if (!this._isFrozen) {
        throw new Error('Time is not frozen. Call freeze() first.');
    }

    this._frozenTime += milliseconds;
};

/**
 * @brief Restore original Date implementation
 *
 * Restores the original Date object and Date.now() function,
 * undoing the effects of freeze(). This method is idempotent and
 * can be called multiple times safely.
 *
 * @return {void}
 *
 * @note Should be called in test teardown (after() hook)
 * @note Idempotent - safe to call multiple times
 *
 * @example
 * after(function(cb) {
 *     this.timeMock.restore();
 *     cb();
 * });
 *
 * @since 2.1.0
 */
TimeMock.prototype.restore = function restore() {
    if (!this._isFrozen) {
        return; // Already restored, nothing to do
    }

    global.Date = this._originalDate;
    Date.now = this._originalNow;

    this._frozenTime = null;
    this._isFrozen = false;
};

/**
 * @brief Get current frozen time
 *
 * Returns the current frozen timestamp if time is frozen, otherwise
 * returns the current real time.
 *
 * @return {number} Current timestamp in milliseconds
 *
 * @since 2.1.0
 */
TimeMock.prototype.now = function now() {
    if (this._isFrozen) {
        return (this._frozenTime);
    }
    return (this._originalNow.call(this._originalDate));
};

/**
 * @brief Check if time is currently frozen
 *
 * @return {boolean} True if time is frozen, false otherwise
 *
 * @since 2.1.0
 */
TimeMock.prototype.isFrozen = function isFrozen() {
    return (this._isFrozen);
};

module.exports = TimeMock;
