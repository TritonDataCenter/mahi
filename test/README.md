# Mahi Test Suite Documentation

This document describes the test organization, patterns, and how to run tests for the Mahi authentication service.

## Table of Contents

- [Test Organization](#test-organization)
- [Running Tests](#running-tests)
- [Test Helpers and Fixtures](#test-helpers-and-fixtures)
- [Common Test Patterns](#common-test-patterns)
- [Writing New Tests](#writing-new-tests)
- [JWT Rotation Testing Strategy](#jwt-rotation-testing-strategy)
- [Troubleshooting](#troubleshooting)

## Test Organization

### Directory Structure

```
test/
├── README.md                      # This file
├── integration/                   # End-to-end integration tests
│   ├── auth-flow-complete.test.js # Complete authentication flows
│   ├── auth-errors-e2e.test.js    # Error condition testing
│   └── sigv4-sts-flow.test.js     # SigV4 + STS integration
├── lib/                           # Test helpers and utilities
│   ├── sigv4-helper.js            # SigV4 signature generation
│   ├── redis-fixtures.js          # Redis test data management
│   ├── s3-test-utils.js           # S3-specific test utilities
│   ├── time-mock.js               # Time/timestamp mocking
│   ├── test-harness.js            # Common test setup
│   └── mock-ufds.js               # UFDS mocking utilities
├── data/                          # Test data files
│   └── sigv4-test.json            # SigV4 test vectors
├── *.test.js                      # Unit tests (organized by component)
└── *.sh                           # Shell-based integration tests
```

### Test Categories

#### Unit Tests (Root Level)

Unit tests focus on testing individual components in isolation:

- **SigV4 Components**
  - `sigv4-parsing.test.js` - Authorization header parsing
  - `sigv4-canonical.test.js` - Canonical request generation
  - `sigv4-signature.test.js` - Signature calculation
  - `sigv4-timestamp.test.js` - Timestamp validation
  - `sigv4-verification.test.js` - End-to-end verification

- **STS (Security Token Service)**
  - `sts.test.js` - Core STS functionality
  - `sts-token-generation.test.js` - Token creation
  - `sts-token-validation.test.js` - Token verification
  - `sts-policy.test.js` - Policy attachment
  - `sts-e2e.test.js` - STS end-to-end flows

- **Session Token Management**
  - `session-token-jwt.test.js` - JWT operations
  - `session-token-rotation.test.js` - Secret rotation

- **IAM Policy**
  - `iam-policy-parsing.test.js` - Policy document parsing
  - `iam-policy-evaluation.test.js` - Policy evaluation logic
  - `iam-role-assumption.test.js` - Role assumption flows

- **API Endpoints**
  - `endpoint-aws-auth.test.js` - /aws-auth endpoint
  - `endpoint-aws-verify.test.js` - /aws-verify endpoint

- **LDAP Transforms** (Legacy)
  - `accesskey.test.js` - Access key transformation
  - `sdcaccountpolicy.test.js` - Account policy transformation
  - `sdcaccountrole.test.js` - Account role transformation
  - `sdcaccountuser.test.js` - Account user transformation
  - `sdckey.test.js` - SDC key transformation
  - `sdcperson.test.js` - Person transformation
  - `groupofuniquenames.test.js` - Group transformation
  - `common.test.js` - Common transform utilities

- **Infrastructure**
  - `server.test.js` - Server initialization

#### Integration Tests (`test/integration/`)

Integration tests verify complete workflows with all components:

- `auth-flow-complete.test.js` - Complete authentication workflows
- `auth-errors-e2e.test.js` - Error handling across components
- `sigv4-sts-flow.test.js` - Combined SigV4 and STS flows

#### Shell Tests (Root Level)

Bash-based tests for CLI testing and external tool integration:

- `jwt-rotation-test.sh` - JWT secret rotation scenarios
- `jwt-rotation-awscli-test.sh` - AWS CLI compatibility testing

## Running Tests

### Prerequisites

```bash
# Ensure Node v0.10.48 is active
nvm use v0.10.48

# Install dependencies
npm install
```

### Run All Tests

```bash
# Using make
make test

# Direct nodeunit invocation
find test -name '*.test.js' | xargs -n 1 ./node_modules/.bin/nodeunit
```

### Run Specific Test File

```bash
./node_modules/.bin/nodeunit test/sigv4-parsing.test.js
```

### Run Integration Tests Only

```bash
./node_modules/.bin/nodeunit test/integration/*.test.js
```

### Run Tests by Component

```bash
# All SigV4 tests
./node_modules/.bin/nodeunit test/sigv4-*.test.js

# All STS tests
./node_modules/.bin/nodeunit test/sts*.test.js

# All IAM tests
./node_modules/.bin/nodeunit test/iam-*.test.js

# All endpoint tests
./node_modules/.bin/nodeunit test/endpoint-*.test.js
```

### Run with Coverage

```bash
# Generate coverage report
make coverage

# View HTML coverage report
make coverage-html

# Or manually
./node_modules/.bin/istanbul cover ./node_modules/.bin/nodeunit -- \
    test/**/*.test.js
```

### Run Shell Tests

```bash
# JWT rotation test
cd test && ./jwt-rotation-test.sh

# AWS CLI compatibility test
cd test && ./jwt-rotation-awscli-test.sh
```

## Test Helpers and Fixtures

### SigV4Helper (`test/lib/sigv4-helper.js`)

Utility for generating valid AWS SigV4 signatures and authentication headers.

**Usage:**

```javascript
var SigV4Helper = require('./lib/sigv4-helper');

var helper = new SigV4Helper({
    region: 'us-east-1',
    service: 's3'
});

var headers = helper.createHeaders({
    method: 'POST',
    path: '/aws-verify',
    accessKey: 'AKIAIOSFODNN7EXAMPLE',
    secret: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
    body: {foo: 'bar'},
    host: '127.0.0.1:8080',
    timestamp: '20251217T120000Z'  // Optional, defaults to now
});

// headers contains:
// - 'authorization': SigV4 auth header
// - 'x-amz-date': ISO8601 timestamp
// - 'host': host header
// - 'content-type': application/json
```

**Methods:**

- `createHeaders(opts)` - Generate complete signed headers
- `calculateSignature(opts)` - Calculate signature only
- `canonicalRequest(opts)` - Generate canonical request string

### RedisFixture (`test/lib/redis-fixtures.js`)

Manages Redis test data population and scenario loading.

**Usage:**

```javascript
var fakeredis = require('fakeredis');
var RedisFixture = require('./lib/redis-fixtures');

var redis = fakeredis.createClient();
var fixture = new RedisFixture({
    redis: redis,
    log: bunyan.createLogger({name: 'test', level: 'fatal'})
});

// Load pre-defined scenario
fixture.loadScenario('basicAuth', function(err) {
    if (err) throw err;
    // Redis now populated with test users, accounts, keys
});

// Or add custom data
fixture.addUser({
    uuid: 'test-uuid',
    login: 'testuser',
    email: 'test@example.com',
    account: 'account-uuid',
    accesskeys: {'AKIATEST': 'secretkey'}
}, function(err) {
    // User added to Redis
});
```

**Available Scenarios:**

- `basicAuth` - Single user with access key
- `multiUser` - Multiple users and accounts
- `stsWithRoles` - Users with IAM roles configured
- `policyScenarios` - Various policy configurations

### S3TestUtils (`test/lib/s3-test-utils.js`)

S3-specific test utilities for request validation and response checking.

**Usage:**

```javascript
var S3TestUtils = require('./lib/s3-test-utils');

// Validate S3 request format
S3TestUtils.validateS3Request(req, function(err) {
    t.ok(!err, 'request should be valid S3 format');
});

// Create test S3 request
var req = S3TestUtils.createS3Request({
    method: 'GET',
    bucket: 'testbucket',
    key: 'testkey',
    headers: {'x-amz-content-sha256': 'UNSIGNED-PAYLOAD'}
});
```

### TimeMock (`test/lib/time-mock.js`)

Utilities for mocking time and controlling timestamp generation.

**Usage:**

```javascript
var TimeMock = require('./lib/time-mock');

// Freeze time
TimeMock.freeze('2025-12-17T12:00:00Z');

// Advance time
TimeMock.advance(60000); // +60 seconds

// Restore real time
TimeMock.restore();
```

### TestHarness (`test/lib/test-harness.js`)

Common test setup and teardown logic.

**Usage:**

```javascript
var TestHarness = require('./lib/test-harness');

var harness = new TestHarness({
    port: 0,  // Random port
    redis: fakeredis.createClient()
});

exports.setUp = function(cb) {
    harness.start(cb);
};

exports.tearDown = function(cb) {
    harness.stop(cb);
};
```

### MockUFDS (`test/lib/mock-ufds.js`)

Mock UFDS (User, Fabric, Directory Service) for testing LDAP integration.

**Usage:**

```javascript
var MockUFDS = require('./lib/mock-ufds');

var ufds = new MockUFDS();

// Add test LDAP entry
ufds.addEntry({
    dn: 'uuid=test,ou=users,o=smartdc',
    objectclass: 'sdcperson',
    uuid: 'test-uuid',
    login: 'testuser'
});
```

## Common Test Patterns

### Basic Test Structure

All tests use the nodeunit framework with this structure:

```javascript
var nodeunit = require('nodeunit');
var moduleUnderTest = require('../lib/server/sigv4');

exports.testFunctionName = function (t) {
    // Arrange
    var input = 'test data';

    // Act
    var result = moduleUnderTest.someFunction(input);

    // Assert
    t.ok(result, 'should return a result');
    t.equal(result.foo, 'expected', 'should have expected value');

    // Always call t.done() at the end
    t.done();
};
```

### Test Lifecycle Hooks

```javascript
exports.setUp = function (cb) {
    // Runs before each test
    this.redis = fakeredis.createClient();
    this.server = createTestServer();
    cb();
};

exports.tearDown = function (cb) {
    // Runs after each test
    if (this.server) {
        this.server.close(function() {
            if (this.redis) {
                this.redis.quit();
            }
            cb();
        }.bind(this));
    } else {
        cb();
    }
};

exports.testSomething = function (t) {
    // Can access this.redis and this.server
    t.done();
};
```

### Server Testing Pattern

```javascript
var server = require('../../lib/server/server');
var fakeredis = require('fakeredis');
var bunyan = require('bunyan');

var testServer;
var redis;
var serverPort;

exports.setUp = function (cb) {
    redis = fakeredis.createClient();

    testServer = server.createServer({
        log: bunyan.createLogger({name: 'test', level: 'fatal'}),
        redis: redis,
        port: 0,  // Random port
        sessionConfig: {
            secretKey: 'test-secret-key-32-characters',
            secretKeyId: 'test-key-001',
            gracePeriod: 300
        }
    });

    // Wait for server to be ready
    setTimeout(function () {
        var addr = testServer.address();
        serverPort = addr.port;
        cb();
    }, 2000);
};

exports.tearDown = function (cb) {
    if (testServer) {
        testServer.close(function () {
            if (redis) {
                redis.quit();
            }
            cb();
        });
    } else {
        cb();
    }
};
```

### HTTP Request Testing Pattern

```javascript
var http = require('http');

function makeRequest(method, path, headers, body, callback) {
    var options = {
        hostname: '127.0.0.1',
        port: serverPort,
        path: path,
        method: method,
        headers: headers
    };

    var req = http.request(options, function (res) {
        var responseBody = '';

        res.on('data', function (chunk) {
            responseBody += chunk;
        });

        res.on('end', function () {
            var obj;
            try {
                obj = JSON.parse(responseBody);
            } catch (e) {
                obj = responseBody;
            }

            if (res.statusCode >= 400) {
                var err = new Error('HTTP ' + res.statusCode);
                err.statusCode = res.statusCode;
                err.body = obj;
                return callback(err, req, res, obj);
            }

            callback(null, req, res, obj);
        });
    });

    req.on('error', function (err) {
        callback(err);
    });

    if (body) {
        req.write(typeof body === 'string' ? body : JSON.stringify(body));
    }
    req.end();
}
```

### Async Operation Testing

```javascript
exports.testAsyncOperation = function (t) {
    var redis = fakeredis.createClient();

    // Async operation
    redis.set('/uuid/test', JSON.stringify({foo: 'bar'}), function(err) {
        t.ok(!err, 'should not error');

        // Next async operation
        redis.get('/uuid/test', function(err, data) {
            t.ok(!err, 'should not error on get');
            t.ok(data, 'should return data');

            var obj = JSON.parse(data);
            t.equal(obj.foo, 'bar', 'should have correct value');

            redis.quit();
            t.done();
        });
    });
};
```

### Error Testing Pattern

```javascript
exports.testErrorCondition = function (t) {
    var headers = helper.createHeaders({
        method: 'POST',
        path: '/aws-verify',
        accessKey: 'NONEXISTENT',
        secret: 'fakesecret',
        body: {},
        host: '127.0.0.1:' + serverPort
    });

    makeRequest('POST', '/aws-verify', headers, '{}',
        function (err, req, res, obj) {
        t.ok(err, 'should error on nonexistent access key');
        t.ok(err.statusCode === 403 || err.statusCode === 404,
            'should return 403 or 404');
        t.done();
    });
};
```

### Concurrent Request Testing

```javascript
exports.testConcurrentRequests = function (t) {
    var numRequests = 5;
    var completed = 0;
    var allSucceeded = 0;

    function checkComplete() {
        completed++;
        if (completed === numRequests) {
            t.equal(allSucceeded, numRequests,
                'all concurrent requests should succeed');
            t.done();
        }
    }

    for (var i = 0; i < numRequests; i++) {
        makeRequest('POST', '/some-endpoint', headers, body,
            function (err, req, res, obj) {
            if (!err) {
                allSucceeded++;
            }
            checkComplete();
        });
    }
};
```

### Common Assertions

```javascript
// Boolean assertions
t.ok(value, 'message');
t.equal(actual, expected, 'message');
t.notEqual(actual, unexpected, 'message');
t.strictEqual(actual, expected, 'message');

// Deep equality
t.deepEqual(obj1, obj2, 'message');

// Type checks
t.equal(typeof value, 'string', 'should be string');
t.ok(Array.isArray(value), 'should be array');

// Null/undefined checks
t.ok(value !== null, 'should not be null');
t.ok(value !== undefined, 'should not be undefined');

// Regex matching
t.ok(/^AWS4-/.test(header), 'should match pattern');

// Error assertions
t.ok(err, 'should error');
t.ok(!err, 'should not error');
t.equal(err.message, 'expected message');
```

## Writing New Tests

### Step 1: Choose Test Location

- **Unit test**: Place in `test/` root if testing a single module/function
- **Integration test**: Place in `test/integration/` if testing multiple components
- **Component-specific**: Follow naming convention `<component>-<aspect>.test.js`

### Step 2: Set Up Test File

```javascript
/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright 2026 Edgecast Cloud LLC.
 */

/*
 * test/<filename>.test.js: Brief description of what this tests
 */

var nodeunit = require('nodeunit');
var moduleUnderTest = require('../lib/path/to/module');

/* --- Test category 1 --- */

exports.testCase1 = function (t) {
    // Test implementation
    t.done();
};

exports.testCase2 = function (t) {
    // Test implementation
    t.done();
};

/* --- Test category 2 --- */

exports.testCase3 = function (t) {
    // Test implementation
    t.done();
};
```

### Step 3: Add Test Data if Needed

If your test requires data files:

```bash
# Create data file
cat > test/data/my-test-data.json <<EOF
{
    "testCase1": {
        "input": "foo",
        "expected": "bar"
    }
}
EOF
```

### Step 4: Implement Tests

Follow the [Common Test Patterns](#common-test-patterns) above.

### Step 5: Run and Verify

```bash
# Run your new test
./node_modules/.bin/nodeunit test/my-new.test.js

# Verify style compliance
~/.config/doom/scripts/jsstyle -f tools/jsstyle.conf test/my-new.test.js
```

## Troubleshooting

### Tests Hanging with "FAILURES: Undone tests"

**Symptom:** Test hangs and reports undone tests.

**Cause:** Test didn't call `t.done()` or encountered an unhandled error.

**Solution:**

1. Ensure every code path calls `t.done()`
2. Add error handling to async operations
3. Check for unhandled promise rejections
4. Add debug logging:

```javascript
exports.testSomething = function (t) {
    console.log('Test started');

    someAsyncOp(function(err, result) {
        console.log('Callback invoked, err:', err);
        t.ok(!err);
        console.log('Before t.done()');
        t.done();
    });
};
```

### DTrace Provider Errors

**Symptom:** `Cannot find module './build/Release/DTraceProviderBindings'`

**Cause:** DTrace native module not built (expected on non-SmartOS platforms).

**Solution:** These errors are harmless warnings and can be ignored. They don't affect test execution.

### Redis Connection Errors

**Symptom:** Tests fail with Redis connection errors.

**Cause:** Using real Redis instead of fakeredis.

**Solution:** Always use fakeredis in tests:

```javascript
var fakeredis = require('fakeredis');
var redis = fakeredis.createClient();
```

### Server Port Binding Failures

**Symptom:** `EADDRINUSE` errors.

**Cause:** Previous test didn't clean up server, or port already in use.

**Solution:**

1. Always use `port: 0` for random port assignment
2. Ensure `tearDown` properly closes servers
3. Add cleanup timeout:

```javascript
exports.tearDown = function (cb) {
    if (testServer) {
        testServer.close(function () {
            setTimeout(cb, 100);  // Give port time to release
        });
    } else {
        cb();
    }
};
```

### Timestamp Expiration Errors

**Symptom:** Valid requests rejected as expired.

**Cause:** Timestamp outside 15-minute validation window.

**Solution:**

1. Use current timestamp (default behavior)
2. Or use TimeMock for controlled testing:

```javascript
var TimeMock = require('./lib/time-mock');
TimeMock.freeze('2025-12-17T12:00:00Z');
```

### Memory Leaks in Tests

**Symptom:** Tests slow down or crash with "out of memory".

**Cause:** Resources not cleaned up in `tearDown`.

**Solution:**

1. Always close servers and Redis connections
2. Clear intervals/timeouts
3. Use weak references for large objects

```javascript
exports.tearDown = function (cb) {
    // Close server
    if (this.server) {
        this.server.close();
        this.server = null;
    }

    // Quit Redis
    if (this.redis) {
        this.redis.quit();
        this.redis = null;
    }

    // Clear timers
    if (this.interval) {
        clearInterval(this.interval);
    }

    cb();
};
```

### Wrong Test Endpoint

**Symptom:** Tests pass but shouldn't, or fail unexpectedly.

**Cause:** Using wrong API endpoint (e.g., `/aws-auth` instead of `/aws-verify`).

**Solution:**

- `/aws-auth/:accesskeyid` - User lookup only, does NOT validate signatures
- `/aws-verify` - SigV4 signature validation (use for auth testing)

### Style Check Failures

**Symptom:** `jsstyle` reports errors.

**Common Issues:**

1. **Tabs vs Spaces:** Use tabs for indentation
2. **Line length:** Keep lines ≤80 characters
3. **Trailing whitespace:** Remove all trailing spaces

**Fix:**

```bash
# Check style
~/.config/doom/scripts/jsstyle -f tools/jsstyle.conf test/*.test.js

# Common fixes:
# - Use tabs: :%s/^    /\t/g (in vim)
# - Split long lines at logical breaks
# - Remove trailing spaces: :%s/\s\+$//g (in vim)
```

## JWT Rotation Testing Strategy

This section describes the testing approach for JWT session token
rotation features. For implementation details, see
`docs/jwt-rotation.md`.

### Unit Tests

Unit tests for JWT rotation focus on individual components:

- **Token generation with key IDs** (`session-token-jwt.test.js`)
  - Verify tokens include `keyId` in payload
  - Validate token version is always `1.1`
  - Check `tokenType` field is set correctly
  - Ensure all required claims are present

- **Multi-secret verification** (`session-token-rotation.test.js`)
  - Test verification with primary secret
  - Test verification with old secret during grace period
  - Verify fallback to trying all valid secrets
  - Check key ID matching logic

- **Grace period validation** (`session-token-rotation.test.js`)
  - Test secret expiration after grace period
  - Verify `isSecretValid()` function
  - Check `getValidSecrets()` filtering
  - Test grace period boundary conditions

- **Secret expiration cleanup** (`session-token-rotation.test.js`)
  - Verify expired secrets are rejected
  - Test secret rotation without grace period overlap
  - Check cleanup of old secrets after expiration

### Integration Tests

Integration tests verify complete rotation workflows:

- **Full rotation workflow** (`test/integration/jwt-rotation-flow.test.js`)
  - Generate token with primary secret
  - Rotate secrets (primary becomes old, new secret generated)
  - Verify old tokens still work during grace period
  - Verify new tokens use new secret
  - Confirm old tokens fail after grace period expiration

- **Multi-secret verification during grace periods**
(`test/integration/jwt-rotation-flow.test.js`)
  - Multiple secrets active simultaneously
  - Token verification tries correct secret first (by keyId)
  - Fallback to all valid secrets if keyId lookup fails
  - Performance with multiple secrets

- **Token expiration and renewal**
  - Token expiration independent of secret rotation
  - Renewing tokens after rotation uses new secret
  - Expired tokens rejected regardless of secret validity

- **Error handling scenarios**
  - Missing grace period configuration
  - Invalid secret format
  - Corrupted key IDs
  - Malformed rotation metadata

### Load Testing

Load testing ensures rotation doesn't impact performance:

- **Rotation under load**
  - Measure impact of rotation on active requests
  - Verify no dropped requests during rotation
  - Check latency distribution during grace period
  - Test multiple concurrent rotations (should be prevented)

- **Performance impact measurement**
  - Baseline: single-secret verification time
  - Grace period: two-secret verification time
  - Worst case: fallback through all secrets
  - Memory overhead per additional secret

- **Memory usage with multiple secrets**
  - Track memory per secret configuration
  - Verify cleanup releases memory
  - Check for secret leaks in error paths
  - Monitor long-running processes

### Shell-Based Tests

Shell tests verify operational rotation scripts:

- **jwt-rotation-test.sh** - JWT secret rotation scenarios
  - Test rotation script dry-run mode
  - Verify secret generation produces valid format
  - Check SAPI metadata updates
  - Test grace period enforcement
  - Verify cleanup of expired secrets

- **jwt-rotation-awscli-test.sh** - AWS CLI compatibility
  - Test tokens work with AWS CLI tools
  - Verify rotation doesn't break AWS compatibility
  - Check STS AssumeRole with rotated secrets
  - Validate session token format after rotation

### Running Rotation Tests

```bash
# Run all JWT/session token tests
./node_modules/.bin/nodeunit test/session-token*.test.js

# Run integration tests
./node_modules/.bin/nodeunit test/integration/jwt-rotation-flow.test.js

# Run shell-based rotation tests
cd test && ./jwt-rotation-test.sh
cd test && ./jwt-rotation-awscli-test.sh

# Run with coverage
./node_modules/.bin/istanbul cover ./node_modules/.bin/nodeunit -- \
    test/session-token*.test.js
```

### Test Data Requirements

Rotation tests require:

- **Valid secrets**: 64-character hexadecimal strings (32 bytes)
- **Key IDs**: Format `key-YYYYMMDD-HHMMSS-RRRRRRRR`
- **Grace periods**: Test with various durations (60s minimum, 86400s
default)
- **Rotation timestamps**: Unix epoch seconds
- **Mock SAPI**: For integration tests that update metadata

### Continuous Integration

Rotation tests run in CI pipeline:

1. Unit tests run on every commit
2. Integration tests run on pull requests
3. Shell tests run in SmartOS zone (deployment environment)
4. Load tests run nightly on staging

See `.github/workflows/test.yml` (or equivalent CI config) for details.

## Additional Resources

- **Test Framework:** [nodeunit documentation](https://github.com/caolan/nodeunit)
- **Mocking:** [fakeredis](https://github.com/hdachev/fakeredis)
- **Coverage:** See COVERAGE.md (generated by `make coverage`)
- **Code Style:** See `tools/jsstyle.conf`

## Contributing

When adding new tests:

1. Follow existing patterns and naming conventions
2. Add appropriate JSDoc comments for test helpers
3. Group related tests with comment headers
4. Ensure all assertions have descriptive messages
5. Run `make test` before committing
6. Verify style compliance with `jsstyle`
7. Update this README if adding new test categories or helpers
