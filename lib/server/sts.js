/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2025 Edgecast Cloud LLC.
 */

/*
 * AWS STS (Security Token Service) implementation for Mahi
 */

var assert = require('assert-plus');
var crypto = require('crypto');
var sprintf = require('util').format;
var vasync = require('vasync');
var accesskey = require('ufds/lib/accesskey');
var errors = require('./errors.js');
var sessionTokenModule = require('./session-token');

/**
 * Default ARN partition for multi-cloud support
 * Can be overridden via ARN_PARTITION environment variable
 * Supported values: 'aws', 'manta', 'triton'
 */
var DEFAULT_ARN_PARTITION = process.env.ARN_PARTITION || 'aws';

/**
 * @brief Validates STS AssumeRole input parameters for security
 *
 * Performs comprehensive validation of ARN format, session names,
 * and other parameters to prevent injection attacks and malformed data.
 * Supports aws/manta/triton ARN prefixes for future-proofing.
 *
 * @param {string} roleArn - Role ARN (aws/manta/triton compatible)
 * @param {string} roleSessionName - Session name for role assumption
 * @param {number} durationSeconds - Session duration in seconds
 * @throws {InvalidParameterError} If any parameter is invalid
 *
 * @security Prevents ARN injection, validates UUID format, enforces AWS limits
 * @note Supports migration from AWS S3 to Manta S3
 * @since 1.0.0
 */
function validateStsAssumeRoleInputs(roleArn, roleSessionName,
                                     durationSeconds) {
    // Basic presence validation
    if (!roleArn) {
        throw new errors.InvalidParameterError('RoleArn is required');
    }

    if (!roleSessionName) {
        throw new errors.InvalidParameterError('RoleSessionName is required');
    }

    // Validate role ARN format (Multi-cloud compatible)
    // Supported formats:
    // - arn:aws:iam::UUID:role/role-name (AWS S3 migration compatibility)
    // - arn:manta:iam::UUID:role/role-name (Manta native)
    // - arn:triton:iam::UUID:role/role-name (Triton compatibility)
    /* JSSTYLED */
    var arnPattern = /^arn:(aws|manta|triton):iam::([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}):role\/([a-zA-Z0-9+=,.@_-]{1,64})$/;
    var arnMatch = roleArn.match(arnPattern);

    if (!arnMatch) {
        throw new errors.InvalidParameterError(
            'Invalid RoleArn format.' +
                ' Expected: arn:(aws|manta|triton):iam::UUID:role/role-name');
    }

    // Extract and validate components
    //var arnPrefix = arnMatch[1];     // aws, manta, or triton
    var accountUuid = arnMatch[2];   // UUID
    var roleName = arnMatch[3];      // role name

    // Validate UUID format is correct (additional check)
    /* JSSTYLED */
    var uuidPattern = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
    if (!uuidPattern.test(accountUuid)) {
        throw new errors.InvalidParameterError(
            'Invalid account UUID format in RoleArn');
    }

    // Validate role name (AWS-compatible character set)
    if (!/^[a-zA-Z0-9+=,.@_-]{1,64}$/.test(roleName)) {
        throw new errors.InvalidParameterError(
            'Invalid role name format.' +
                ' Must be 1-64 characters: a-zA-Z0-9+=,.@_-');
    }

    // Validate session name (AWS-compatible)
    if (!/^[a-zA-Z0-9+=,.@_-]{2,64}$/.test(roleSessionName)) {
        throw new errors.InvalidParameterError(
            'Invalid RoleSessionName format. ' +
                ' Must be 2-64 characters: a-zA-Z0-9+=,.@_-');
    }

    // Validate duration (AWS limits)
    if (isNaN(durationSeconds) || durationSeconds < 900 ||
        durationSeconds > 43200) {
        throw new errors.InvalidParameterError(
            'DurationSeconds must be between 900 and 43200');
    }

    // Enforce maximum length limits to prevent DoS
    if (roleArn.length > 2048) {
        throw new errors.InvalidParameterError(
            'RoleArn too long (max 2048 characters)');
    }

    if (roleSessionName.length > 64) {
        throw new errors.InvalidParameterError(
            'RoleSessionName too long (max 64 characters)');
    }

    // Additional security checks for common injection patterns
    if (roleArn.indexOf('\0') !== -1 || roleSessionName.indexOf('\0') !== -1) {
        throw new errors.InvalidParameterError(
            'Null bytes not allowed in parameters');
    }

    if (roleArn.indexOf('..') !== -1 || roleSessionName.indexOf('..') !== -1) {
        throw new errors.InvalidParameterError(
            'Path traversal patterns not allowed');
    }
}

/**
 * @brief Generates cryptographically secure UUID for security operations
 *
 * Creates a version 4 UUID using cryptographically secure random bytes
 * for use in security-critical contexts like session tokens.
 *
 * @return {string} UUID in standard format (36 characters)
 *
 * @note Uses crypto.randomBytes() for cryptographic security
 * @note Format: xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx
 *
 * @example
 * var id = generateUUID();
 * // Returns: "a1b2c3d4-e5f6-4789-a012-3456789abcde"
 *
 * @since 1.0.0
 * @security FIXED: Replaced Math.random() with crypto.randomBytes()
 */
function generateUUID() {
    // Generate 16 random bytes for UUID v4
    var randomBytes = crypto.randomBytes(16);

    // Set version (4) and variant bits according to RFC 4122
    randomBytes[6] = (randomBytes[6] & 0x0f) | 0x40; // Version 4
    randomBytes[8] = (randomBytes[8] & 0x3f) | 0x80; // Variant bits

    // Convert to hex string with proper UUID formatting
    var hex = randomBytes.toString('hex');
    return [
        hex.substring(0, 8),
        hex.substring(8, 12),
        hex.substring(12, 16),
        hex.substring(16, 20),
        hex.substring(20, 32)
    ].join('-');
}

/**
 * @brief Generates temporary access key ID for GetSessionToken
 *
 * Creates a unique access key identifier with MSTS prefix.
 * These credentials CANNOT call IAM APIs per AWS specification.
 *
 * @return {string} Access key ID in format "MSTS<hex>"
 *                  where <hex> is 16 random hexadecimal chars
 *
 * @note Uses crypto.randomBytes for cryptographic randomness
 * @note MSTS prefix identifies GetSessionToken credentials
 * @note AWS restriction: MSTS credentials blocked from IAM APIs
 *
 * @example
 * var keyId = generateSessionTokenAccessKeyId();
 * // Returns: "MSTS4F2A1B3C9E7D8A6F"
 *
 * @since 1.0.0
 */
function generateSessionTokenAccessKeyId() {
    // MSTS = Manta Session Token Service (GetSessionToken)
    // These credentials cannot call IAM APIs per AWS spec
    var prefix = 'MSTS';
    var randomPart = crypto.randomBytes(8).toString('hex').toUpperCase();
    return (prefix + randomPart);
}

/**
 * @brief Generates temporary access key ID for AssumeRole
 *
 * Creates a unique access key identifier with MSAR prefix.
 * These credentials CAN call IAM APIs if role policy allows.
 *
 * @return {string} Access key ID in format "MSAR<hex>"
 *                  where <hex> is 16 random hexadecimal chars
 *
 * @note Uses crypto.randomBytes for cryptographic randomness
 * @note MSAR prefix identifies AssumeRole credentials
 * @note These credentials may call IAM APIs per role policy
 *
 * @example
 * var keyId = generateAssumeRoleAccessKeyId();
 * // Returns: "MSAR4F2A1B3C9E7D8A6F"
 *
 * @since 1.0.0
 */
function generateAssumeRoleAccessKeyId() {
    // MSAR = Manta STS Assume Role
    // These credentials can call IAM APIs (if role permits)
    var prefix = 'MSAR';
    var randomPart = crypto.randomBytes(8).toString('hex').toUpperCase();
    return (prefix + randomPart);
}


/**
 * @brief Check if policy statement matches specified action
 *
 * Validates whether a trust policy statement's Action field
 * matches the specified action, supporting both single actions
 * and action arrays with wildcard matching.
 *
 * @param {Object} statement IAM policy statement object
 * @param {string} targetAction Action to match (e.g. 'sts:AssumeRole')
 *
 * @return {boolean} True if statement matches action, false otherwise
 *
 * @note Supports wildcard '*' matching any action
 * @note Handles both string and array Action formats
 * @note Required for proper Deny/Allow action validation
 *
 * @example
 * var stmt = {"Action": ["sts:AssumeRole", "sts:GetSessionToken"]};
 * var matches = statementMatchesAction(stmt, 'sts:AssumeRole'); // true
 *
 * @since 1.0.0
 */
function statementMatchesAction(statement, targetAction) {
    if (!statement.Action) {
        return (false);
    }

    var actions = Array.isArray(statement.Action) ?
        statement.Action : [statement.Action];

    for (var i = 0; i < actions.length; i++) {
        if (actions[i] === targetAction || actions[i] === '*') {
            return (true);
        }
    }

    return (false);
}

/**
 * @brief Validates IAM trust policy against caller identity
 *
 * Parses and evaluates the role's AssumeRolePolicyDocument to
 * determine if the calling principal is authorized to assume
 * the role. Supports AWS IAM policy syntax with Principal,
 * Effect, and Action validation. Implements proper AWS policy
 * evaluation logic with explicit deny precedence.
 *
 * @param {string} trustPolicyDocument JSON-encoded IAM trust policy
 * @param {Object} caller Calling principal information
 * @param {string} caller.uuid Principal UUID
 * @param {string} caller.login Principal login name
 * @param {Object} log Bunyan logger instance
 *
 * @return {boolean} True if caller authorized, false otherwise
 *
 * @note Implements AWS policy evaluation order:
 *       1. Default DENY (implicit)
 *       2. Check for explicit DENY (overrides everything)
 *       3. Check for explicit ALLOW
 *       4. Return DENY if no explicit ALLOW found
 * @note Supports wildcard (*) and ARN-based principal matching
 * @note Requires sts:AssumeRole action in policy statements
 *
 * @example
 * var policy = '{"Statement":[{"Effect":"Allow",...}]}';
 * var allowed = validateTrustPolicy(policy, caller, log);
 *
 * @since 1.0.0
 */
function validateTrustPolicy(trustPolicyDocument, caller, log) {
    // Extract caller properties from either flat or nested structure
    var callerUuid = caller.user && caller.user.uuid ? caller.user.uuid :
        caller.uuid || (caller.account ? caller.account.uuid : null);
    var callerLogin = caller.user && caller.user.login ? caller.user.login :
        caller.login || (caller.account ? caller.account.login : null);

    if (!trustPolicyDocument) {
        log.warn('No trust policy found for role');
        return (false);
    }

    var policy;
    try {
        policy = JSON.parse(trustPolicyDocument);
    } catch (parseErr) {
        log.error({err: parseErr, trustPolicy: trustPolicyDocument},
            'Invalid trust policy JSON');
        return (false);
    }

    if (!policy.Statement || !Array.isArray(policy.Statement)) {
        log.error({policy: policy},
            'Trust policy missing Statement array');
        return (false);
    }

    // AWS IAM Policy Evaluation Logic:
    // 1. Default: DENY (implicit)
    // 2. Check for explicit DENY (wins over everything)
    // 3. Check for explicit ALLOW
    // 4. If no explicit ALLOW: DENY (implicit)

    // First pass: Check for explicit DENY statements
    for (var i = 0; i < policy.Statement.length; i++) {
        var statement = policy.Statement[i];

        // Process only Deny statements in first pass
        if (statement.Effect !== 'Deny') {
            continue;
        }

        // Check if Action includes sts:AssumeRole
        if (!statementMatchesAction(statement, 'sts:AssumeRole')) {
            continue;
        }

        // Check if Principal matches caller
        if (statement.Principal &&
            validatePrincipal(statement.Principal, caller, log)) {
            log.warn({
                statement: i,
                caller: callerUuid,
                principal: statement.Principal,
                effect: 'Deny'
            }, 'Trust policy DENY statement matched - access denied');
            return (false); // Explicit deny overrides everything
        }
    }

    // Special business rule: Check if root user in mixed policy scenario
    if (callerLogin === 'root') {
        var hasAccountLevelAllow = false;
        var hasExplicitRootAllow = false;

        for (var k = 0; k < policy.Statement.length; k++) {
            var stmt = policy.Statement[k];
            if (stmt.Effect !== 'Allow' ||
                !statementMatchesAction(stmt, 'sts:AssumeRole')) {
                continue;
            }

            if (stmt.Principal && stmt.Principal.AWS) {
                var principals = Array.isArray(stmt.Principal.AWS) ?
                    stmt.Principal.AWS : [stmt.Principal.AWS];
                for (var m = 0; m < principals.length; m++) {
                    // Support both AWS 12-digit and Manta UUID account IDs
                    if ((/^\d{12}$/.test(principals[m]) ||
                        /^[\da-f-]{36}$/.test(principals[m])) &&
                        principals[m] === caller.account.uuid) {
                        hasAccountLevelAllow = true;
                    }
                    if (principals[m] === 'arn:aws:iam::' +
                        caller.account.uuid + ':root') {
                        hasExplicitRootAllow = true;
                    }
                }
            }
        }

        // Business rule: Root users denied if both account-level and
        // explicit root allows exist
        if (hasAccountLevelAllow && hasExplicitRootAllow) {
            log.warn({
                caller: callerUuid,
                hasAccountLevelAllow: hasAccountLevelAllow,
                hasExplicitRootAllow: hasExplicitRootAllow
            }, 'Root user denied due to mixed policy scenario');
            return (false);
        }
    }

    // Second pass: Check for explicit ALLOW statements
    // (Only if no explicit DENY was found)
    for (var j = 0; j < policy.Statement.length; j++) {
        var allowStatement = policy.Statement[j];

        // Process only Allow statements in second pass
        if (allowStatement.Effect !== 'Allow') {
            continue;
        }

        // Check if Action includes sts:AssumeRole
        if (!statementMatchesAction(allowStatement, 'sts:AssumeRole')) {
            continue;
        }

        // Check Principal
        if (allowStatement.Principal) {
            log.debug({
                statement: j,
                caller: callerUuid,
                callerLogin: callerLogin,
                callerAccountUuid: caller.account ? caller.account.uuid : null,
                principal: allowStatement.Principal,
                effect: 'Allow'
            }, 'SECURITY DEBUG: Checking Allow statement principal');

            if (validatePrincipal(allowStatement.Principal, caller, log)) {
                log.debug({
                    statement: j,
                    caller: callerUuid,
                    callerLogin: callerLogin,
                    principal: allowStatement.Principal,
                    effect: 'Allow'
                }, 'SECURITY DEBUG:' +
                   ' Trust policy ALLOW statement matched - GRANTING ACCESS');
                return (true); // Explicit allow found
            } else {
                log.debug({
                    statement: j,
                    caller: callerUuid,
                    callerLogin: callerLogin,
                    principal: allowStatement.Principal,
                    effect: 'Allow'
                }, 'SECURITY DEBUG: ' +
                          'Trust policy ALLOW statement did NOT match');
            }
        }
    }

    // No explicit ALLOW found - implicit deny
    log.warn({
        caller: callerUuid,
        policyStatements: policy.Statement.length
    }, 'No trust policy ALLOW statement matched caller - implicit deny');
    return (false);
}

/**
 * @brief Validates IAM principal specification against caller
 *
 * Evaluates different principal formats from trust policy statements
 * to determine if the caller matches the specified principal. Handles
 * both string and object principal formats as per AWS IAM spec.
 *
 * @param {string|Object} principal Principal from trust policy
 * @param {Object} caller Calling principal information
 * @param {string} caller.uuid Principal UUID
 * @param {string} caller.login Principal login name
 * @param {Object} log Bunyan logger instance
 *
 * @return {boolean} True if caller matches principal, false otherwise
 *
 * @note Supports string format: "*", ARN strings
 * @note Supports object format: {"AWS": "..."}, {"Service": "..."}
 * @note Supports arrays of principals for multiple matches
 *
 * @example
 * // Wildcard principal
 * validatePrincipal("*", caller, log); // true
 *
 * // AWS service principal object
 * validatePrincipal({"AWS": "arn:aws:iam::123:user/bob"}, caller, log);
 *
 * @since 1.0.0
 */
function validatePrincipal(principal, caller, log) {
    // Extract caller login from either flat or nested structure
    var callerLogin = caller.user && caller.user.login ? caller.user.login :
        caller.login;

    // Handle different principal formats

    if (typeof (principal) === 'string') {
        if (principal === '*') {
            // Wildcard principal should not allow role chaining
            log.debug({
                principal: '*',
                callerHasRoleArn: !!caller.roleArn,
                callerRoleArn: caller.roleArn,
                callerLogin: callerLogin,
                callerKeys: Object.keys(caller)
            }, 'SECURITY DEBUG: Checking wildcard principal with caller');

            if (caller.roleArn) {
                log.warn({
                    callerRoleArn: caller.roleArn,
                    callerLogin: callerLogin,
                    principal: '*'
                }, 'SECURITY: Wildcard principal denied for assumed-role ' +
                   'credentials to prevent privilege escalation');
                return (false);
            }
            return (true);
        }
        return (validateSinglePrincipal(principal, caller, log));
    }

    if (typeof (principal) === 'object') {
        // Handle {"AWS": "..."} or {"Service": "..."} format
        if (principal.AWS) {
            var awsPrincipals = Array.isArray(principal.AWS) ?
                principal.AWS : [principal.AWS];
            for (var k = 0; k < awsPrincipals.length; k++) {
                if (validateSinglePrincipal(awsPrincipals[k],
                    caller, log)) {
                    return (true);
                }
            }
            return (false);
        }

        if (principal.Service) {
            // Service principals should only match actual service callers
            // Regular user callers should not match service principals
            return (false);
        }

        if (principal.Federated) {
            // For now, we don't support federated principals
            log.debug({federatedPrincipal: principal.Federated},
                'Skipping federated principal validation');
            return (false);
        }
    }

    log.debug({principal: principal},
        'Unrecognized principal format');
    return (false);
}

/**
 * @brief Validates AWS service principal against whitelist
 *
 * Checks if the specified service principal is authorized to assume
 * roles in the Manta S3 compatibility environment. Only whitelisted
 * AWS-compatible services are permitted for security.
 *
 * @param {string} servicePrincipal Service principal to validate
 *                 (e.g., 'lambda.amazonaws.com', 'ec2.amazonaws.com')
 * @param {Object} log Bunyan logger instance
 *
 * @return {boolean} True if service is whitelisted, false otherwise
 *
 * @note Whitelist approach for security - only known services allowed
 * @note Supports common AWS services that might need S3 access
 * @note Can be extended as needed for additional services
 *
 * @example
 * var valid = validateServicePrincipal('lambda.amazonaws.com', log);
 * // Returns: true (if lambda is whitelisted)
 *
 * @since 1.1.0
 */
function validateServicePrincipal(servicePrincipal, log) {
    // Whitelist of supported service principals for Manta S3
    // Only services that legitimately need S3 access should be here
    var supportedServices = [
        'lambda.amazonaws.com',           // Lambda functions
        'ec2.amazonaws.com',              // EC2 instances
        'glue.amazonaws.com',             // AWS Glue ETL jobs
        'datapipeline.amazonaws.com',     // Data Pipeline
        'elasticmapreduce.amazonaws.com', // EMR clusters
        'batch.amazonaws.com',            // AWS Batch jobs
        'ecs-tasks.amazonaws.com',        // ECS tasks
        'states.amazonaws.com'            // Step Functions
        // Add more services as needed for your environment
    ];

    if (supportedServices.indexOf(servicePrincipal) !== -1) {
        log.debug({
            servicePrincipal: servicePrincipal,
            supported: true
        }, 'Service principal validation: ALLOWED');
        return (true);
    }

    log.warn({
        servicePrincipal: servicePrincipal,
        supportedServices: supportedServices,
        supported: false
    }, 'Service principal validation: DENIED - not in whitelist');

    return (false);
}

/**
 * @brief Validates single principal string against caller identity
 *
 * Performs detailed validation of a single principal string value
 * against caller information. Supports wildcard matching and
 * ARN-based principal validation for trust policies.
 *
 * @param {string} principalString Principal identifier to validate
 * @param {Object} caller Calling principal information
 * @param {string} caller.uuid Principal UUID
 * @param {string} caller.login Principal login name
 * @param {Object} log Bunyan logger instance
 *
 * @return {boolean} True if principal matches caller, false otherwise
 *
 * @note Supports wildcard "*" for any principal
 * @note Supports ARN format: arn:aws:iam::account:user/username
 * @note Supports root account format: arn:aws:iam::account:root
 * @note Uses login name matching for user identification
 *
 * @example
 * var arn = "arn:aws:iam::123456789012:user/alice";
 * var valid = validateSinglePrincipal(arn, caller, log);
 *
 * @since 1.0.0
 */
function validateSinglePrincipal(principalString, caller, log) {
    // Extract caller login from either flat or nested structure
    var callerLogin = caller.user && caller.user.login ? caller.user.login :
        caller.login;

    if (principalString === '*') {
        // SECURITY: Wildcard principal should not allow role chaining
        // to prevent privilege escalation attacks
        if (caller.roleArn) {
            log.warn({
                callerRoleArn: caller.roleArn,
                callerLogin: callerLogin,
                principalString: '*'
            }, 'SECURITY: Wildcard principal denied for assumed-role ' +
               'credentials to prevent privilege escalation');
            return (false);
        }
        return (true);
    }

    // Handle ARN format: arn:(aws|manta|triton):iam::account-id:user/username
    // or arn:(aws|manta|triton):iam::account-id:root
    if (/^arn:(aws|manta|triton):iam::/.test(principalString)) {
        var arnParts = principalString.split(':');
        if (arnParts.length >= 6) {
            var accountId = arnParts[4];
            var resourcePart = arnParts.slice(5).join(':');

            // Handle root ARN - allows any principal in the account
            // In AWS, arn:aws:iam::ACCOUNT:root means
            // "any principal in ACCOUNT" not just the root user
            if (resourcePart === 'root' && caller.account &&
                caller.account.uuid === accountId) {
                return (true);
            }

            // Handle user ARN - must match both account and username
            if (resourcePart.indexOf('user/') === 0 &&
                caller.account &&
                caller.account.uuid === accountId) {
                var username = resourcePart.substring(5); // Remove 'user/'
                return (callerLogin === username);
            }
        }
    }

    // Handle account ID (12-digit AWS format or 36-char UUID format)
    // Note: Root users should only match explicit root ARNs, not account-level
    if ((/^\d{12}$/.test(principalString) ||
        /^[\da-f-]{36}$/.test(principalString)) &&
        caller.account &&
        caller.account.uuid === principalString &&
        callerLogin !== 'root') {
        return (true);
    }

    // SECURITY: Do not allow matching by caller UUID alone
    // This would allow any authenticated user to assume any role
    // by providing their UUID as the principal. Role assumption
    // should only be authorized via explicit ARN or account-level policies.

    var callerUuid = caller.user && caller.user.uuid ? caller.user.uuid :
        caller.uuid;
    log.debug({
        principal: principalString,
        callerUuid: callerUuid,
        callerAccountUuid: caller.account ? caller.account.uuid : null
    }, 'Principal did not match caller');

    return (false);
}

/**
 * @brief Fetches IAM role trust policy from UFDS directory
 *
 * Retrieves the AssumeRolePolicyDocument for a specified role by
 * parsing the role ARN, searching UFDS directory, and extracting
 * trust policy from role attributes. Uses LDAP search with role
 * name and account filtering.
 *
 * @param {string} roleArn AWS role ARN to fetch policy for
 * @param {Object} ufds UFDS client instance for directory access
 * @param {Object} log Bunyan logger instance
 * @param {function} callback Node.js callback function
 * @param {Error} callback.err Error if operation failed
 * @param {string} callback.trustPolicy JSON trust policy document
 *
 * @note Expected ARN format: arn:aws:iam::account:role/rolename
 * @note Searches for 'sdcaccountrole' objectclass in UFDS
 * @note Extracts policy from 'memberpolicy' attribute array
 * @note Returns first policy containing sts:AssumeRole action
 *
 * @example
 * var arn = "arn:aws:iam::123456789012:role/MyRole";
 * fetchRoleTrustPolicy(arn, ufds, log, function(err, policy) {
 *     if (!err) console.log('Trust policy:', policy);
 * });
 *
 * @since 1.0.0
 */

/*jsl:ignore*/
function fetchRoleTrustPolicy(roleArn, ufds, log, callback) {
    // Parse role ARN to extract role name and account
    // Expected format: arn:aws:iam::account:role/rolename
    var arnParts = roleArn.split(':');
    if (arnParts.length < 6 || arnParts[2] !== 'iam') {
        return callback(new errors.InvalidParameterError(
            'Invalid role ARN format'));
    }

    var accountId = arnParts[4];
    var resourcePart = arnParts[5];
    if (resourcePart.indexOf('role/') !== 0) {
        return callback(new errors.InvalidParameterError(
            'ARN must specify a role'));
    }

    var roleName = resourcePart.substring(5); // Remove 'role/' prefix

    log.debug({
        roleArn: roleArn,
        accountId: accountId,
        roleName: roleName,
        note: 'Starting role trust policy lookup'
    }, 'fetchRoleTrustPolicy: Beginning role lookup');

    // Search for role in UFDS
    var searchBase = sprintf('uuid=%s, ou=users, o=smartdc',
        accountId);
    var searchFilter = sprintf(
        '(&(objectclass=sdcaccountrole)(name=%s))', roleName);

    log.debug({
        roleArn: roleArn,
        searchBase: searchBase,
        searchFilter: searchFilter,
        accountId: accountId,
        roleName: roleName,
        ufdsAvailable: !!ufds
    }, 'Searching for role in UFDS');

    var searchStartTime = Date.now();
    log.debug({
        roleArn: roleArn,
        searchStartTime: searchStartTime
    }, 'Starting UFDS search operation');

    ufds.search(searchBase, {
        scope: 'one',
        filter: searchFilter
    }, function (searchErr, result) {
        var searchCallbackTime = Date.now();
        var searchDuration = searchCallbackTime - searchStartTime;

        log.debug({
            roleArn: roleArn,
            searchDuration: searchDuration,
            searchStartTime: searchStartTime,
            searchCallbackTime: searchCallbackTime,
            hasError: !!searchErr
        }, 'UFDS search callback received');
        if (searchErr) {
            log.error({
                err: searchErr,
                roleArn: roleArn,
                searchBase: searchBase
            }, 'UFDS search failed for role');
            return callback(new errors.InternalError(
                'Failed to search for role'));
        }

        var roles = [];
        result.on('searchEntry', function (entry) {
            roles.push(entry.object);
            return;
        });

        result.on('end', function () {
            var searchEndTime = Date.now();
            var totalSearchDuration = searchEndTime - searchStartTime;

            log.debug({
                roleArn: roleArn,
                totalSearchDuration: totalSearchDuration,
                rolesFound: roles.length,
                searchEndTime: searchEndTime
            }, 'UFDS search completed');

            if (roles.length === 0) {
                log.warn({
                    roleArn: roleArn,
                    searchBase: searchBase,
                    searchFilter: searchFilter,
                    totalSearchDuration: totalSearchDuration
                }, 'Role not found in UFDS');
                return callback(new errors.NoSuchEntityError(
                    'Role not found'));
            }

            if (roles.length > 1) {
                log.error({
                    roleArn: roleArn,
                    foundRoles: roles.length
                }, 'Multiple roles found with same name');
                return callback(new errors.InternalError(
                    'Multiple roles found'));
            }

            var role = roles[0];

            // Use Manta RBAC memberpolicy as AWS trust policy
            // memberpolicy is an array, so we look for the first entry that
            // looks like a trust policy
            var trustPolicy = null;
            if (role.memberpolicy && role.memberpolicy.length > 0) {
                // Try to find an AWS trust policy format in memberpolicy array
                for (var policyIdx = 0; policyIdx < role.memberpolicy.length;
                     policyIdx++) {
                    var policy = role.memberpolicy[policyIdx];
                    try {
                        var parsed = JSON.parse(policy);
                        // Check if this looks like an AWS trust policy
                        // (has Principal and sts:AssumeRole)
                        if (parsed.Statement &&
                            Array.isArray(parsed.Statement)) {
                            var hasAssumeRole = parsed.Statement.some(
                                function (stmt) {
                                if (!stmt.Action)
                                    return (false);
                                var actions = Array.isArray(stmt.Action) ?
                                    stmt.Action : [stmt.Action];
                                return actions.some(function (action) {
                                    return (action === 'sts:AssumeRole' ||
                                            action === '*');
                                });
                            });
                            if (hasAssumeRole) {
                                trustPolicy = policy;
                                break;
                            }
                        }
                    } catch (e) {
                        // Not JSON, skip this policy
                        continue;
                    }
                }
            }

            log.debug({
                roleArn: roleArn,
                roleName: role.name,
                hasTrustPolicy: !!trustPolicy,
                policyCount: role.memberpolicy ? role.memberpolicy.length : 0
            }, 'Role found in UFDS, mapped trust policy from memberpolicy');

            callback(null, trustPolicy);
            return;
        });

        result.on('error', function (resultErr) {
            log.error({
                err: resultErr,
                roleArn: roleArn
            }, 'UFDS search result error');
            callback(new errors.InternalError(
                'Role search failed'));
            return;
        });
    });
}
/*jsl:end*/

/**
 * @brief AWS STS AssumeRole operation implementation
 *
 * Handles AssumeRole requests by validating trust policies, generating
 * temporary credentials, and returning AWS-compatible STS response.
 * Uses Redis for fast credential storage with async UFDS persistence.
 *
 * @param {Object} req Restify request object containing:
 *   - caller: Caller identity (set by server wrapper)
 *   - body.RoleArn: ARN of role to assume
 *   - body.RoleSessionName: Session identifier
 *   - body.DurationSeconds: Credential lifetime (optional)
 *   - redis: Redis client
 *   - ufdsPool: UFDS connection pool
 *   - sessionConfig: JWT session configuration
 * @param {Object} res Restify response object
 * @param {function} next Restify next callback function
 *
 * @note Validates caller authorization via trust policy evaluation
 * @note Stores credentials in Redis first, async UFDS for consistency
 * @note Returns AWS STS AssumeRoleResponse format
 *
 * @error 400 InvalidParameterError Missing or invalid parameters
 * @error 403 AccessDenied Trust policy denies access
 * @error 404 NoSuchEntity Role not found
 * @error 500 InternalError Credential generation or storage failure
 *
 * @since 1.0.0
 */
/*jsl:ignore*/
function assumeRole(req, res, next) {

    assert.object(req, 'req');
    assert.object(res, 'res');
    assert.object(req.body, 'body');
    assert.object(req.body.caller, 'caller');
    assert.func(next, 'callback');

    var log = req.log;

    log.debug('sts.assumeRole: entered');

    // Extract STS parameters from request body
    var caller = req.body.caller;
    var callerUuid = caller.user && caller.user.uuid ? caller.user.uuid :
        caller.account.uuid;
    var callerLogin = caller.user && caller.user.login ? caller.user.login :
        caller.account.login;

    // SECURITY DEBUG: Log what caller info we received
    log.debug({
        callerHasRoleArn: !!caller.roleArn,
        callerRoleArn: caller.roleArn,
        callerLogin: callerLogin,
        callerKeys: Object.keys(caller)
    }, 'SECURITY DEBUG: AssumeRole received caller info');

    var roleArn = req.params.RoleArn || req.body.RoleArn;
    var roleSessionName = req.params.RoleSessionName ||
        req.body.RoleSessionName;
    var durationSeconds = parseInt(req.params.DurationSeconds ||
        req.body.DurationSeconds || 3600, 10);

    // Validate inputs
    try {
        validateStsAssumeRoleInputs(roleArn, roleSessionName, durationSeconds);
    } catch (validationError) {
        return (next(validationError));
    }

    // Parse role ARN to extract account and role name
    var arnParts = roleArn.split(':');
    if (arnParts.length < 6 || arnParts[2] !== 'iam') {
        res.send(400, {error: 'Invalid role ARN format'});
        return (next());
    }

    var accountId = arnParts[4];
    var resourcePart = arnParts[5];
    if (resourcePart.indexOf('role/') !== 0) {
        res.send(400, {error: 'ARN must specify a role'});
        return (next());
    }

    var roleName = resourcePart.substring(5); // Remove 'role/' prefix

    // Fast role validation using Redis
    var roleNameKey = '/role/' + accountId + '/' + roleName;

    log.debug({
        roleArn: roleArn,
        accountId: accountId,
        roleName: roleName,
        roleNameKey: roleNameKey
    }, 'STS AssumeRole: Fast role validation');

    req.redis.get(roleNameKey, function (roleErr, roleUuidStr) {
        if (roleErr) {
            log.error({
                err: roleErr,
                roleNameKey: roleNameKey,
                roleArn: roleArn
            }, 'STS AssumeRole: Error retrieving role UUID');
            res.send(500, {error: 'Failed to validate role'});
            return (next());
        }

        if (!roleUuidStr) {
            log.warn({
                roleName: roleName,
                accountId: accountId,
                roleArn: roleArn,
                roleNameKey: roleNameKey
            }, 'STS AssumeRole: Role not found');
            res.send(404, {error: 'Role not found: ' + roleArn});
            return (next());
        }

        // Get the full role data
        var roleUuid = roleUuidStr.trim();
        var roleDataKey = '/uuid/' + roleUuid;

        req.redis.get(roleDataKey, function (roleDataErr, roleDataStr) {
            if (roleDataErr) {
                log.error({
                    err: roleDataErr,
                    roleDataKey: roleDataKey,
                    roleArn: roleArn
                }, 'STS AssumeRole: Error retrieving full role data');
                res.send(500, {error: 'Failed to validate role'});
                return (next());
            }

            if (!roleDataStr) {
                log.warn({
                    roleName: roleName,
                    roleUuid: roleUuid,
                    roleArn: roleArn,
                    roleDataKey: roleDataKey
                }, 'STS AssumeRole: Role data not found');
                res.send(404, {error: 'Role data not found: ' + roleArn});
                return (next());
            }

            var roleData;
            try {
                roleData = JSON.parse(roleDataStr);
            } catch (parseErr) {
                log.error({
                    err: parseErr,
                    roleDataStr: roleDataStr
                }, 'STS AssumeRole: Failed to parse role data');
                res.send(500, {error: 'Invalid role data'});
                return (next());
            }

            log.debug({
                roleArn: roleArn,
                roleName: roleName,
                accountId: accountId,
                roleUuid: roleData.uuid
            }, 'STS AssumeRole: Role data retrieved');

            // Load permission policies
            var rolePermPoliciesKey = '/role-permissions/' + roleData.uuid;
            req.redis.get(rolePermPoliciesKey,
                function (getPolErr, policiesData) {
                if (getPolErr) {
                    log.error({
                        err: getPolErr,
                        rolePermPoliciesKey: rolePermPoliciesKey
                    }, 'STS AssumeRole: Error getting permission policies');
                    res.send(500, {error: 'Failed to load role policies'});
                    return (next());
                }

                var permissionPolicies = [];
                if (policiesData) {
                    try {
                        permissionPolicies = JSON.parse(policiesData);
                        if (!Array.isArray(permissionPolicies)) {
                            permissionPolicies = [];
                        }
                    } catch (parseErr) {
                        log.error({
                            err: parseErr,
                            policiesData: policiesData
                        }, 'STS AssumeRole: Failed to parse policies');
                        res.send(500, {error: 'Invalid role policies'});
                        return (next());
                    }
                }

                log.debug({
                    roleUuid: roleData.uuid,
                    permissionPoliciesCount: permissionPolicies.length
                }, 'STS AssumeRole: Permission policies loaded');

                roleData.permissionPolicies = permissionPolicies;

                // Validate trust policy
                var trustPolicy = roleData.assumerolepolicydocument;
                if (typeof (trustPolicy) === 'object') {
                    trustPolicy = JSON.stringify(trustPolicy);
                }

                var validationResult;
                try {
                    validationResult = validateTrustPolicy(
                        trustPolicy, caller, log);
                } catch (validationError) {
                    log.error({
                        err: validationError,
                        errorMessage: validationError.message
                    }, 'Trust policy validation threw error');
                    res.send(500, {
                        error: 'InternalError',
                        message: 'Trust policy validation failed'
                    });
                    return (next());
                }

                if (!validationResult) {
                    log.warn({
                        roleArn: roleArn,
                        callerUuid: callerUuid
                    }, 'Trust policy validation failed - access denied');
                    res.send(403, {
                        error: 'AccessDenied',
                        message: 'AssumeRole access denied by trust policy'
                    });
                    return (next());
                }

                log.info({
                    roleArn: roleArn,
                    callerUuid: callerUuid
                }, 'Trust policy validation successful');

                // Generate temporary credentials
                generateTemporaryCredentials(roleData);
            });
        });
    });

    function generateTemporaryCredentials(roleData) {
        var tempAccessKeyId = generateAssumeRoleAccessKeyId();

        accesskey.generate(accesskey.DEFAULT_PREFIX,
            accesskey.DEFAULT_BYTE_LENGTH,
            function (keyErr, tempSecretKey) {
            if (keyErr) {
                log.error({err: keyErr},
                    'Failed to generate temporary secret key');
                res.send(500,
                    {error: 'Failed to generate temporary credentials'});
                return (next());
            }

            var expiration = new Date(Date.now() + durationSeconds * 1000);
            var sessionTokenData = {
                uuid: callerUuid,
                expires: Math.floor(expiration.getTime() / 1000),
                sessionName: roleSessionName,
                roleArn: roleArn
            };

            var secureSessionToken;
            try {

                if (!req.sessionConfig) {
                    throw new errors.ServiceUnavailableError(
                        'STS operations are not enabled');
                }

                if (!req.sessionConfig.secretKey) {
                    throw new Error('Session secret key not configured');
                }

                var buildSecretConfig =
                    require('./server.js').buildSecretConfig;
                var secretConfig = buildSecretConfig(req.sessionConfig);
                if (!secretConfig.primarySecret) {
                    throw new Error('Session secret key not configured');
                }

                var tokenOptions = {
                    issuer: req.sessionConfig.issuer || 'manta-mahi',
                    audience: req.sessionConfig.audience || 'manta-s3',
                    keyId: secretConfig.primaryKeyId
                };

                secureSessionToken = sessionTokenModule.generateSessionToken(
                    sessionTokenData,
                    secretConfig.primarySecret,
                    tokenOptions);

                log.info({
                    roleArn: roleArn,
                    sessionName: roleSessionName,
                    expires: expiration.toISOString(),
                    tokenLength: secureSessionToken.length
                }, 'Generated secure JWT session token');

            } catch (tokenErr) {
                log.error({
                    err: tokenErr,
                    roleArn: roleArn,
                    sessionName: roleSessionName
                }, 'Failed to generate secure session token');
                res.send(500, {
                    error: 'Failed to generate session credentials'
                });
                return (next());
            }

            // Build Redis credential data
            var now = Date.now().toString();
            var accessKeyData = {
                type: 'accesskey',
                accessKeyId: tempAccessKeyId,
                secretAccessKey: tempSecretKey,
                sessionToken: secureSessionToken,
                userUuid: callerUuid,
                expiration: expiration.toISOString(),
                assumedRole: {
                    arn: roleArn,
                    sessionName: roleSessionName,
                    roleUuid: roleData.uuid,
                    policies: roleData.permissionPolicies || []
                },
                credentialType: 'temporary',
                created: now
            };

            var redisKey = '/accesskey/' + tempAccessKeyId;
            var credentialJson = JSON.stringify(accessKeyData);

            // Build UFDS LDAP object for async persistence
            var dn = 'accesskeyid=' + tempAccessKeyId + ', uuid=' +
                callerUuid + ', ou=users, o=smartdc';
            var ldapObject = {
                objectclass: ['accesskey'],
                accesskeyid: tempAccessKeyId,
                accesskeysecret: tempSecretKey,
                sessiontoken: secureSessionToken,
                expiration: expiration.toISOString(),
                principaluuid: callerUuid,
                assumedrole: roleArn,
                credentialtype: 'temporary',
                status: 'Active',
                created: now,
                updated: now
            };

            log.info({
                accessKeyId: tempAccessKeyId,
                roleArnBeingStored: roleArn,
                ldapObjectAssumedrole: ldapObject.assumedrole,
                areTheyEqual: roleArn === ldapObject.assumedrole
            }, 'SECURITY DEBUG: Storing assumedrole in UFDS: ' +
                     ldapObject.assumedrole);

            // Store in Redis first using vasync pipeline
            vasync.pipeline({
                funcs: [
                    // Step 1: Check for existing key (collision check)
                    function checkExistingKey(_, cb) {
                        req.redis.get(redisKey,
                            function (checkErr, existingKey) {
                            if (checkErr) {
                                log.error({err: checkErr},
                                    'Failed to check existing access key');
                                return (cb(new errors.InternalError(
                                    'Failed to check for existing cred')));
                            }
                            if (existingKey) {
                                log.warn({accessKeyId: tempAccessKeyId},
                                    'Access key collision detected');
                                return (cb(new errors.InternalError(
                                    'Credential generation conflict')));
                            }
                            cb();
                        });
                    },

                    // Step 2: Store credential in Redis
                    function storeCredential(_, cb) {
                        req.redis.set(redisKey, credentialJson,
                            function (setErr) {
                            if (setErr) {
                                log.error({
                                    err: setErr,
                                    accessKeyId: tempAccessKeyId,
                                    redisKey: redisKey
                                }, 'Failed to store temp cred in Redis');
                                return (cb(new errors.InternalError(
                                    'Failed to store temporary creds')));
                            }

                            log.info({
                                accessKeyId: tempAccessKeyId,
                                redisKey: redisKey,
                                expiration: expiration.toISOString(),
                                roleArn: roleArn
                            }, 'Stored temporary credentials in Redis');

                            cb();
                        });
                    },

                    // Step 3: Verify credential was stored
                    function verifyCredential(_, cb) {
                        req.redis.get(redisKey,
                            function (getErr, storedData) {
                            if (getErr) {
                                log.error({
                                    err: getErr,
                                    accessKeyId: tempAccessKeyId,
                                    redisKey: redisKey
                                }, 'Failed to verify stored credential');
                                return (cb(new errors.InternalError(
                                    'Failed to verify stored credential')));
                            }

                            if (!storedData) {
                                log.error({
                                    accessKeyId: tempAccessKeyId,
                                    redisKey: redisKey
                                }, 'Stored cred not found during verify');
                                return (cb(new errors.InternalError(
                                    'Credential verification failed')));
                            }

                            log.debug({
                                accessKeyId: tempAccessKeyId,
                                redisKey: redisKey,
                                dataSize: storedData.length
                            }, 'Credential storage verified');

                            cb();
                        });
                    }
                ]
            }, function (pipelineErr) {
                if (pipelineErr) {
                    res.send(500, {error: pipelineErr.message});
                    return (next());
                }

                // Return AWS response immediately
                var response = {
                    AssumeRoleResponse: {
                        AssumeRoleResult: {
                            Credentials: {
                                AccessKeyId: tempAccessKeyId,
                                SecretAccessKey: tempSecretKey,
                                SessionToken: secureSessionToken,
                                Expiration: expiration.toISOString()
                            },
                            AssumedRoleUser: {
                                AssumedRoleId: roleArn + ':' + roleSessionName,
                                Arn: roleArn
                            }
                        }
                    }
                };

                res.send(200, response);

                // Async UFDS write for consistency (non-blocking)
                if (req.ufdsPool) {
                    setImmediate(function () {
                        req.ufdsPool.acquire(function (poolErr, ufdsClient) {
                            if (poolErr) {
                                log.error({err: poolErr},
                                    'Async UFDS write failed - pool acquire');
                                return;
                            }
                            ufdsClient.add(dn, ldapObject,
                                function (addErr) {
                                req.ufdsPool.release(ufdsClient);
                                if (addErr) {
                                    log.error({
                                        err: addErr,
                                        accessKeyId: tempAccessKeyId,
                                        dn: dn
                                    }, 'Async UFDS credential write failed');
                                } else {
                                    log.debug({
                                        accessKeyId: tempAccessKeyId,
                                        dn: dn
                                    }, 'Temp cred written to UFDS');
                                }
                            });
                        });
                    });
                } else {
                    log.warn({accessKeyId: tempAccessKeyId},
                        'UFDS pool not available - cred in Redis only');
                }

                return (next());
            }); // End vasync.pipeline callback
        }); // End accesskey.generate callback
    } // End generateTemporaryCredentials function
}
/*jsl:end*/

/**
 * @brief AWS STS GetSessionToken operation implementation
 *
 * Generates temporary security credentials for the calling user
 * without role assumption. Creates session-scoped temporary
 * credentials with configurable duration for enhanced security
 * in multi-factor authentication scenarios.
 *
 * @param {Object} req Restify request object containing parameters:
 * @param {number} req.params.DurationSeconds Credential lifetime
 * @param {Object} res Restify response object
 * @param {function} next Restify next callback function
 *
 * @note No role assumption - credentials for calling principal
 * @note Duration range: 900 seconds (15 min) to 129600 (36 hours)
 * @note Generates MSTS-prefixed temporary access keys
 * @note Creates JWT session tokens for identification
 * @note Stores temporary credentials in UFDS with expiration
 * @note Returns AWS STS GetSessionTokenResponse XML format
 *
 * @error 400 InvalidParameterError Invalid duration parameter
 * @error 500 InternalError Credential generation or storage failure
 *
 * @example
 * POST /sts/get-session-token
 * {
 *   "DurationSeconds": 7200
 * }
 *
 * @since 1.0.0
 */
/*jsl:ignore*/
function getSessionToken(req, res, next) {
    assert.object(req, 'req');
    assert.object(res, 'res');
    assert.object(req.body, 'body');
    assert.object(req.body.caller, 'caller');
    assert.func(next, 'callback');

    var log = req.log;

    log.debug('sts.getSessionToken: entered');

    // Extract caller from request body (sent by manta-buckets-api)
    var caller = req.body.caller;
    var callerUuid = caller.user && caller.user.uuid ? caller.user.uuid :
        caller.account.uuid;
    var callerLogin = caller.user && caller.user.login ? caller.user.login :
        caller.account.login;

    log.debug({
        callerUuid: callerUuid,
        callerLogin: callerLogin,
        hasUser: !!caller.user
    }, 'STS getSessionToken: processing request');

    var durationSeconds = parseInt(req.params && req.params.DurationSeconds ||
                                   req.body.DurationSeconds || 3600, 10);

    if (durationSeconds < 900 || durationSeconds > 129600) {
        next(new errors.InvalidParameterError(
            'DurationSeconds must be between 900 and 129600'));
        return;
    }

    if (!callerUuid || !callerLogin) {
        log.error({
            caller: caller
        }, 'Missing caller identity in GetSessionToken');
        next(new errors.InvalidParameterError(
            'Caller identity required'));
        return;
    }

    // Generate temporary credentials using ufds accesskey module
    // Use MSTS prefix - these credentials cannot call IAM APIs
    var tempAccessKeyId = generateSessionTokenAccessKeyId();
    var expiration = new Date(Date.now() +
        durationSeconds * 1000);

    // Use accesskey.generate to create UFDS-compatible secret
    accesskey.generate(accesskey.DEFAULT_PREFIX,
                       accesskey.DEFAULT_BYTE_LENGTH,
                       function (keyErr, tempSecretKey) {
        if (keyErr) {
            log.error({err: keyErr},
                      'Failed to generate temporary secret key');
            next(new errors.InternalError(
                'Failed to generate temporary credentials'));
            return;
        }

        continueWithCredentialGeneration(tempSecretKey);
    });

    function continueWithCredentialGeneration(tempSecretKey) {

    // Generate secure JWT session token (matching AssumeRole implementation)
    var sessionTokenData = {
        uuid: callerUuid,
        expires: Math.floor(expiration.getTime() / 1000),
        sessionName: 'session-' + Date.now(), // Generate session name
        roleArn: 'arn:aws:sts::' + callerUuid + ':session'
    };

    var secureSessionToken;
    try {
        // Get secret configuration from request (passed by server wrapper)
        if (!req.sessionConfig) {
            throw new errors.ServiceUnavailableError(
                'STS operations are not enabled');
        }

        if (!req.sessionConfig.secretKey) {
            throw new Error('Session secret key not configured');
        }

        var buildSecretConfig = require('./server.js').buildSecretConfig;
        var secretConfig = buildSecretConfig(req.sessionConfig);

        if (!secretConfig.primarySecret) {
            throw new Error('Session secret key not configured');
        }

        var tokenOptions = {
            issuer: req.sessionConfig.issuer || 'manta-mahi',
            audience: req.sessionConfig.audience || 'manta-s3'
        };

        secureSessionToken = sessionTokenModule.generateSessionToken(
            sessionTokenData,
            secretConfig.primarySecret,
            tokenOptions);

        log.debug({
            sessionName: sessionTokenData.sessionName,
            expires: expiration.toISOString(),
            tokenLength: secureSessionToken.length
        }, 'Generated secure JWT session token for GetSessionToken');

    } catch (tokenErr) {
        log.error({
            err: tokenErr,
            callerUuid: callerUuid
        }, 'Failed to generate secure session token');

        next(new errors.InternalError(
            'Failed to generate session token: ' + tokenErr.message));
        return;
    }

    // Add session token to UFDS via LDAP client
    var dn = 'accesskeyid=' + tempAccessKeyId +
        ', uuid=' + callerUuid + ', ou=users, o=smartdc';
    var ldapObject = {
        objectclass: ['accesskey'],
        accesskeyid: tempAccessKeyId,
        accesskeysecret: tempSecretKey,
        sessiontoken: secureSessionToken,
        expiration: expiration.toISOString(),
        principaluuid: callerUuid,
        credentialtype: 'temporary',
        status: 'Active',
        created: Date.now().toString(),
        updated: Date.now().toString()
    };

    log.debug({
        dn: dn,
        tempCredential: {
            accessKeyId: tempAccessKeyId,
            expiration: expiration.toISOString(),
            principal: callerUuid
        }
    }, 'Creating session token in UFDS');

    if (!req.ufdsPool) {
        log.error('UFDS connection pool not available for STS operations');
        return (next(new errors.InternalError(
            'Authentication service unavailable')));
    }

    // Use connection pool for UFDS operations
    req.ufdsPool.acquire(function (poolErr, ufdsClient) {
        if (poolErr) {
            log.error({err: poolErr},
                      'Failed to acquire UFDS connection for session token');
            return (next(new errors.InternalError(
                'Authentication service unavailable')));
        }

        ufdsClient.add(dn, ldapObject, function (addErr) {
            // Always release the connection back to the pool
            req.ufdsPool.release(ufdsClient);
        if (addErr) {
            log.error({
                err: addErr,
                dn: dn,
                accessKeyId: tempAccessKeyId,
                ldapErrorCode: addErr.code,
                ldapErrorMessage: addErr.message
            }, 'Failed to create session token in UFDS');

            // Map LDAP errors to appropriate AWS errors
            if (addErr.code === 'LDAP_INVALID_CREDENTIALS') {
                next(new errors.AccessDeniedError('Invalid LDAP credentials'));
            } else {
                next(new errors.InternalError(
                    'Failed to create session token: ' + addErr.message));
            }
            return;
        }

        log.info({
            accessKeyId: tempAccessKeyId,
            expiration: expiration.toISOString(),
            principal: callerUuid,
            dn: dn
        }, 'Successfully created session token in UFDS');

        // Store in Redis for fast lookup (similar to AssumeRole)
        var accessKeyData = {
            type: 'accesskey',
            accessKeyId: tempAccessKeyId,
            secretAccessKey: tempSecretKey,
            sessionToken: secureSessionToken,
            userUuid: callerUuid,
            expiration: expiration.toISOString(),
            credentialType: 'temporary',
            created: Date.now().toString(),
            // No assumedRole for GetSessionToken
            // - it's for the original principal
            principalUuid: callerUuid
        };

        var redisKey = '/accesskey/' + tempAccessKeyId;
        var credentialJson = JSON.stringify(accessKeyData);

        req.redis.set(redisKey, credentialJson, function (setErr) {
            if (setErr) {
                log.error({
                    err: setErr,
                    accessKeyId: tempAccessKeyId
                }, 'Failed to store GetSessionToken credential in Redis');
                // Continue anyway - UFDS storage is primary
            } else {
                log.info({
                    accessKeyId: tempAccessKeyId,
                    expiration: expiration.toISOString()
                }, 'Successfully stored GetSessionToken credential in Redis');
            }
        });

        // Return STS response
        var response = {
            GetSessionTokenResponse: {
                GetSessionTokenResult: {
                    Credentials: {
                        AccessKeyId: tempAccessKeyId,
                        SecretAccessKey: tempSecretKey,
                        SessionToken: secureSessionToken,
                        Expiration: expiration.toISOString()
                    }
                }
            }
        };

        res.send(200, response);
        next();
        return;
        });
    }); // End pool.acquire callback
    } // End continueWithCredentialGeneration function
}
/*jsl:end*/

/**
 * @brief GetCallerIdentity STS operation implementation
 *
 * Returns details about the IAM entity used to make the request.
 * This operation does not require any specific permissions and can be
 * called with any valid AWS credentials.
 *
 * @param {Object} req HTTP request object with authentication info
 * @param {Object} res HTTP response object
 * @param {function} next Next middleware function
 *
 * @returns AWS XML response with caller identity information:
 *   - UserId: The unique identifier of the calling entity
 *   - Account: The AWS account ID number
 *   - Arn: The AWS ARN of the user or role making the request
 *
 * @note Works with both permanent and temporary credentials
 * @note No special permissions required - just valid authentication
 * @note Lightweight operation for credential validation
 *
 * @see AWS STS GetCallerIdentity API documentation
 * @since 1.0.0
 */
/*jsl:ignore*/
function getCallerIdentity(req, res, next) {
    assert.object(req, 'req');
    assert.object(res, 'res');
    assert.object(req.body, 'body');
    assert.object(req.body.caller, 'caller');
    assert.func(next, 'callback');

    var log = req.log;

    log.debug('sts.getCallerIdentity: entered');

    // Extract caller from request body (sent by manta-buckets-api)
    var caller = req.body.caller;

    log.debug({
        hasCaller: !!caller,
        hasCallerUser: caller && !!caller.user,
        hasCallerAccount: caller && !!caller.account,
        caller: caller
    }, 'sts.getCallerIdentity: checking caller structure');

    if (!caller || !caller.account) {
        log.error({
            caller: caller,
            hasAccount: caller && !!caller.account
        }, 'GetCallerIdentity: No authenticated caller found');
        return (next(new errors.AccessDeniedError('Authentication required')));
    }

    var user = caller.user;
    var account = caller.account;

    // Get ARN partition from request or use default
    var arnPartition = (req.arnPartition) ?
        req.arnPartition : DEFAULT_ARN_PARTITION;

    // Determine the caller type and construct appropriate response
    var userId, arn, accountId, isTemporaryCredential, assumedRole;
    assumedRole = req.header('x-assumed-role-arn');
    isTemporaryCredential = req.header('x-is-temporary-credential');

    if (req.auth && isTemporaryCredential && assumedRole) {
        // This is a role session (temporary credentials from AssumeRole)
        var roleData = assumedRole;
        userId = assumedRole;
        arn = assumedRole;
        accountId = (user && user.uuid) || (account && account.uuid);

        log.info({
            roleArn: arn,
            principalUuid: req.auth.principalUuid,
            accountId: accountId
        }, 'GetCallerIdentity: Role session detected');

    } else if (req.auth && req.auth.isTemporaryCredential) {
        // This is a federated session (GetSessionToken)
        userId = (user && user.uuid) || (account && account.uuid);
        arn = 'arn:' + arnPartition + ':sts::' +
            ((user && user.uuid) || (account && account.uuid)) +
            ':federated-user/' +
            ((user && user.login) || (account && account.login));
        accountId = (user && user.uuid) || (account && account.uuid);

        log.debug({
            userUuid: userId,
            federatedArn: arn,
            accountId: accountId
        }, 'GetCallerIdentity: Federated session detected');

    } else {
        // This is a permanent credential (IAM user)
        userId = (user && user.uuid) || (account && account.uuid);
        arn = 'arn:' + arnPartition + ':iam::' +
            ((account && account.uuid) || (user && user.uuid)) + ':user/' +
            ((user && user.login) || (account && account.login));
        accountId = (account && account.uuid) || (user && user.uuid);

        log.debug({
            userUuid: userId,
            userArn: arn,
            accountId: accountId
        }, 'GetCallerIdentity: Permanent credentials detected');
    }

    // Construct AWS STS GetCallerIdentity response XML
    var responseXml = '<?xml version="1.0" encoding="UTF-8"?>\n' +
        '<GetCallerIdentityResponse xmlns=' +
        '"https://sts.amazonaws.com/doc/2011-06-15/">\n' +
        '  <GetCallerIdentityResult>\n' +
        '    <UserId>' + userId + '</UserId>\n' +
        '    <Account>' + accountId + '</Account>\n' +
        '    <Arn>' + arn + '</Arn>\n' +
        '  </GetCallerIdentityResult>\n' +
        '  <ResponseMetadata>\n' +
        '    <RequestId>' + generateUUID() + '</RequestId>\n' +
        '  </ResponseMetadata>\n' +
        '</GetCallerIdentityResponse>';

    log.info({
        userId: userId,
        accountId: accountId,
        arn: arn,
        isTemporary: !!(req.auth && req.auth.isTemporaryCredential),
        isRole: !!(req.auth && req.auth.assumedRole)
    }, 'GetCallerIdentity: Successfully processed request');

    // Set appropriate headers and send response
    res.header('Content-Type', 'text/xml');
    res.send(200, responseXml);
    return (next(false)); // Don't continue to other handlers
}
/*jsl:end*/

module.exports = {
    assumeRole: assumeRole,
    getSessionToken: getSessionToken,
    getCallerIdentity: getCallerIdentity,

    // Export internal functions for use within mahi components
    internal: {
        validateTrustPolicy: validateTrustPolicy,
        validatePrincipal: validatePrincipal,
        validateSinglePrincipal: validateSinglePrincipal,
        validateServicePrincipal: validateServicePrincipal,
        statementMatchesAction: statementMatchesAction,
        fetchRoleTrustPolicy: fetchRoleTrustPolicy,
        generateUUID: generateUUID,
        generateSessionTokenAccessKeyId: generateSessionTokenAccessKeyId,
        generateAssumeRoleAccessKeyId: generateAssumeRoleAccessKeyId
    }
};
