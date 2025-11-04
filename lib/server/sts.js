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
var errors = require('./errors.js');

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
    if (roleArn.includes('\0') || roleSessionName.includes('\0')) {
        throw new errors.InvalidParameterError(
            'Null bytes not allowed in parameters');
    }

    if (roleArn.includes('..') || roleSessionName.includes('..')) {
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
 * @brief Generates temporary access key ID for STS credentials
 *
 * Creates a unique access key identifier with MSTS prefix to
 * distinguish temporary credentials from permanent ones.
 *
 * @return {string} Temporary access key ID in format "MSTS<hex>"
 *                  where <hex> is 16 random hexadecimal chars
 *
 * @note Uses crypto.randomBytes for cryptographic randomness
 * @note MSTS prefix enables credential type identification
 *
 * @example
 * var keyId = generateTemporaryAccessKeyId();
 * // Returns: "MSTS4F2A1B3C9E7D8A6F"
 *
 * @since 1.0.0
 */
function generateTemporaryAccessKeyId() {
    // Use MSTS prefix to distinguish from permanent credentials
    var prefix = 'MSTS';
    var randomPart = crypto.randomBytes(8).toString('hex').toUpperCase();
    return (prefix + randomPart);
}

/**
 * @brief Generates temporary secret access key
 *
 * Creates a cryptographically random secret key for temporary
 * credentials using 256 bits of entropy.
 *
 * @return {string} Base64-encoded secret key (44 characters)
 *
 * @note Uses crypto.randomBytes(32) for 256-bit entropy
 * @note Base64 encoding for AWS compatibility
 *
 * @example
 * var secret = generateTemporarySecretKey();
 * // Returns: "AbC123dEf456GhI789jKl012MnO345pQr678StU901VwX="
 *
 * @since 1.0.0
 */
function generateTemporarySecretKey() {
    return (crypto.randomBytes(32).toString('base64'));
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
                caller: caller.uuid,
                principal: statement.Principal,
                effect: 'Deny'
            }, 'Trust policy DENY statement matched - access denied');
            return (false); // Explicit deny overrides everything
        }
    }

    // Special business rule: Check if root user in mixed policy scenario
    if (caller.login === 'root') {
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
                    if (/^\d{12}$/.test(principals[m]) &&
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
                caller: caller.uuid,
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
                caller: caller.uuid,
                callerLogin: caller.login,
                callerAccountUuid: caller.account ? caller.account.uuid : null,
                principal: allowStatement.Principal,
                effect: 'Allow'
            }, 'SECURITY DEBUG: Checking Allow statement principal');

            if (validatePrincipal(allowStatement.Principal, caller, log)) {
                log.debug({
                    statement: j,
                    caller: caller.uuid,
                    callerLogin: caller.login,
                    principal: allowStatement.Principal,
                    effect: 'Allow'
                }, 'SECURITY DEBUG:' +
                   ' Trust policy ALLOW statement matched - GRANTING ACCESS');
                return (true); // Explicit allow found
            } else {
                log.debug({
                    statement: j,
                    caller: caller.uuid,
                    callerLogin: caller.login,
                    principal: allowStatement.Principal,
                    effect: 'Allow'
                }, 'SECURITY DEBUG: ' +
                          'Trust policy ALLOW statement did NOT match');
            }
        }
    }

    // No explicit ALLOW found - implicit deny
    log.warn({
        caller: caller.uuid,
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
    // Handle different principal formats

    if (typeof (principal) === 'string') {
        if (principal === '*') {
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
    if (principalString === '*') {
        return (true);
    }

    // Handle ARN format: arn:aws:iam::account-id:user/username
    // or arn:aws:iam::account-id:root
    if (principalString.indexOf('arn:aws:iam::') === 0) {
        var arnParts = principalString.split(':');
        if (arnParts.length >= 6) {
            var accountId = arnParts[4];
            var resourcePart = arnParts.slice(5).join(':');

            // Handle root ARN - must match both account and login
            if (resourcePart === 'root' && caller.account &&
                caller.account.uuid === accountId) {
                return (caller.login === 'root');
            }

            // Handle user ARN - must match both account and username
            if (resourcePart.indexOf('user/') === 0 &&
                caller.account &&
                caller.account.uuid === accountId) {
                var username = resourcePart.substring(5); // Remove 'user/'
                return (caller.login === username);
            }
        }
    }

    // Handle account ID (12-digit string)
    // Note: Root users should only match explicit root ARNs, not account-level
    if (/^\d{12}$/.test(principalString)) {
        return caller.account &&
            caller.account.uuid === principalString &&
            caller.login !== 'root';
    }

    // Handle UUID format directly
    // Note: Root users should only match explicit root ARNs, not account-level
    if (caller.account &&
        caller.account.uuid === principalString &&
        caller.login !== 'root') {
        return (true);
    }

    // SECURITY: Do not allow matching by caller UUID alone
    // This would allow any authenticated user to assume any role
    // by providing their UUID as the principal. Role assumption
    // should only be authorized via explicit ARN or account-level policies.

    log.debug({
        principal: principalString,
        callerUuid: caller.uuid,
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
 * Performs complete role assumption workflow including trust policy
 * validation, temporary credential generation, and UFDS storage.
 *
 * @param {Object} req Restify request object containing parameters:
 * @param {string} req.params.RoleArn ARN of role to assume
 * @param {string} req.params.RoleSessionName Session identifier
 * @param {number} req.params.DurationSeconds Credential lifetime
 * @param {Object} res Restify response object
 * @param {function} next Restify next callback function
 *
 * @note Validates caller authorization via trust policy evaluation
 * @note Generates MSTS-prefixed temporary access keys
 * @note Creates session tokens for credential identification
 * @note Stores temporary credentials in UFDS with expiration
 * @note Returns AWS STS AssumeRoleResponse XML format
 *
 * @error 400 InvalidParameterError Missing or invalid parameters
 * @error 403 AssumeRoleAccessDenied Trust policy denies access
 * @error 404 NoSuchEntityError Role not found in directory
 * @error 500 InternalError UFDS or credential generation failure
 *
 * @example
 * POST /sts/assume-role
 * {
 *   "RoleArn": "arn:aws:iam::123456789012:role/MyRole",
 *   "RoleSessionName": "session1",
 *   "DurationSeconds": 3600
 * }
 *
 * @since 1.0.0
 */
/*jsl:ignore*/
function assumeRole(req, res, next) {
    var log = req.log;

    log.debug('sts.assumeRole: entered');

    // Extract parameters
    var roleArn = req.params.RoleArn || req.body.RoleArn;
    var roleSessionName = req.params.RoleSessionName ||
        req.body.RoleSessionName;
    var durationSeconds = parseInt(req.params.DurationSeconds ||
                                   req.body.DurationSeconds || 3600, 10);

    // Comprehensive input validation with multi-cloud ARN support
    try {
        validateStsAssumeRoleInputs(roleArn, roleSessionName, durationSeconds);
    } catch (validationError) {
        next(validationError);
        return;
    }

    // For now, assume caller identity is available (from
    // authentication middleware)
    var callerUuid = req.caller ? req.caller.uuid : null;
    if (!callerUuid) {
        next(new errors.InvalidParameterError(
            'Caller identity required'));
        return;
    }

    // Validate role trust policy before generating credentials
    log.error({
        hasUfds: !!req.ufds,
        roleArn: roleArn,
        callerUuid: callerUuid,
        note: 'CRITICAL DEBUG: ' +
            ' Checking UFDS availability for trust policy validation'
    }, 'CRITICAL DEBUG: About to check UFDS for trust policy validation');

    if (!req.ufds) {
        log.error({
            hasUfds: !!req.ufds,
            roleArn: roleArn,
            callerUuid: callerUuid,
            note: 'UFDS client required for trust policy validation'
        }, 'SECURITY: AssumeRole denied - UFDS unavailable, ' +
                  'cannot validate trust policy');

        return (next(new errors.InternalError(
            'Authentication service unavailable - ' +
                'cannot validate role trust policy')));
    }

    log.error({
        hasUfds: !!req.ufds,
        roleArn: roleArn,
        callerUuid: callerUuid,
        note: 'CRITICAL DEBUG: UFDS is available,' +
            ' proceeding to fetch trust policy'
    }, 'CRITICAL DEBUG: UFDS available, fetching trust policy');

    // Fetch role's trust policy from UFDS
    fetchRoleTrustPolicy(roleArn, req.ufds, log,
        function (fetchErr, trustPolicy) {
        if (fetchErr) {
            log.error({
                err: fetchErr,
                roleArn: roleArn,
                callerUuid: callerUuid
            }, 'Failed to fetch role trust policy');
            return (next(fetchErr));
        }

        // Validate trust policy
        log.debug({
            roleArn: roleArn,
            callerUuid: callerUuid,
            callerLogin: req.caller.login,
            callerAccountUuid: req.caller.account ?
                req.caller.account.uuid : null,
            trustPolicy: trustPolicy,
            hasValidTrustPolicy: !!trustPolicy
        }, 'SECURITY DEBUG: About to validate trust policy');

        if (!validateTrustPolicy(trustPolicy, req.caller, log)) {
            log.warn({
                roleArn: roleArn,
                callerUuid: callerUuid,
                callerLogin: req.caller.login,
                callerAccountUuid: req.caller.account ?
                    req.caller.account.uuid : null,
                trustPolicy: trustPolicy
            }, 'Trust policy validation failed - access denied');

            var accessDeniedError = new errors.AccessDeniedError(
                'AssumeRole access denied by trust policy');
            return (next(accessDeniedError));
        }

        log.info({
            roleArn: roleArn,
            callerUuid: callerUuid
        }, 'Trust policy validation successful');

        // Generate and return credentials
        return (generateAndReturnCredentials());
    });

    // Function to generate and return credentials (extracted for reuse)
    function generateAndReturnCredentials() {
        // Generate temporary credentials
        var tempAccessKeyId = generateTemporaryAccessKeyId();
        var tempSecretKey = generateTemporarySecretKey();
        var expiration = new Date(Date.now() +
            durationSeconds * 1000);

        // Generate secure JWT session token (v1.1 with keyId in payload)
        var sessionTokenData = {
            uuid: callerUuid,
            expires: Math.floor(expiration.getTime() / 1000),
            sessionName: roleSessionName,
            roleArn: roleArn
        };

        var sessionToken;
        try {
            var sessionTokenModule = require('./session-token');

            // Get secret configuration (passed by server wrapper)
            if (!req.sessionConfig || !req.sessionConfig.secretKey) {
                throw new Error('Session secret key not configured');
            }

            // Build secret config using the same function as server.js
            var buildSecretConfig =
                require('./server.js').buildSecretConfig;
            var secretConfig = buildSecretConfig(req.sessionConfig);

            if (!secretConfig.primarySecret) {
                throw new Error('Session secret key not configured');
            }

            var tokenOptions = {
                issuer: req.sessionConfig.issuer || 'manta-mahi',
                audience: req.sessionConfig.audience || 'manta-s3'
            };

            sessionToken = sessionTokenModule.generateSessionToken(
                sessionTokenData,
                secretConfig.primarySecret,
                tokenOptions);

            log.debug({
                roleArn: roleArn,
                sessionName: roleSessionName,
                expires: expiration.toISOString(),
                tokenLength: sessionToken.length,
                keyId: secretConfig.primarySecret.keyId
            }, 'Generated secure JWT session token for AssumeRole');

        } catch (tokenErr) {
            log.error({
                error: tokenErr.message,
                roleArn: roleArn,
                sessionName: roleSessionName
            }, 'Failed to generate JWT session token for AssumeRole');

            return (next(new errors.InternalError(
                'Failed to generate session token: ' + tokenErr.message)));
        }

        // Add temporary credential to UFDS via LDAP client
        var dn = 'accesskeyid=' + tempAccessKeyId +
            ', uuid=' + callerUuid + ', ou=users, o=smartdc';
        var ldapObject = {
            objectclass: ['accesskey'],
            accesskeyid: tempAccessKeyId,
            accesskeysecret: tempSecretKey,
            sessiontoken: sessionToken,
            expiration: expiration.toISOString(),
            principaluuid: callerUuid,
            assumedrole: roleArn,
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
                roleArn: roleArn,
                sessionName: roleSessionName
            }
        }, 'Creating temporary credential in UFDS');

        if (!req.ufdsPool) {
            log.error({
                hasUfdsPool: !!req.ufdsPool,
                roleArn: roleArn,
                sessionName: roleSessionName
            }, 'STS AssumeRole failed: UFDS connection pool not available');

            next(new errors.InternalError(
                'STS service not properly configured' +
                ' - UFDS client unavailable'));
            return;
        }

        // Use connection pool for UFDS operations
        req.ufdsPool.acquire(function (poolErr, ufdsClient) {
            if (poolErr) {
                log.error({err: poolErr},
                          'Failed to acquire UFDS connection for AssumeRole');
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
                    accessKeyId: tempAccessKeyId
                }, 'Failed to create temporary credential in UFDS');
                next(new errors.InternalError(
                    'Failed to create temporary credential'));
                return;
            }

            log.info({
                accessKeyId: tempAccessKeyId,
                expiration: expiration.toISOString(),
                roleArn: roleArn,
                sessionName: roleSessionName,
                dn: dn
            }, 'Successfully created temporary credential ' +
                'in UFDS');

            // Return STS response
            var response = {
                AssumeRoleResponse: {
                    AssumeRoleResult: {
                        Credentials: {
                            AccessKeyId: tempAccessKeyId,
                            SecretAccessKey: tempSecretKey,
                            SessionToken: sessionToken,
                            Expiration: expiration.toISOString()
                        },
                        AssumedRoleUser: {
                            AssumedRoleId: roleArn + ':' +
                                roleSessionName,
                            Arn: roleArn
                        }
                    }
                }
            };

            res.send(200, response);
            next();
            return;
            });
        }); // End pool.acquire callback
    } // End generateAndReturnCredentials function
} // End assumeRole function
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
 * @note Creates base64-encoded session tokens for identification
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
    var log = req.log;

    log.debug('sts.getSessionToken: entered');

    var callerUuid = req.caller ? req.caller.uuid : null;
    log.debug({
        callerUuid: callerUuid,
        hasUfds: !!req.ufds,
        hasCallerIdentity: !!req.caller,
        callerHeaders: {
            'x-caller-uuid': req.headers['x-caller-uuid'],
            'x-caller-login': req.headers['x-caller-login']
        }
    }, 'STS getSessionToken: processing request');

    var durationSeconds = parseInt(req.params.DurationSeconds ||
                                   req.body.DurationSeconds || 3600, 10);

    if (durationSeconds < 900 || durationSeconds > 129600) {
        next(new errors.InvalidParameterError(
            'DurationSeconds must be between 900 and 129600'));
        return;
    }

    if (!callerUuid) {
        log.error({
            caller: req.caller,
            callerHeaders: {
                'x-caller-uuid': req.headers['x-caller-uuid'],
                'x-caller-login': req.headers['x-caller-login']
            }
        }, 'Missing caller identity in GetSessionToken');
        next(new errors.InvalidParameterError(
            'Caller identity required'));
        return;
    }

    // Generate temporary credentials using ufds accesskey module
    // (same as AssumeRole)
    var tempAccessKeyId = generateTemporaryAccessKeyId();
    var expiration = new Date(Date.now() +
        durationSeconds * 1000);

    // Use accesskey.generate to create UFDS-compatible secret
    var accesskey = require('ufds/lib/accesskey');
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
        var sessionToken = require('./session-token');

        // Get secret configuration from request (passed by server wrapper)
        if (!req.sessionConfig || !req.sessionConfig.secretKey) {
            throw new Error('Session secret key not configured');
        }

        // Build secret configuration using the same function as server.js
        var buildSecretConfig = require('./server.js').buildSecretConfig;
        var secretConfig = buildSecretConfig(req.sessionConfig);

        if (!secretConfig.primarySecret) {
            throw new Error('Session secret key not configured');
        }

        var tokenOptions = {
            issuer: req.sessionConfig.issuer || 'manta-mahi',
            audience: req.sessionConfig.audience || 'manta-s3'
        };

        secureSessionToken = sessionToken.generateSessionToken(
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
    assert.func(next, 'callback');

    var log = req.log;

    log.debug('sts.getCallerIdentity: entered');

    // GetCallerIdentity works with the already authenticated caller
    var caller = req.caller;

    log.debug({
        hasCaller: !!caller,
        hasCallerUser: caller && !!caller.user,
        hasCallerAccount: caller && !!caller.account,
        caller: caller
    }, 'sts.getCallerIdentity: checking caller structure');

    if (!caller || (!caller.user && !caller.account)) {
        log.error({
            caller: caller,
            hasUser: caller && !!caller.user,
            hasAccount: caller && !!caller.account
        }, 'GetCallerIdentity: No authenticated caller found');
        return (next(new errors.AccessDeniedError('Authentication required')));
    }

    var user = caller.user;
    var account = caller.account;

    // Determine the caller type and construct appropriate response
    var userId, arn, accountId;

    if (req.auth && req.auth.isTemporaryCredential && req.auth.assumedRole) {
        // This is a role session (temporary credentials from AssumeRole)
        var roleData = req.auth.assumedRole;
        userId = roleData.arn; // Use role ARN as user ID for role sessions
        arn = roleData.arn;
        accountId = user.uuid || account.uuid;

        log.debug({
            roleArn: arn,
            principalUuid: req.auth.principalUuid,
            accountId: accountId
        }, 'GetCallerIdentity: Role session detected');

    } else if (req.auth && req.auth.isTemporaryCredential) {
        // This is a federated session (GetSessionToken)
        userId = (user && user.uuid) || (account && account.uuid);
        arn = 'arn:aws:sts::' + ((user && user.uuid) ||
                                 (account && account.uuid)) +
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
        arn = 'arn:aws:iam::' + ((account && account.uuid) ||
                                 (user && user.uuid)) + ':user/' +
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
        generateTemporaryAccessKeyId: generateTemporaryAccessKeyId,
        generateTemporarySecretKey: generateTemporarySecretKey
        // Removed: generateSessionToken (insecure Base64 method)
        // Use session-token.js module for secure JWT generation
    }
};
