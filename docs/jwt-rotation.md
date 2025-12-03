# JWT Secret Rotation Implementation for Mahi

## Overview

This document describes the JWT secret rotation system implemented for mahi's session token management for S3 STS requests.
The solution provides zero-downtime secret rotation through a grace period mechanism that allows old and new secrets to coexist temporarily.

## Background

### The Problem
- JWT tokens are signed with HMAC-SHA256 using a secret key
- When the secret changes, ALL existing tokens become invalid immediately
- This causes authentication failures for active users
- Traditional rotation is a breaking change requiring downtime

### The Solution
- **Key Versioning**: Each secret has a unique ID (`kid` in JWT header)
- **Multi-Secret Support**: Server can verify tokens with multiple secrets
- **Grace Period**: Old secrets remain valid for a configurable period
- **Gradual Migration**: New tokens use new secret, old ones expire naturally

## Architecture

### Current Mahi JWT Flow
```
1. STS Operations (AssumeRole/GetSessionToken)
2. Generate JWT with session-token.js
3. Sign with SESSION_SECRET_KEY
4. Client uses JWT for authentication
5. Server verifies JWT signature
```

### Enhanced Flow with Rotation
```
1. STS Operations (AssumeRole/GetSessionToken)
2. Generate JWT with session-token.js + key ID
3. Sign with current PRIMARY secret
4. Client uses JWT for authentication
5. Server verifies JWT with multiple secrets:
   - Try specific key ID first (if present)
   - Fallback to all valid secrets
   - Check grace period for old secrets
```

## Implementation Details

### 1. Enhanced Session Token Module (`lib/server/session-token.js`)

#### Key Changes:
- **Backward compatible**: Supports both v1.0 (legacy) and v1.1 (rotation) tokens
- **Key ID support**: Adds `kid` field to JWT header
- **Multi-secret verification**: Three verification strategies:
  - Single secret (current behavior)
  - Array of secrets (simple fallback)
  - Full rotation config (production mode)

#### Token Format Evolution:

**Important:** Due to limitations in `jsonwebtoken` v1.1.0 (which doesn't support custom headers), the key ID is stored in the JWT **payload** as `keyId`, not in the standard JWT header as `kid`. This is a non-standard approach but works for internal rotation purposes.

```javascript
// JWT Header (same for both versions - no kid support)
{
  "alg": "HS256",
  "typ": "JWT"
}

// Legacy v1.0 payload (no keyId)
{
  "uuid": "...",
  "roleArn": "...",
  "sessionName": "..."
}

// New v1.1 payload (with keyId in payload, not header)
{
  "uuid": "...",
  "roleArn": "...",
  "sessionName": "...",
  "tokenVersion": "1.1",
  "keyId": "key-20250120-143022"  // Non-standard: in payload, not header
}
```

**Limitation:** External JWT libraries expecting `kid` in the header won't find it. To support standard `kid` header claim, would need to upgrade `jsonwebtoken` to a newer version or use a different JWT library.

#### New Functions:
- `generateKeyId()`: Creates versioned key IDs
- `verifyWithMultipleSecrets()`: Handles rotation verification
- `isSecretValid()`: Checks if secret is within grace period
- `getValidSecrets()`: Returns all currently valid secrets

### 2. Configuration Enhancement (`sapi_manifests/mahi2/template`)

#### New Fields:
```json
{
  "sessionConfig": {
    "secretKey": "SESSION_SECRET_KEY",           // Current primary secret
    "secretKeyId": "SESSION_SECRET_KEY_ID",     // Current key ID
    "oldSecretKey": "SESSION_SECRET_KEY_OLD",   // Previous secret (grace period)
    "oldSecretKeyId": "SESSION_SECRET_KEY_OLD_ID", // Previous key ID
    "rotationTime": "SESSION_SECRET_ROTATION_TIME", // When rotation occurred
    "gracePeriod": "SESSION_SECRET_GRACE_PERIOD",   // Grace period duration
    "issuer": "manta-mahi",
    "audience": "manta-s3",
    "defaultDuration": 3600,
    "maxDuration": 43200
  }
}
```

### 3. Server Integration (`lib/server/server.js`)

#### New Function: `buildSecretConfig()`
- Reads rotation configuration from environment/config
- Builds multi-secret structure for verification
- Handles both legacy and rotation modes
- Supports graceful transition

#### Secret Structure:
```javascript
{
  primarySecret: {
    key: "abc123...",
    keyId: "key-20250120-143022"
  },
  secrets: {
    "key-20250120-143022": {
      key: "abc123...",
      keyId: "key-20250120-143022", 
      isPrimary: true,
      addedAt: 1705751822000
    },
    "primary": {
      key: "xyz789...",
      keyId: "primary",
      isPrimary: false,
      addedAt: 1705665422000
    }
  },
  gracePeriod: 86400
}
```

### 4. Rotation Script (`boot/rotate-session-secret.sh`)

#### Features:
- **Dry-run mode**: Test rotations without making changes
- **Force mode**: Override safety checks
- **Configurable grace period**: Default 24 hours
- **Automatic backup**: Current secret becomes old secret
- **SAPI integration**: Persists configuration across restarts
- **Instance notification**: Signals running mahi processes to reload
- **Cleanup**: Removes expired secrets automatically

#### Usage Examples:
```bash
# Standard rotation
./rotate-session-secret.sh

# Dry run
./rotate-session-secret.sh --dry-run

# Custom grace period (6 hours)
./rotate-session-secret.sh --grace-period 21600

# Force rotation
./rotate-session-secret.sh --force
```

### 5. Enhanced Setup Process (`boot/setup.sh`)

#### Enhancements:
- **Backward compatibility**: Existing installations get rotation support
- **Key ID assignment**: Legacy secrets get proper key IDs
- **Automatic cleanup**: Boot process removes expired secrets
- **Metadata initialization**: Sets up rotation tracking

## Rotation Timeline

### Phase 1: Preparation (T-0)
```
Current State:
- All tokens signed with SECRET_A (key-id: primary)
- All instances verify with SECRET_A only
```

### Phase 2: Rotation (T+0)
```bash
./rotate-session-secret.sh
```
```
Actions:
1. Generate SECRET_B with new key-id: key-20250120-143022
2. Backup SECRET_A as old secret
3. Update SAPI metadata
4. Signal mahi instances to reload config

Result:
- New tokens signed with SECRET_B (key-id: key-20250120-143022)
- Old tokens still valid (SECRET_A verification)
- Both secrets active for grace period
```

### Phase 3: Grace Period (T+0 to T+24h)
```
Behavior:
- New STS operations → JWT with SECRET_B
- Old JWT tokens → Verified with SECRET_A
- Gradual migration as old tokens expire naturally
- No authentication failures
```

### Phase 4: Completion (T+24h)
```
Actions:
- Grace period expires
- SECRET_A automatically removed
- Only SECRET_B remains valid

Result:
- All active tokens use SECRET_B
- Zero-downtime rotation complete
```

## Security Considerations

### Secret Storage
- **SAPI Metadata**: Secrets stored in SAPI application metadata
- **Environment Variables**: Runtime access via environment
- **No Local Storage**: Secrets not stored in files on disk

### Grace Period Security
- **Limited Duration**: Default 24 hours, configurable minimum
- **Automatic Cleanup**: Expired secrets removed automatically  
- **Emergency Revocation**: Can immediately disable old secrets if compromised
- **Audit Trail**: Track which secret was used for each token

### Key ID Security
- **Cryptographically Random**: Key IDs include random component
- **Timestamped**: Include creation timestamp
- **Unique**: No collision risk across rotations

## Operational Procedures

### Scheduled Rotation
```bash
# Monthly rotation via cron
echo "0 2 1 * * /opt/smartdc/mahi/boot/scripts/rotate-session-secret.sh" >> /var/spool/cron/crontabs/root
```

### Emergency Rotation
```bash
# Immediate rotation with short grace period
./rotate-session-secret.sh --force --grace-period 3600
```

### Monitoring Rotation
```bash
# Check current rotation status
mdata-get sdc:application_metadata.SESSION_SECRET_KEY_ID
mdata-get sdc:application_metadata.SESSION_SECRET_ROTATION_TIME
mdata-get sdc:application_metadata.SESSION_SECRET_GRACE_PERIOD
```

### Rollback Procedure
If rotation causes issues, can manually swap secrets:
```bash
# Emergency rollback (swap current and old secrets)
OLD_SECRET=$(mdata-get sdc:application_metadata.SESSION_SECRET_KEY_OLD)
CURRENT_SECRET=$(mdata-get sdc:application_metadata.SESSION_SECRET_KEY)

set-sapi-metadata.sh SESSION_SECRET_KEY "$OLD_SECRET"
set-sapi-metadata.sh SESSION_SECRET_KEY_OLD "$CURRENT_SECRET"

# Signal mahi instances
pkill -HUP -f "node.*mahi"
```

## Testing Strategy

### Unit Tests
- Token generation with key IDs
- Multi-secret verification
- Grace period validation
- Secret expiration cleanup

### Integration Tests  
- Full rotation workflow
- Backward compatibility
- Cross-version token verification
- Error handling scenarios

### Load Testing
- Rotation under load
- Performance impact measurement
- Memory usage with multiple secrets

## Migration Plan

### Phase 1: Deploy Code (Backward Compatible)
- Deploy enhanced session-token module
- No configuration changes needed
- Existing tokens continue working

### Phase 2: Enable Rotation Support
- Run enhanced setup.sh
- Adds key IDs to existing secrets
- Makes rotation script executable

### Phase 3: First Rotation
- Test with dry-run first
- Perform actual rotation
- Monitor for issues

### Phase 4: Automation
- Set up scheduled rotation
- Document operational procedures
- Train operations team

## Benefits

### Security Benefits
- **Regular Key Rotation**: Reduces impact of key compromise
- **Limited Blast Radius**: Old compromised keys expire automatically
- **Crypto Agility**: Easy to change algorithms/key sizes in future

### Operational Benefits
- **Zero Downtime**: No service interruption during rotation
- **Automatic Management**: Minimal manual intervention required
- **Backward Compatible**: Works with existing deployments
- **Audit Trail**: Track rotation history

### Development Benefits
- **Gradual Migration**: No flag day deployments required
- **Testing Support**: Dry-run mode for safe testing
- **Error Recovery**: Rollback procedures available

## Future Enhancements

### Possible Improvements
1. **Key Escrow**: Store encrypted copies of keys for disaster recovery
2. **HSM Integration**: Use Hardware Security Modules for key storage
3. **Automatic Detection**: Monitor for compromised keys
4. **Policy-Based Rotation**: Different rotation schedules per environment
5. **Metrics**: Detailed rotation metrics and alerting

### Algorithm Evolution
- **Modern Algorithms**: Easy migration to Ed25519 or other modern algorithms
- **Key Size Changes**: Support for larger key sizes
- **Multiple Algorithms**: Support different algorithms simultaneously

## SAPI Integration Details

### SmartDataCenter SAPI Workflow

The rotation system leverages SmartDataCenter's SAPI (Services API) for distributing secret metadata across all mahi instances in the datacenter.

#### Key Components:

1. **SAPI Service API**: Centralized metadata storage for services
2. **Config-Agent**: Runs on each zone, automatically updates configurations when SAPI metadata changes
3. **Service Templates**: SAPI manifest templates define how metadata becomes configuration

#### Integration Flow:

```
1. Rotation Script runs → set-sapi-metadata.sh
2. Script calls SAPI API → Updates service metadata
3. SAPI notifies all instances → Config-agent receives updates
4. Config-agent renders templates → Updates /opt/smartdc/mahi/etc/mahi.json
5. SIGHUP sent to mahi → Process reloads configuration
```

#### SAPI Metadata Structure:

```json
{
  "SESSION_SECRET_KEY": "current-primary-secret",
  "SESSION_SECRET_KEY_ID": "key-20250120-143022", 
  "SESSION_SECRET_KEY_OLD": "previous-secret",
  "SESSION_SECRET_KEY_OLD_ID": "key-20250119-120000",
  "SESSION_SECRET_ROTATION_TIME": "1705751822",
  "SESSION_SECRET_GRACE_PERIOD": "86400"
}
```

#### Template Processing:

The `/home/build/S3-MANTA/mahi/sapi_manifests/mahi/template` file defines how SAPI metadata becomes mahi configuration:

```json
{
  "sessionConfig": {
    "secretKey": "{{SESSION_SECRET_KEY}}",
    "secretKeyId": "{{SESSION_SECRET_KEY_ID}}",
    "oldSecretKey": "{{SESSION_SECRET_KEY_OLD}}",
    "oldSecretKeyId": "{{SESSION_SECRET_KEY_OLD_ID}}",
    "rotationTime": "{{SESSION_SECRET_ROTATION_TIME}}",
    "gracePeriod": "{{SESSION_SECRET_GRACE_PERIOD}}"
  }
}
```

### SAPI Script Implementation (`boot/set-sapi-metadata.sh`)

#### Key Operations:

1. **Service Discovery**: Uses `mdata-get sdc:tags.manta_role` to get service role (typically "authcache")
2. **Service Lookup**: Calls SAPI API to find service UUID by role name
3. **Metadata Update**: Updates service metadata via PUT to `/services/{uuid}`
4. **Error Handling**: Graceful degradation for development environments

#### Security Considerations:

- **Read-Only mdata**: Cannot write directly to `sdc:` namespace (read-only)
- **Proper Workflow**: Must use SAPI API calls, not direct mdata manipulation
- **Service Authentication**: Uses zone's natural SAPI access permissions

### Mahi Integration Architecture

#### Configuration Loading:

```javascript
// lib/server/server.js - Enhanced with rotation support
function buildSecretConfig(sessionConfig) {
    // Handle both legacy and rotation configurations
    if (sessionConfig.secretKeyId || sessionConfig.oldSecretKey) {
        // Full rotation configuration
        return buildRotationConfig(sessionConfig);
    } else {
        // Legacy single-secret mode
        return buildLegacyConfig(sessionConfig);
    }
}
```

#### Multi-Instance Coordination:

1. **Single Source of Truth**: SAPI metadata is authoritative
2. **Automatic Propagation**: Config-agent ensures all instances stay synchronized
3. **Graceful Updates**: SIGHUP triggers configuration reload without service restart
4. **Consistency**: All instances transition together during rotation

#### Boot Safety Mechanisms:

```bash
# rotate-session-secret.sh - Idempotent behavior
function check_rotation_needed() {
    # Check if secrets already exist (prevents rotation on every boot)
    if [[ -n "$current_secret" && -n "$current_key_id" ]]; then
        log "No rotation needed - secrets are already present."
        return 1
    fi
}
```

### Deployment Considerations

#### File Locations in Production:

```
/opt/smartdc/mahi/boot/rotate-session-secret.sh
/opt/smartdc/mahi/boot/set-sapi-metadata.sh
/opt/smartdc/mahi/etc/mahi2.json (generated by config-agent from mahi2/template)
```

Note: The `mahi/boot` directory is copied to `/opt/smartdc/boot` during deployment, so scripts run from the central boot location.

#### Template Manifests:

- `sapi_manifests/mahi/template` - Main mahi service template
- `sapi_manifests/mahi2/template` - Secondary mahi service template (STS operations)

Both templates now include all rotation variables for consistent behavior across service types.

## Lessons Learned

### SAPI Workflow Understanding:

1. **Namespace Restrictions**: The `sdc:` namespace in zone metadata is read-only
2. **Proper API Usage**: Must use SAPI REST API, not direct metadata manipulation
3. **Service Discovery**: Use zone tags to find correct service for metadata updates
4. **Config-Agent Integration**: Automatic template processing and configuration updates

### Boot Script Safety:

1. **Idempotent Design**: Scripts must be safe to run on every boot
2. **State Checking**: Always check existing configuration before making changes
3. **Graceful Degradation**: Handle missing dependencies in development environments

### Multi-Instance Challenges:

1. **Coordination**: All instances must transition together
2. **Timing**: Grace periods must account for config propagation delays
3. **Consistency**: SAPI provides single source of truth for configuration

### Path Management:

1. **Deployment Paths**: Scripts run from `/opt/smartdc/boot`, not source locations
2. **Service Paths**: Configuration files in `/opt/smartdc/mahi/etc/`
3. **Template Processing**: SAPI manifest templates define final configuration structure

## Conclusion

This JWT rotation implementation provides a robust, secure, and operationally friendly solution for managing JWT secrets in production. The grace period mechanism ensures zero-downtime rotations while maintaining strong security posture through regular key rotation.

The solution integrates deeply with SmartDataCenter's SAPI infrastructure for reliable metadata distribution and automatic configuration management across all service instances.

Key architectural decisions:
- **SAPI-First Design**: Leverages existing SDC infrastructure for configuration management
- **Idempotent Operations**: Safe to run rotation scripts on boot without side effects  
- **Graceful Transitions**: Multi-secret verification during grace periods prevents service disruption
- **Backward Compatibility**: Supports existing JWT tokens while enabling rotation capabilities

The solution is fully backward compatible and can be deployed incrementally, making it suitable for production environments where service continuity is critical.
