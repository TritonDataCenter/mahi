---
title: Mahi STS API
markdown2extras: tables, code-friendly
---
<!--
    This Source Code Form is subject to the terms of the Mozilla Public
    License, v. 2.0. If a copy of the MPL was not distributed with this
    file, You can obtain one at http://mozilla.org/MPL/2.0/.
-->
<!--
    Copyright 2026 Edgecast Cloud LLC.
-->

# STS (Security Token Service)

AWS-compatible STS endpoints for generating temporary security credentials.

**Note:** These are internal mahi endpoints called by manta-buckets-api after
SigV4 authentication. External clients authenticate via SigV4 to
manta-buckets-api, which then forwards requests to mahi with caller identity
headers.


## AssumeRole (POST /sts/assume-role)

Assumes an IAM role and returns temporary security credentials.

### Inputs

| Field | Type | Required? | Notes |
| ----- | ---- | --------- | ----- |
| RoleArn | string | Yes | `arn:aws:iam::<account-uuid>:role/<role-name>` |
| RoleSessionName | string | Yes | Session identifier (2-64 chars) |
| DurationSeconds | number | No | 900-43200, default 3600 |

### Returns

```json
{
  "AssumeRoleResponse": {
    "AssumeRoleResult": {
      "Credentials": {
        "AccessKeyId": "MSTS-...",
        "SecretAccessKey": "tdc_...",
        "SessionToken": "eyJhbGci...",
        "Expiration": "2025-12-02T12:00:00.000Z"
      },
      "AssumedRoleUser": {
        "AssumedRoleId": "MSTS-...:my-session",
        "Arn": "arn:aws:sts::<account>:assumed-role/<role>/<session>"
      }
    }
  }
}
```

### Errors

| Code | HTTP Status | Description |
| ---- | ----------- | ----------- |
| InvalidParameterValue | 400 | Invalid RoleArn, RoleSessionName, or DurationSeconds |
| NoSuchEntity | 404 | Role does not exist |
| AccessDenied | 403 | Trust policy denies access |
| InternalError | 500 | Credential generation failure |


## GetSessionToken (POST /sts/get-session-token)

Generates temporary credentials for the calling principal (no role assumption).

### Inputs

| Field | Type | Required? | Notes |
| ----- | ---- | --------- | ----- |
| DurationSeconds | number | No | 900-129600, default 3600 |

### Returns

```json
{
  "GetSessionTokenResponse": {
    "GetSessionTokenResult": {
      "Credentials": {
        "AccessKeyId": "MSTS-...",
        "SecretAccessKey": "tdc_...",
        "SessionToken": "eyJhbGci...",
        "Expiration": "2025-12-02T14:00:00.000Z"
      }
    }
  }
}
```

### Errors

| Code | HTTP Status | Description |
| ---- | ----------- | ----------- |
| InvalidParameterValue | 400 | Invalid DurationSeconds |
| InternalError | 500 | Credential generation failure |


## GetCallerIdentity (GET /sts/get-caller-identity)

Returns details about the calling IAM entity.

### Inputs

None.

### Returns

```json
{
  "GetCallerIdentityResponse": {
    "GetCallerIdentityResult": {
      "UserId": "<uuid>",
      "Account": "<uuid>",
      "Arn": "arn:aws:iam::<uuid>:user/<login>"
    }
  }
}
```


# Temporary Credentials

## Credential Format

| Credential | Permanent | Temporary |
|------------|-----------|-----------|
| **AccessKeyId** | 32-char hex (no prefix) | `MSTS-` + hex |
| **SecretAccessKey** | `tdc_` + base64 | `tdc_` + base64 |

Examples:
- Permanent AccessKeyId: `a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6`
- Temporary AccessKeyId: `MSTS-a1b2c3d4e5f6...`
- SecretAccessKey (both): `tdc_xyz123...`

## Storage

Credentials are stored in:
1. **UFDS**: `accesskeyid=<id>, uuid=<user>, ou=users, o=smartdc`
2. **Redis**: `/accesskey/<AccessKeyId>` (cache)
