# Operator Endpoints

Mahi exposes two internal endpoints for direct Redis manipulation.
These are on the mahi server port (80) and are not exposed to
external S3 clients.

## POST /cache-push/:accesskeyid

Writes an access key directly to Redis, bypassing the replicator
poll interval (~2s).  Called by CloudAPI after creating or updating
keys for immediate availability.

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| accesskeysecret | string | yes | Secret access key |
| ownerUuid | string | yes | Owner account UUID |
| status | string | no | Key status (default: "Active") |
| scope | string\|null | no | Scope JSON string or null |

**Behavior:**

- Active keys are written in the unified format via the shared
  builder (`redis-accesskey-format.js`), identical to the
  replicator output.
- Inactive keys are removed from Redis (reverse lookup deleted,
  key entry removed from user record).
- Uses `Date.now()` as the write version, which is always greater
  than the replicator's changenumber.  This ensures cachePush
  always wins over a concurrent replicator write.
- Idempotent.  Repeated calls overwrite the previous entry.
- Best-effort: failure is logged at warn level by the CloudAPI
  caller but does not block the CloudAPI response.

**Example:**

```
curl -X POST http://authcache.coal.joyent.us/cache-push/abc123 \
  -H 'Content-Type: application/json' \
  -d '{
    "accesskeysecret": "tdc_...",
    "ownerUuid": "fe3617d8-...",
    "status": "Active",
    "scope": "{\"version\":1,\"permissions\":[{\"bucket\":\"my-bucket\",\"level\":\"read\"}]}"
  }'
```

## POST /key-revoke/:accesskeyid

Removes an access key from Redis immediately and writes a
revocation tombstone with a 24-hour TTL.  The replicator checks
for the tombstone before writing a key — if present, the write
is skipped, making the revocation durable across replication
cycles.

Use for emergency revocation of compromised keys without waiting
for the UFDS delete to propagate through the replicator.

**Request body:** None required.

**Behavior:**

- Deletes the key entry from the user record in Redis.
- Deletes the reverse lookup at `/accesskey/:accesskeyid`.
- Writes a tombstone at `/revoked/:accesskeyid` with a 24-hour
  TTL (`SETEX`).
- Repeated calls renew the tombstone TTL.
- Returns 404 if the key is not found in Redis.

**Important:** Revocation is temporary.  The replicator will
re-add the key on its next cycle once the tombstone expires
(24 hours) if the key still exists in UFDS.  To permanently
revoke a key:

1. Call `DELETE /:account/accesskeys/:id` via CloudAPI
   (which deletes from UFDS and calls key-revoke automatically).
2. Or: call key-revoke for immediate effect, then delete
   from UFDS within 24 hours.

**Example:**

```
curl -X POST http://authcache.coal.joyent.us/key-revoke/abc123
```

**Response:**

```json
{
  "revoked": true,
  "accessKeyId": "abc123",
  "userUuid": "fe3617d8-...",
  "tombstoneTtlSeconds": 86400,
  "replicationWarning": "Key removed from Redis cache and revocation tombstone set (86400s TTL). Delete from UFDS via CloudAPI to permanently revoke."
}
```
