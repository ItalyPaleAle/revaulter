---
title: "Audit events"
weight: 42
---

Revaulter records security-relevant actions to a durable, append-only `v2_audit_events` table. The table sits alongside the operational application log (emitted to stdout): ordinary debug messages still go to the log stream, while audit rows are the long-lived history of *who did what*.

There is currently no admin UI or REST API for reading audit events for all users, and operators must query the table directly with SQL. A read endpoint may ship in a future release.

## What gets recorded

Each row captures one logical action: a confirmed request, a rotated request key, a deleted passkey, etc. Failed and denied attempts are recorded too where the signal is interesting (e.g. a failed login).

Events are written through one of two paths:

- **In-transaction**: for security-critical state changes the audit row commits in the same transaction as the mutation. If the audit insert fails, the user action also rolls back. This guarantees that a "request confirmed" row exists if and only if the request was actually marked confirmed.
- **Best-effort**: for purely observational events (logout cookie clear, background expiry, login *failures*) the audit row is written outside the mutation. A failed audit insert is logged as a warning and does not affect the user-facing response.

## Schema

| column | type | nullable | notes |
| --- | --- | --- | --- |
| `id` | TEXT (SQLite) / UUID (Postgres) | no | Time-sortable primary key (UUIDv7 format) |
| `created_at` | INTEGER (Unix seconds) | no | When the audit row was written |
| `event_type` | TEXT | no | `<area>.<verb>` — see list below |
| `outcome` | TEXT | no | `success` \| `failure` \| `denied` |
| `auth_method` | TEXT | no | `session` \| `request_key` \| `system` \| `none` (set on rows from handlers that run before any authentication is established, e.g. `auth.login_finish` failures) |
| `actor_user_id` | TEXT | yes | The user who performed the action, NULL for unauthenticated failures and pure system events |
| `target_user_id` | TEXT | yes | The user the action affects (often equal to `actor_user_id`) |
| `signing_key_id` | TEXT | yes | Set for `signing_key.*` events |
| `credential_id` | TEXT | yes | Set for `auth.credential_*` events and `auth.login_finish` |
| `request_state` | TEXT | yes | The v2 protocol request `state` for `request.*` events |
| `http_request_id` | TEXT | yes | Correlates the audit row with the HTTP access log |
| `client_ip` | TEXT | yes | NULL for system events |
| `user_agent` | TEXT | yes | Capped at 512 chars |
| `metadata` | TEXT (SQLite) / JSONB (Postgres) | no | Free-form JSON, capped at 4 KiB, default `{}` |
| `seq` | INTEGER (SQLite only) | no | Internal: the shipping key for [streaming to a SIEM](#streaming-to-a-siem). Private property assigned by the database, not included in backups |
| `xact_id` | XID8 (Postgres only) | no | Internal: the shipping key for [streaming to a SIEM](#streaming-to-a-siem). Private property assigned by the database, not included in backups |

## Event types

Naming convention is `<area>.<verb>` with both halves in `snake_case`. The full list is fixed at the application layer. Inserts with any other value are rejected.

### Auth

| event_type | When it fires |
| --- | --- |
| `auth.register_finish` | Account creation completes |
| `auth.finalize_signup` | First-credential setup completes — anchor pubkeys, wrapped keys, request enc keys are written |
| `auth.login_finish` | A login attempt finishes — `outcome=success` for accepted credentials, `outcome=failure` for rejected ones |
| `auth.logout` | User invokes logout. The session JWT is not invalidated server-side — this records the cookie-clear |
| `auth.request_key_regenerate` | User rotates the CLI request key |
| `auth.allowed_ips_change` | Allowed-IP list updated. Metadata: `{old_count, new_count}` |
| `auth.display_name_change` | User updates their display name |
| `auth.wrapped_key_update` | The wrapped primary/anchor key changes. Metadata: `{advance_epoch}` (true when the change is a password rotation) |
| `auth.credential_add_finish` | New passkey registered |
| `auth.credential_rename` | Passkey renamed |
| `auth.credential_delete` | Passkey deleted |

### Requests

| event_type | When it fires |
| --- | --- |
| `request.create` | CLI/API submits a new encrypt/decrypt/sign request. Metadata: `{operation, algorithm, keyLabel, note?}` |
| `request.confirm` | User approves a pending request. Metadata: `{operation, algorithm, keyLabel, note?}` |
| `request.cancel` | User cancels a pending request. Metadata: `{operation, algorithm, keyLabel, note?}` |
| `request.expire` | TTL elapses and the background goroutine marks the request expired. `auth_method=system`. Metadata: `{operation, algorithm, keyLabel, note?}` |

The `note` field is only included when the original request carried a non-empty user-facing note.

### Signing keys

| event_type | When it fires |
| --- | --- |
| `signing_key.create` | User explicitly creates/uploads a signing key. Metadata: `{algorithm, keyLabel, published, hasProof}` |
| `signing_key.publish` | Existing row flipped to `published=true` |
| `signing_key.unpublish` | Existing row flipped back to `published=false` |
| `signing_key.delete` | Row deleted |
| `signing_key.auto_store` | Server stored a derived public key after a successful sign request (no explicit user action) |

## What is *never* recorded

Audit events must never carry sensitive material. The metadata payloads above are designed accordingly. Specifically, audit rows do not store:

- Request keys (`rvk_…`) or session tokens
- Wrapped primary keys, wrapped anchor keys, or any encrypted blob
- Raw WebAuthn credential JSON, attestation payloads, or signature bytes
- Encrypted request/response envelopes
- Webhook URLs or shared secrets
- Allowed-IP lists in full (only their count)
- ML-DSA / ES384 signatures of any kind

The schema-level cap of 4 KiB on `metadata` is a defence-in-depth limit, not a license to spend it on payloads.

## Retention

Rows older than **30 days** are pruned automatically by a background task that runs once at startup and then every 24 hours.

When [streaming to a SIEM](#streaming-to-a-siem) is enabled, the prune is held back to whatever the stream has already shipped, so a collector outage cannot cost you events. That hold has a ceiling of **90 days**, after which rows are pruned even if they have not been delivered. The `revaulter_audit_stream_lag_seconds` metric surfaces a backlog long before that ceiling is reached.

## Sample queries

All queries below assume SQLite syntax. Postgres equivalents differ only in time arithmetic.

**All events for a user in the last 24 hours**

```sql
SELECT created_at, event_type, outcome, client_ip, metadata
FROM v2_audit_events
WHERE actor_user_id = 'user-123'
  AND created_at >= strftime('%s', 'now', '-1 day')
ORDER BY created_at DESC;
```

**All denied or failed actions in the last week**

```sql
SELECT created_at, event_type, actor_user_id, client_ip
FROM v2_audit_events
WHERE outcome IN ('failure', 'denied')
  AND created_at >= strftime('%s', 'now', '-7 days')
ORDER BY created_at DESC;
```

**Every signing-key change ever**

```sql
SELECT created_at, event_type, actor_user_id, signing_key_id, metadata
FROM v2_audit_events
WHERE event_type LIKE 'signing_key.%'
ORDER BY created_at DESC;
```

**Background expiries during a window**

```sql
SELECT created_at, request_state, metadata
FROM v2_audit_events
WHERE event_type = 'request.expire'
  AND created_at BETWEEN ?1 AND ?2
ORDER BY created_at DESC;
```

## Streaming to a SIEM

Revaulter can stream every audit event to an external HTTP collector (such as Splunk HEC, Elastic, Vector, Fluent Bit, Cribl, Panther, or a plain webhook receiver) as it is written. The feature is enabled by setting `auditStreamUrl`.

```yaml
auditStreamUrl: "https://splunk.internal:8088/services/collector/raw"
auditStreamFormat: "ndjson"          # ndjson (default) | json
auditStreamKey: "Splunk 00000000-0000-0000-0000-000000000000"
auditStreamAuthHeader: "Authorization"
auditStreamBatchSize: 100            # 1–1000
auditStreamFlushInterval: "10s"      # 1s–5m
auditStreamEventTypes: []            # empty = all, "request.*" wildcards allowed
```

Delivery is at-least-once and **your collector must deduplicate on the event `id`.**
The `id` is a UUIDv7 and is stable across redeliveries, which makes it the right dedupe key. A collector that does not deduplicate will double-count events.

> Only events created after the feature is enabled are streamed and pre-existing rows are never sent.

### Wire formats

Both `ndjson` and `json` formats carry the same event object:

```json
{
  "schemaVersion": 1,
  "source": "revaulter",
  "instanceId": "7Yk2…",
  "id": "019974c1-1f3a-7c4e-9b2d-6f1e8a4c0d55",
  "time": "2026-09-15T20:11:03Z",
  "eventType": "request.confirm",
  "outcome": "success",
  "authMethod": "session",
  "actorUserId": "u_9f2c…",
  "targetUserId": "u_9f2c…",
  "httpRequestId": "01JC…",
  "clientIp": "203.0.113.41",
  "userAgent": "Mozilla/5.0 …",
  "attributes": { "requestState": "3f7a…" },
  "metadata": { "operation": "decrypt", "algorithm": "ES384", "keyLabel": "prod-backup" }
}
```

- Nullable columns are omitted, never emitted as `null`
- `attributes` carries the correlation columns (`requestState`, `signingKeyId`, `credentialId`) that are set only on the event types they apply to. Entries with no value are dropped, and the object is omitted entirely when none apply
- `metadata` is the event's own payload, always present, always a JSON object `{}` when empty. It is passed through as-is and never merged with `attributes`.
- `time` is RFC3339 in UTC. `created_at` is stored as Unix seconds, so it has second precision. Sort and deduplicate on `id`, not on `time`
- `schemaVersion`, `source` and `instanceId` are repeated on every event, so a single NDJSON line stays fully attributable after a collector splits the batch apart
- The internal shipping key (`seq` / `xact_id`) is never emitted

`ndjson` (the default) sends `Content-Type: application/x-ndjson` with one compact object per line, newline-terminated including the last line. It is what Splunk HEC `/raw`, Elastic, Vector, Loki and Fluent Bit all ingest natively.

`json` sends `Content-Type: application/json` with a single envelope, for endpoints that want one well-formed JSON document per request:

```json
{
  "schemaVersion": 1,
  "source": "revaulter",
  "instanceId": "7Yk2…",
  "sentAt": "2026-09-15T20:11:08Z",
  "count": 2,
  "events": []
}
```

`events` holds one event object per entry, in the same shape as an NDJSON line.

### Request headers

| header | value |
| --- | --- |
| `Content-Type` | `application/x-ndjson` or `application/json`, per format |
| `User-Agent` | `revaulter/<version>` |
| `X-Revaulter-Instance` | The instance ID |
| `X-Revaulter-Schema-Version` | `1` |
| `X-Revaulter-Batch-Count` | Number of events in the body |
| `Authorization` | `auditStreamKey`, verbatim |

`auditStreamKey` is sent with no scheme prefix added, matching how `webhookKey` behaves, so `Splunk abc123`, `Bearer …` and `ApiKey …` all work as written. Set `auditStreamAuthHeader` when your collector expects the credential in a different header.

### Private addresses

`auditStreamUrl` may point at a private or otherwise internal address, which is what most collectors are. Redirects are never followed, so a redirect to a link-local metadata endpoint cannot be used to reach one.

### Filtering

`auditStreamEventTypes` restricts the feed. Each entry is either an exact event type (`request.confirm`) or an area wildcard (`request.*`). An empty list streams everything. An entry that does not name an event type Revaulter emits fails at startup rather than silently emptying the feed.

Filtering happens after the events are read, and a filtered-out event still advances the cursor: the cursor tracks what has been *considered*, not what has been sent, so a narrow filter does not hold the retention prune back.

### Metrics

| metric | type | labels |
| --- | --- | --- |
| `revaulter_audit_stream_events_total` | counter | `outcome=sent\|filtered` |
| `revaulter_audit_stream_batches_total` | counter | `outcome=sent\|retried\|failed` |
| `revaulter_audit_stream_lag_seconds` | gauge | — |
| `revaulter_audit_stream_backlog` | gauge | — |

`revaulter_audit_stream_lag_seconds` is the one to alert on: it covers collector outages, misconfiguration and a stalled shipper in a single signal.
