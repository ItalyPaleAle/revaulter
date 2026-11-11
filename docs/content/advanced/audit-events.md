---
title: "Audit events"
weight: 42
---

Revaulter records security-relevant actions to a durable, append-only `v2_audit_events` table. This is separate from the application log (written to stdout): ordinary log messages still go to the log stream, while audit rows are the long-term history of *who did what*.

Each user can see their own events in the web UI, under **Settings → Audit log**. There's no admin UI or REST API for reading the events of all users yet, so operators must query the table directly with SQL, or [stream the events to a SIEM](#streaming-to-a-siem).

## What gets recorded

Each row records one action, such as a confirmed request, a regenerated request key, or a deleted passkey. Some failed and denied attempts are recorded too, such as failed logins.

Events are written through one of two paths:

- **In the same transaction**: for security-critical changes, the audit row is written in the same transaction as the change. If writing the audit row fails, the change is rolled back too. This guarantees that a "request confirmed" row exists if and only if the request was actually confirmed.
- **Best-effort**: for events that are only observational in nature (logouts, expired requests, login *failures*), the audit row is written separately. If writing it fails, Revaulter logs a warning, and the user's action isn't affected.

## Schema

| column | type | nullable | notes |
| --- | --- | --- | --- |
| `id` | TEXT (SQLite) / UUID (Postgres) | no | Time-sortable primary key (UUIDv7 format) |
| `created_at` | INTEGER (Unix seconds) | no | When the audit row was written |
| `event_type` | TEXT | no | `<area>.<verb>`: see the list below |
| `outcome` | TEXT | no | `success` \| `failure` \| `denied` |
| `auth_method` | TEXT | no | `session` \| `request_key` \| `request_oidc` (a JWT from a trusted OIDC issuer) \| `system` \| `none` (set on rows from handlers that run before any authentication is established, e.g. `auth.login_finish` failures and `auth.pairing_hello`) |
| `actor_user_id` | TEXT | yes | The user who performed the action, NULL for unauthenticated failures and pure system events |
| `target_user_id` | TEXT | yes | The user the action affects (often equal to `actor_user_id`) |
| `signing_key_id` | TEXT | yes | Set for `signing_key.*` events |
| `credential_id` | TEXT | yes | Set for `auth.credential_*`, `auth.wrapped_key_update`, `auth.login_finish`, `auth.device_login_finish`, `auth.pairing_hello` and `auth.pairing_complete` events |
| `request_state` | TEXT | yes | The v2 protocol request `state` for `request.*` events |
| `http_request_id` | TEXT | yes | Correlates the audit row with the HTTP access log |
| `client_ip` | TEXT | yes | NULL for system events |
| `user_agent` | TEXT | yes | Capped at 512 chars |
| `metadata` | TEXT (SQLite) / JSONB (Postgres) | no | Free-form JSON, capped at 4 KiB, default `{}` |
| `seq` | INTEGER (SQLite only) | no | Internal: tracks progress when [streaming to a SIEM](#streaming-to-a-siem). Assigned by the database and not included in backups |
| `xact_id` | XID8 (Postgres only) | no | Internal: tracks progress when [streaming to a SIEM](#streaming-to-a-siem). Assigned by the database and not included in backups |

## Event types

Event types are named `<area>.<verb>`, with both parts in `snake_case`. Revaulter records only the event types listed here, and rejects any other value.

### Auth

| event_type | When it fires |
| --- | --- |
| `auth.register_finish` | Account creation completes |
| `auth.finalize_signup` | Setup of the first passkey completes, and the user's anchor public keys, wrapped keys, and request encryption keys are stored |
| `auth.login_finish` | A login attempt finishes: `outcome=success` for accepted credentials, `outcome=failure` for rejected ones |
| `auth.logout` | User logs out. The server doesn't revoke the session token, so this records that the session cookie was cleared |
| `auth.request_key_regenerate` | User regenerates the CLI request key |
| `auth.request_auth_methods_change` | User enables or disables the static request key or OIDC tokens. Metadata: `{requestKeyEnabled, requestOidcEnabled}` |
| `auth.request_oidc_issuer_add` | User adds a trusted OIDC issuer. Metadata: `{issuerId, issuer, audience, subject, discovery}`, with long values truncated |
| `auth.request_oidc_issuer_delete` | User removes a trusted OIDC issuer. Metadata: same as `auth.request_oidc_issuer_add` |
| `auth.allowed_ips_change` | User updates the list of allowed IPs. Metadata: `{old_count, new_count}` |
| `auth.display_name_change` | User updates their display name |
| `auth.wrapped_key_update` | A credential's wrapped primary key and anchor key change, with one row per credential. Metadata: `{advanceEpoch}` (true when the change is a password change) |
| `auth.credential_add_finish` | New passkey registered |
| `auth.credential_rename` | Passkey or device renamed |
| `auth.credential_delete` | Passkey or device deleted |
| `auth.device_login_finish` | A native app's login finishes: `outcome=success` when both device signatures verify, `outcome=failure` otherwise |
| `auth.pairing_create` | User starts pairing a new device. Metadata: `{pairingSessionId}` |
| `auth.pairing_hello` | The new device answers the pairing. The device isn't signed in, so the row has `auth_method=none` and is attributed to the user who started the pairing, failures included. Metadata: `{pairingSessionId}` |
| `auth.pairing_complete` | User completes the pairing and the device is added. Metadata: `{pairingSessionId}` |
| `auth.pairing_cancel` | User cancels the pairing. Metadata: `{pairingSessionId}` |

### Requests

| event_type | When it fires |
| --- | --- |
| `request.create` | The CLI or API submits a new encrypt, decrypt, or sign request. Metadata: `{operation, algorithm, keyLabel, note?, jwtIssuer?, jwtSubject?, jwtId?}` |
| `request.confirm` | User approves a pending request. Metadata: `{operation, algorithm, keyLabel, note?}` |
| `request.cancel` | User cancels a pending request. Metadata: `{operation, algorithm, keyLabel, note?}` |
| `request.expire` | A pending request expires before it's approved or canceled. `auth_method=system`. Metadata: `{operation, algorithm, keyLabel, note?}` |

The `note` field is included only when the request had a note. The `jwt*` fields are included only on `request.create`, when the request was authenticated with an OIDC token: they hold the token's verified `iss`, `sub`, and `jti` claims, so the audit log shows which workload sent the request.

### Signing keys

| event_type | When it fires |
| --- | --- |
| `signing_key.create` | User creates a signing key. Metadata: `{algorithm, keyLabel, published, hasProof}` |
| `signing_key.publish` | User publishes an existing signing key |
| `signing_key.unpublish` | User unpublishes a signing key |
| `signing_key.delete` | User deletes a signing key |
| `signing_key.auto_store` | Server stored the public key of a signing key after a successful sign request, with no explicit user action |

## What is *never* recorded

Audit events never contain sensitive material. Specifically, audit rows don't store:

- Request keys (`rvk_…`) or session tokens
- Wrapped primary keys, wrapped anchor keys, or any encrypted blob
- Raw WebAuthn credential JSON, attestation payloads, or signature bytes
- Encrypted request/response envelopes
- Webhook URLs or shared secrets
- Allowed-IP lists in full (only their count)
- ML-DSA / ES384 signatures of any kind

## Retention

Rows older than **30 days** are deleted automatically by a background task that runs when Revaulter starts, and then every 24 hours.

When [streaming to a SIEM](#streaming-to-a-siem) is enabled, rows that haven't been sent yet aren't deleted, so a collector outage doesn't lose events. Rows are kept for at most **90 days**, after which they're deleted even if they weren't delivered. The `revaulter_audit_stream_lag_seconds` metric shows a backlog long before that.

## Sample queries

These queries use SQLite syntax. For Postgres, only the date calculations differ.

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

**All signing key changes**

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

Revaulter can send every audit event to an external HTTP collector as it's written, such as Splunk HEC, Elastic, Vector, Fluent Bit, Cribl, Panther, or a plain webhook receiver. To enable this, set `auditStreamUrl`.

```yaml
auditStreamUrl: "https://splunk.internal:8088/services/collector/raw"
auditStreamFormat: "ndjson"          # ndjson (default) | json
auditStreamKey: "Splunk 00000000-0000-0000-0000-000000000000"
auditStreamAuthHeader: "Authorization"
auditStreamBatchSize: 100            # 1–1000
auditStreamFlushInterval: "10s"      # 1s–5m
auditStreamEventTypes: []            # empty = all, "request.*" wildcards allowed
```

Events can be delivered more than once, so **your collector must deduplicate on the event `id`.**
The `id` is a UUIDv7 that stays the same when an event is sent again. A collector that doesn't deduplicate will count some events twice.

> Only events created after you enable streaming are sent. Earlier rows are never sent.

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
  "metadata": { "operation": "decrypt", "algorithm": "A256GCM", "keyLabel": "prod-backup" }
}
```

- Nullable columns are omitted, never emitted as `null`
- `attributes` holds the correlation columns (`requestState`, `signingKeyId`, `credentialId`), which are set only on the event types they apply to. Entries with no value are dropped, and the object is omitted when none apply
- `metadata` is the event's own data. It's always present (as an empty object `{}` when there's nothing to include) and it's never merged with `attributes`
- `time` is RFC 3339 in UTC, with second precision. Sort and deduplicate on `id`, not on `time`
- `schemaVersion`, `source`, and `instanceId` are repeated on every event, so each NDJSON line still identifies its source after a collector splits the batch
- The internal shipping key (`seq` / `xact_id`) is never emitted

`ndjson` (the default) sends `Content-Type: application/x-ndjson`, with one compact object per line, and a newline after each line, including the last one. Splunk HEC `/raw`, Elastic, Vector, Loki, and Fluent Bit all accept it natively.

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

`auditStreamKey` is sent exactly as written, like `webhookKey`, so include the scheme yourself: `Splunk abc123`, `Bearer …`, and `ApiKey …` all work. Set `auditStreamAuthHeader` when your collector expects the credential in a different header.

### Private addresses

`auditStreamUrl` can point at a private or internal address, as most collectors are. Redirects are never followed, so a redirect can't be used to reach other internal addresses, such as a cloud metadata endpoint.

### Filtering

`auditStreamEventTypes` limits which events are sent. Each entry is either an exact event type (`request.confirm`) or an area wildcard (`request.*`). An empty list sends everything. If an entry doesn't match any event type Revaulter records, Revaulter fails to start, instead of silently sending nothing.

Events that the filter excludes count as processed, so a narrow filter doesn't stop old rows from being deleted.

### Metrics

| metric | type | labels |
| --- | --- | --- |
| `revaulter_audit_stream_events_total` | counter | `outcome=sent\|filtered` |
| `revaulter_audit_stream_batches_total` | counter | `outcome=sent\|retried\|failed` |
| `revaulter_audit_stream_lag_seconds` | gauge | — |
| `revaulter_audit_stream_backlog` | gauge | — |

Alert on `revaulter_audit_stream_lag_seconds`: it catches collector outages, misconfiguration, and a stalled stream in a single metric.
