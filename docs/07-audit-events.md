# Audit events

Revaulter records security-relevant actions to a durable, append-only `v2_audit_events` table. The table sits alongside the operational application log (emitted to stdout): ordinary debug messages still go to the log stream, while audit rows are the long-lived history of *who did what*.

There is currently no UI or REST API for reading audit events and operators must query the table directly with SQL. A read endpoint may ship in a future release.

## What gets recorded

Each row captures one logical action: a confirmed request, a rotated request key, a deleted passkey, etc. Failed and denied attempts are recorded too where the signal is interesting (e.g. a failed login).

Events are written through one of two paths:

- **In-transaction**: for security-critical state changes the audit row commits in the same transaction as the mutation. If the audit insert fails, the user action also rolls back. This guarantees that a "request confirmed" row exists if and only if the request was actually marked confirmed.
- **Best-effort**: for purely observational events (logout cookie clear, background expiry, login *failures*) the audit row is written outside the mutation. A failed audit insert is logged as a warning and does not affect the user-facing response.

## Schema

| column | type | nullable | notes |
|---|---|---|---|
| `id` | TEXT (SQLite) / UUID (Postgres) | no | Time-sortable primary key (UUIDv7 format) |
| `created_at` | INTEGER (Unix seconds) | no | When the audit row was written |
| `event_type` | TEXT | no | `<area>.<verb>` — see list below |
| `outcome` | TEXT | no | `success` \| `failure` \| `denied` |
| `auth_method` | TEXT | no | `session` \| `request_key` \| `system` \| `none` (set on rows from handlers that run before any authentication is established, e.g. `auth.login_finish` failures) |
| `actor_user_id` | TEXT | yes | The user who performed the action; NULL for unauthenticated failures and pure system events |
| `target_user_id` | TEXT | yes | The user the action affects (often equal to `actor_user_id`) |
| `signing_key_id` | TEXT | yes | Set for `signing_key.*` events |
| `credential_id` | TEXT | yes | Set for `auth.credential_*` events and `auth.login_finish` |
| `request_state` | TEXT | yes | The v2 protocol request `state` for `request.*` events |
| `http_request_id` | TEXT | yes | Correlates the audit row with the HTTP access log |
| `client_ip` | TEXT | yes | NULL for system events |
| `user_agent` | TEXT | yes | Capped at 512 chars |
| `metadata` | TEXT (SQLite) / JSONB (Postgres) | no | Free-form JSON; capped at 4 KiB; default `{}` |

## Event types

Naming convention is `<area>.<verb>` with both halves in `snake_case`. The full list is fixed at the application layer; inserts with any other value are rejected.

### Auth

| event_type | When it fires |
|---|---|
| `auth.register_finish` | Account creation completes (success in tx; failure best-effort) |
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
|---|---|
| `request.create` | CLI/API submits a new encrypt/decrypt/sign request. Metadata: `{operation, algorithm, key_label}` |
| `request.confirm` | User approves a pending request. Metadata: `{operation, algorithm}` |
| `request.cancel` | User cancels a pending request. Metadata: `{operation, algorithm}` |
| `request.expire` | TTL elapses and the background goroutine marks the request expired. `auth_method=system` |

### Signing keys

| event_type | When it fires |
|---|---|
| `signing_key.create` | User explicitly creates/uploads a signing key. Metadata: `{algorithm, key_label, published, has_proof}` |
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

## Sample queries

All queries below assume SQLite syntax; Postgres equivalents differ only in time arithmetic.

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
