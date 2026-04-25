# REST API Reference

This document describes all Revaulter REST API endpoints. For most use cases, the [Revaulter CLI](./03-revaulter-cli.md) handles the protocol automatically. Use the REST API directly only when building custom integrations.

All request and response bodies use `application/json` unless noted otherwise. Base64-encoded fields accept both standard and URL-safe base64 (with or without padding).

---

## Utility endpoints

### `GET /healthz`

Health check endpoint.

**Response:** `204 No Content`

---

### `GET /info`

Returns API version information.

**Response:**

```json
{
  "product": "revaulter",
  "apiVersion": 2
}
```

---

## Request endpoints (`/v2/request`)

These endpoints are used by the CLI (or custom clients) to submit cryptographic requests and poll for results. They do not require a session — requests are authenticated by the per-user request key in the URL path.

### `POST /v2/request/:requestKey/encrypt`

### `POST /v2/request/:requestKey/decrypt`

### `POST /v2/request/:requestKey/sign`

Submit an encrypt, decrypt, or sign request for approval. The `:requestKey` identifies the user who will approve the request.

The request payload is encrypted end-to-end by the CLI before submission. The server stores the encrypted envelope without being able to read it.

**Request body:**

```json
{
  "keyLabel": "boot-disk",
  "algorithm": "A256GCM",
  "timeout": "5m",
  "note": "boot unlock",
  "requestEncAlg": "ecdh-p256+mlkem768+a256gcm",
  "cliEphemeralPublicKey": {
    "kty": "EC",
    "crv": "P-256",
    "x": "<base64url>",
    "y": "<base64url>"
  },
  "mlkemCiphertext": "<base64url>",
  "encryptedPayloadNonce": "<base64url>",
  "encryptedPayload": "<base64url>"
}
```

| Field | Required | Description |
|-------|----------|-------------|
| `keyLabel` | Yes | Logical key label for key derivation (max 128 chars) |
| `algorithm` | Yes | Algorithm identifier: `A256GCM` for encrypt/decrypt, `ES256` for sign (max 64 chars) |
| `timeout` | No | Request timeout as seconds or Go duration (default: server `requestTimeout`, max: 24h) |
| `note` | No | Human-readable note displayed in the web UI (max 40 chars, alphanumeric and `. / _ -`) |
| `requestEncAlg` | Yes | Must be `ecdh-p256+mlkem768+a256gcm` |
| `cliEphemeralPublicKey` | Yes | Ephemeral P-256 public key as JWK (public fields only) |
| `mlkemCiphertext` | Yes | ML-KEM-768 ciphertext (base64url) |
| `encryptedPayloadNonce` | Yes | AES-GCM nonce for the encrypted payload (base64url) |
| `encryptedPayload` | Yes | The encrypted request payload (base64url) |

**Response:** `202 Accepted`

```json
{
  "state": "<uuid>",
  "pending": true
}
```

**Sign-specific behavior:**

- Callers must pre-hash the message with SHA-256 and place only the 32-byte digest in the inner payload (base64url under the `value` field). The server and the browser never see the raw message
- The inner payload's `nonce`, `tag`, and `additionalData` fields must be empty after the browser decrypts; the browser rejects the request otherwise
- The `algorithm` field must be `ES256` (ECDSA P-256 + SHA-256 per RFC 7518)
- ECDSA is non-deterministic by design: signing the same digest twice produces different but equally valid signatures.
- The approved response carries a detached signature; see `GET /v2/request/:requestKey/result/:state` below

---

### `GET /v2/request/:requestKey/pubkey`

Get the user's static public encryption keys. The CLI uses these to encrypt request payloads end-to-end.

**Response:** `200 OK`

```json
{
  "ecdhP256": {
    "kty": "EC",
    "crv": "P-256",
    "x": "<base64url>",
    "y": "<base64url>"
  },
  "mlkem768": "<base64url>"
}
```

Returns `412 Precondition Failed` if the user has not completed signup (no encryption keys configured).

---

### `GET /v2/request/:requestKey/result/:state`

Long-poll for the result of a previously submitted request. The server holds the connection until the request is completed, canceled, or the client disconnects.

**Pending response:** `202 Accepted`

```json
{
  "state": "<uuid>",
  "pending": true
}
```

**Completed response:** `200 OK`

```json
{
  "state": "<uuid>",
  "done": true,
  "responseEnvelope": {
    "transportAlg": "ecdh-p256+mlkem768+a256gcm",
    "browserEphemeralPublicKey": {
      "kty": "EC",
      "crv": "P-256",
      "x": "<base64url>",
      "y": "<base64url>"
    },
    "mlkemCiphertext": "<base64url>",
    "nonce": "<base64url>",
    "ciphertext": "<base64url>",
    "resultType": "bytes"
  }
}
```

After AES-GCM decryption of the envelope, the plaintext JSON for a `sign` operation has the following shape:

```json
{
  "state": "<uuid>",
  "operation": "sign",
  "algorithm": "ES256",
  "keyLabel": "release-signing",
  "signature": "<base64url>"
}
```

- `signature` is the detached ECDSA P-256 signature in raw `r || s` form (64 bytes for `ES256`) as produced by WebCrypto — *not* ASN.1 DER
- `algorithm` and `keyLabel` echo the request so the CLI can verify they match before accepting the signature
- Clients that need DER-encoded signatures (e.g., OpenSSL) or compact JWS output must convert on the client side; the CLI supports both via `--format jws` (see the [CLI docs](./03-revaulter-cli.md))

**Failed/canceled/expired response:** `409 Conflict`

```json
{
  "state": "<uuid>",
  "failed": true
}
```

---

## API endpoints (`/v2/api`)

These endpoints are used by the web UI to list, view, and approve or reject requests. All endpoints require an authenticated session (session cookie or bearer token).

### `GET /v2/api/list`

List pending requests for the authenticated user.

**Response:** `200 OK`

```json
[
  {
    "state": "<uuid>",
    "status": "pending",
    "operation": "encrypt",
    "userId": "<uuid>",
    "keyLabel": "boot-disk",
    "algorithm": "A256GCM",
    "requestor": "192.168.1.100",
    "date": 1713200000,
    "expiry": 1713200300,
    "note": "boot unlock"
  }
]
```

**Streaming mode:** Set the `Accept` header to `application/x-ndjson` to receive a server-sent NDJSON stream. The server sends the initial list followed by real-time updates as requests arrive, are approved, or expire.

---

### `GET /v2/api/request/:state`

Get full details of a specific request, including the encrypted request envelope.

**Response:** `200 OK`

```json
{
  "state": "<uuid>",
  "status": "pending",
  "operation": "encrypt",
  "userId": "<uuid>",
  "keyLabel": "boot-disk",
  "algorithm": "A256GCM",
  "requestor": "192.168.1.100",
  "date": 1713200000,
  "expiry": 1713200300,
  "note": "boot unlock",
  "encryptedRequest": {
    "cliEphemeralPublicKey": { "kty": "EC", "crv": "P-256", "x": "...", "y": "..." },
    "mlkemCiphertext": "<base64url>",
    "nonce": "<base64url>",
    "ciphertext": "<base64url>"
  }
}
```

Returns `403 Forbidden` if the request is not assigned to the authenticated user.

---

### `POST /v2/api/confirm`

Approve or cancel a pending request.

**Approve request body:**

```json
{
  "state": "<uuid>",
  "confirm": true,
  "responseEnvelope": {
    "transportAlg": "ecdh-p256+mlkem768+a256gcm",
    "browserEphemeralPublicKey": {
      "kty": "EC",
      "crv": "P-256",
      "x": "<base64url>",
      "y": "<base64url>"
    },
    "mlkemCiphertext": "<base64url>",
    "nonce": "<base64url>",
    "ciphertext": "<base64url>",
    "resultType": "bytes"
  }
}
```

**Approve response:** `200 OK`

```json
{
  "confirmed": true
}
```

**Cancel request body:**

```json
{
  "state": "<uuid>",
  "cancel": true
}
```

**Cancel response:** `200 OK`

```json
{
  "canceled": true
}
```

Exactly one of `confirm` or `cancel` must be `true`. When confirming, `responseEnvelope` is required and validated. Returns `409 Conflict` if the request is no longer in a pending state.

---

## Auth endpoints (`/v2/auth`)

Authentication and user management endpoints. Registration and login endpoints are public; all others require an authenticated session.

### Registration

#### `POST /v2/auth/register/begin`

Start a new account registration. Disabled when `disableSignup` is `true`.

**Request body:**

```json
{
  "displayName": "Alice"
}
```

**Response:** `200 OK`

```json
{
  "challengeId": "<uuid>",
  "challenge": "<base64url>",
  "expiresAt": 1713200300,
  "mode": "webauthn",
  "options": { "...WebAuthn creation options..." },
  "basePrfSalt": "<base64url>"
}
```

#### `POST /v2/auth/register/finish`

Complete account registration with the WebAuthn credential response.

**Request body:**

```json
{
  "challengeId": "<uuid>",
  "credential": { "...WebAuthn credential response..." }
}
```

**Response:** `200 OK`

```json
{
  "registered": true,
  "session": {
    "userId": "<uuid>",
    "displayName": "Alice",
    "requestKey": "AbCdEf0123456789GhIj",
    "wrappedKeyEpoch": 0,
    "allowedIps": [],
    "ttl": 300
  }
}
```

### Login

#### `POST /v2/auth/login/begin`

Start a WebAuthn login flow (discoverable credential).

**Request body:** None required.

**Response:** `200 OK`

```json
{
  "challengeId": "<uuid>",
  "challenge": "<base64url>",
  "expiresAt": 1713200300,
  "mode": "webauthn",
  "options": { "...WebAuthn assertion options..." },
  "basePrfSalt": "<base64url>"
}
```

#### `POST /v2/auth/login/finish`

Complete login with the WebAuthn assertion response.

**Request body:**

```json
{
  "challengeId": "<uuid>",
  "credential": { "...WebAuthn assertion response..." }
}
```

**Response:** `200 OK`

```json
{
  "authenticated": true,
  "session": {
    "userId": "<uuid>",
    "displayName": "Alice",
    "requestKey": "AbCdEf0123456789GhIj",
    "wrappedKeyEpoch": 1,
    "allowedIps": [],
    "ttl": 300
  },
  "wrappedPrimaryKey": "<base64url>",
  "credentialWrappedKeyEpoch": 1,
  "wrappedKeyStale": false
}
```

When `wrappedKeyStale` is `true`, the credential's wrapped key is at an older epoch than the user's current epoch. The client should re-wrap the primary key and upload it via `POST /v2/auth/update-wrapped-key`.

### Session management

#### `GET /v2/auth/session`

Get the current session information. Requires an authenticated session.

**Response:** `200 OK`

```json
{
  "authenticated": true,
  "userId": "<uuid>",
  "displayName": "Alice",
  "requestKey": "AbCdEf0123456789GhIj",
  "wrappedKeyEpoch": 1,
  "allowedIps": [],
  "ttl": 280
}
```

#### `POST /v2/auth/logout`

End the current session.

**Response:** `200 OK`

```json
{
  "loggedOut": true
}
```

### Signup finalization

#### `POST /v2/auth/finalize-signup`

Upload the user's wrapped primary key and static public encryption keys after registration. Called by the browser after deriving keys from the WebAuthn PRF output.

**Request body:**

```json
{
  "requestEncEcdhPubkey": {
    "kty": "EC",
    "crv": "P-256",
    "x": "<base64url>",
    "y": "<base64url>"
  },
  "requestEncMlkemPubkey": "<base64url>",
  "wrappedPrimaryKey": "<base64url>"
}
```

**Response:** `200 OK`

```json
{
  "ok": true
}
```

### User settings

#### `POST /v2/auth/allowed-ips`

Set the IP allowlist for request submission. Requests from IPs not in this list are rejected.

**Request body:**

```json
{
  "allowedIps": ["192.168.1.0/24", "10.0.0.5"]
}
```

**Response:** `200 OK`

```json
{
  "ok": true,
  "allowedIps": ["192.168.1.0/24", "10.0.0.5"]
}
```

#### `POST /v2/auth/regenerate-request-key`

Generate a new per-user request key. The old key stops working immediately.

**Response:** `200 OK`

```json
{
  "ok": true,
  "requestKey": "NewRequestKey1234567"
}
```

#### `POST /v2/auth/update-display-name`

Update the user's display name.

**Request body:**

```json
{
  "displayName": "Alice Smith"
}
```

**Response:** `200 OK`

```json
{
  "ok": true,
  "displayName": "Alice Smith"
}
```

#### `POST /v2/auth/update-wrapped-key`

Update the wrapped primary key for a specific credential. Used after a password change or when a credential's wrapped key epoch is stale.

**Request body:**

```json
{
  "credentialId": "<base64url>",
  "wrappedPrimaryKey": "<base64url>"
}
```

**Response:** `200 OK`

```json
{
  "ok": true
}
```

### Credential management

#### `GET /v2/auth/credentials`

List all WebAuthn credentials for the authenticated user.

**Response:** `200 OK`

```json
[
  {
    "id": "<base64url>",
    "displayName": "YubiKey 5",
    "wrappedKeyEpoch": 1,
    "wrappedKeyStale": false,
    "createdAt": 1713100000,
    "lastUsedAt": 1713200000
  }
]
```

#### `POST /v2/auth/credentials/add/begin`

Start adding a new WebAuthn credential to the account.

**Request body:**

```json
{
  "credentialName": "Backup YubiKey"
}
```

**Response:** `200 OK`

```json
{
  "challengeId": "<uuid>",
  "challenge": "<base64url>",
  "expiresAt": 1713200300,
  "options": { "...WebAuthn creation options..." },
  "basePrfSalt": "<base64url>"
}
```

#### `POST /v2/auth/credentials/add/finish`

Complete adding a new credential.

**Request body:**

```json
{
  "challengeId": "<uuid>",
  "credential": { "...WebAuthn credential response..." },
  "credentialName": "Backup YubiKey",
  "wrappedPrimaryKey": "<base64url>"
}
```

**Response:** `200 OK`

```json
{
  "ok": true
}
```

#### `POST /v2/auth/credentials/rename`

Rename a credential.

**Request body:**

```json
{
  "id": "<base64url>",
  "displayName": "Main YubiKey"
}
```

**Response:** `200 OK`

```json
{
  "ok": true
}
```

#### `POST /v2/auth/credentials/delete`

Delete a credential. The user must have at least one remaining credential.

**Request body:**

```json
{
  "id": "<base64url>"
}
```

**Response:** `200 OK`

```json
{
  "ok": true
}
```

---

## Signing key publication

Signing public keys can be fetched by third-party verifiers using a stable key ID. The ID is the RFC 7638 JWK thumbprint of the EC public key, base64url-encoded: `base64url(SHA-256(canonical-JWK))` where the canonical JWK is the lex-ordered JSON `{"crv":"P-256","kty":"EC","x":"…","y":"…"}`.

A stored row carries both the JWK and the PEM (PKIX) forms along with a `published` flag. Only published rows are served from the unauthenticated fetch endpoints below; unpublished rows still exist (they may have been auto-stored as part of a sign operation) but are hidden from public lookups.

A row is uniquely identified by `(user, algorithm, keyLabel)`: creating a new key under a label that already has a row is rejected with `409 Conflict`; the caller must first `DELETE` the existing row to free the slot.

Revocation is expressed either by setting `published=false` (reversible) or by `DELETE`ing the row (permanent); consumers should treat a 404 on a known key ID as revocation.

### Authenticated endpoints

#### `GET /v2/api/signing-keys`

List the authenticated user's signing keys. JWK and PEM are omitted from the list to keep it lean; fetch them by ID via the endpoints below.

**Response:** `200 OK`

```json
[
  {
    "id": "<key-id>",
    "algorithm": "ES256",
    "keyLabel": "release-signing",
    "published": true,
    "createdAt": "2026-04-17T12:00:00Z",
    "updatedAt": "2026-04-17T12:00:00Z"
  }
]
```

#### `GET /v2/api/signing-keys/:id`

Return a single signing key owned by the current user, including the stored JWK and PEM.

**Response:** `200 OK`

```json
{
  "id": "<key-id>",
  "algorithm": "ES256",
  "keyLabel": "release-signing",
  "published": false,
  "createdAt": "2026-04-17T12:00:00Z",
  "updatedAt": "2026-04-17T12:00:00Z",
  "jwk": { "kty": "EC", "crv": "P-256", "x": "…", "y": "…" },
  "pem": "-----BEGIN PUBLIC KEY-----\n…\n-----END PUBLIC KEY-----\n"
}
```

Returns `404 Not Found` when the ID doesn't match a row belonging to the authenticated user, so a guessed ID can't probe another user's keys.

#### `POST /v2/api/signing-keys`

Create a new signing key for the current user. The `published` flag in the request body controls whether the key is served by the public fetch endpoints below. The server validates that:

- `algorithm` is supported (currently only `ES256`)
- `keyLabel` is non-empty and at most 128 chars
- `jwk` is a valid EC P-256 public JWK (wrong `kty`, wrong `crv`, missing `x`/`y`, presence of `d`, or off-curve points are rejected)
- `pem` parses as a valid PKIX `SubjectPublicKeyInfo`
- The JWK and PEM describe the same public point (mismatch → 400)

**Request body:**

```json
{
  "algorithm": "ES256",
  "keyLabel": "release-signing",
  "jwk": { "kty": "EC", "crv": "P-256", "x": "…", "y": "…" },
  "pem": "-----BEGIN PUBLIC KEY-----\n…\n-----END PUBLIC KEY-----\n",
  "published": true
}
```

**Response:** `201 Created`

```json
{
  "id": "<key-id>",
  "algorithm": "ES256",
  "keyLabel": "release-signing",
  "published": true,
  "createdAt": "2026-04-17T12:00:00Z",
  "updatedAt": "2026-04-17T12:00:00Z"
}
```

The endpoint is insert-only: if a row already exists for the same `(user, algorithm, keyLabel)` (either previously created or auto-stored during a sign operation) the request is rejected with `409 Conflict` and no existing data is overwritten. To store different key material under the same label, `DELETE` the existing row first. To merely flip the `published` flag on an existing row, use `POST /v2/api/signing-keys/:id`.

#### `POST /v2/api/signing-keys/:id`

Updates an existing signing key owned by the current user, flipping the `published` flag. Use this to unpublish (`published: false`) a previously published key, or to publish an auto-stored key that was created during a sign operation.

**Request body:**

```json
{ "published": false }
```

**Response:** `200 OK`

```json
{
  "id": "<key-id>",
  "algorithm": "ES256",
  "keyLabel": "release-signing",
  "published": false,
  "createdAt": "2026-04-17T12:00:00Z",
  "updatedAt": "2026-04-17T12:00:00Z"
}
```

Returns `404 Not Found` when the ID doesn't match a row belonging to the authenticated user, so a guessed ID can't probe another user's keys.

#### `DELETE /v2/api/signing-keys/:id`

Hard-delete a signing key row owned by the current user. The row is removed from the database; the ID becomes unresolvable and the `(algorithm, keyLabel)` slot is freed for a subsequent `POST /v2/api/signing-keys`.

**Response:** `200 OK`

```json
{ "deleted": true }
```

Returns `404 Not Found` when the ID doesn't match a row belonging to the authenticated user, so a guessed ID can't probe another user's keys. A second `DELETE` on the same ID also returns `404`.

### Public (unauthenticated) endpoints

These endpoints take only the opaque key ID. There is no listing or enumeration endpoint, clients must know the key ID out of band.

Both endpoints are rate-limited and return `Cache-Control: public, max-age=600`. Unknown IDs return `404 Not Found`.

#### `GET /v2/signing-keys/:id.jwk`

**Alias: `GET /v2/signing-keys/:id.json`**

Returns the stored JWK verbatim inside a metadata envelope.

**Response:** `200 OK`

```json
{
  "id": "<key-id>",
  "algorithm": "ES256",
  "keyLabel": "release-signing",
  "createdAt": "2026-04-17T12:00:00Z",
  "jwk": { "kty": "EC", "crv": "P-256", "x": "…", "y": "…" }
}
```

#### `GET /v2/signing-keys/:id.pem`

**Alias: `GET /v2/signing-keys/:id.pub`**

Returns the stored PEM with `Content-Type: application/x-pem-file`. This is the form consumed by OpenSSL and many standard verifier libraries.

### Verification

An external verifier receives a message, a detached `ES256` signature (raw `r || s`, 64 bytes), and the signer's published key ID or PEM. Verification:

1. Compute `digest = SHA-256(message)`
2. Convert the raw `r || s` signature to the format your library expects (ASN.1 DER for OpenSSL; raw is already compatible with WebCrypto's `verify` API)
3. Import the PEM (or JWK) public key
4. Call the standard `ECDSA-P256-SHA256 verify(digest, signature, publicKey)`

> Note: ECDSA is non-deterministic by design. Signing the same digest twice yields two different but equally valid signatures; do not rely on signature equality as a fingerprint.
