---
title: "REST API Reference"
weight: 41
---

This page describes all Revaulter REST API endpoints.

For most use cases, the [Revaulter CLI](/cli/revaulter-cli/) or the [Go library](/advanced/go-library/) handle the protocol for you. Use the REST API directly only when building custom integrations.

All request and response bodies use `application/json` unless noted otherwise. Base64-encoded fields accept both standard and URL-safe base64 (with or without padding).

---

## Utility endpoints

### `GET /healthz`

Health check endpoint.

**Response:** `204 No Content`

---

### `GET /info`

Returns information about the server.

**Response:** `200 OK`

```json
{
  "product": "revaulter",
  "apiVersion": 2,
  "version": "2.9.0",
  "commit": "abc1234",
  "buildDate": "2026-11-01T12:00:00Z",
  "hasIntegrity": true
}
```

`hasIntegrity` is `true` when the build includes a signed manifest of the web client. See [Verifying the web client's integrity](/advanced/web-client-integrity/).

---

### `GET /info/integrity`

Returns the signed manifest of the web client's files and its cosign bundle, which `revaulter-cli check` verifies.

**Response:** `200 OK`

```json
{
  "manifest": "<manifest text>",
  "bundle": { "...cosign bundle..." }
}
```

Returns `404 Not Found` for builds without a signed manifest.

---

## Request endpoints (`/v2/request`)

These endpoints are used by the CLI (or custom clients) to submit cryptographic requests and poll for results. They do not require a session. Instead, requests carry a credential in the `Authorization` header. Each user chooses in the web UI which kinds of credentials are accepted, and can enable both at once:

- **Request key** (enabled by default): the per-user static request key, sent as `Authorization: RequestKey <requestKey>`. Note: request keys carry an `rvk_` prefix.
- **OIDC token**: a short-lived JWT signed by one of the user's trusted OIDC issuers (e.g. GitHub Actions OIDC token), sent as `Authorization: Bearer <jwt>`. These requests must also include the `X-Revaulter-User: <userId>` header, because the token on its own doesn't identify a Revaulter user. See [Authenticating with OIDC tokens](/docs/oidc-authentication/).

To retrieve the result of a request, clients can also use the request's **result token**, sent as `Authorization: ResultToken <resultToken>`. See `GET /v2/request/result/:state` below.

> For backwards compatibility, the server also accepts a request key with the `Bearer` scheme (`Authorization: Bearer <requestKey>`), or without any scheme (`Authorization: <requestKey>`). New clients should use the `RequestKey` scheme. JWTs are only recognized with the `Bearer` scheme.

The `X-Revaulter-User` header is optional with request keys and result tokens.

### `POST /v2/request/encrypt`

### `POST /v2/request/decrypt`

### `POST /v2/request/sign`

Submit an encrypt, decrypt, or sign request for approval. The credential in the `Authorization` header (and, for OIDC tokens, the `X-Revaulter-User` header) identifies the user who will approve the request.

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
| --- | --- | --- |
| `keyLabel` | Yes | Logical key label for key derivation: 1-24 characters, letters, digits, and `_ . + -` (case-insensitive) |
| `algorithm` | Yes | Algorithm identifier (max 64 chars). Encrypt and decrypt accept `A256GCM` (alias `aes-256-gcm`) and `C20P` (alias `chacha20-poly1305`). Sign accepts `ES256`, `Ed25519`, and `Ed25519ph` |
| `timeout` | No | Request timeout as seconds or Go duration (default: server `requestTimeout`, max: 24h) |
| `note` | No | Note displayed in the web UI: up to 80 letters, digits, spaces, and `. / _ -` |
| `requestEncAlg` | Yes | Must be `ecdh-p256+mlkem768+a256gcm` |
| `cliEphemeralPublicKey` | Yes | Ephemeral P-256 public key as JWK (public fields only) |
| `mlkemCiphertext` | Yes | ML-KEM-768 ciphertext (base64url) |
| `encryptedPayloadNonce` | Yes | AES-GCM nonce for the encrypted payload (base64url) |
| `encryptedPayload` | Yes | The encrypted request payload (base64url) |

**Response:** `202 Accepted`

```json
{
  "state": "<uuid>",
  "pending": true,
  "resultToken": "rvr_<random>"
}
```

`resultToken` authenticates `GET /v2/request/result/:state` for this request only. Unlike the request credential, it stays valid until the request is completed or expires, so clients can keep polling after a short-lived OIDC token has expired. Servers that predate result tokens omit this field.

### Inner payload

The `encryptedPayload` field carries a JSON object encrypted end-to-end to the user's public keys, so the server can't read it. The browser decrypts and validates it after the user approves.

The shape varies per operation. All `value`/`nonce`/`tag`/`additionalData` fields are base64url-encoded.

```json
{
  "value": "<base64url>",
  "nonce": "<base64url>",
  "tag": "<base64url>",
  "additionalData": "<base64url>",
  "clientTransportEcdhKey": { "kty": "EC", "crv": "P-256", "x": "<base64url>", "y": "<base64url>" },
  "clientTransportMlkemKey": "<base64url>"
}
```

`clientTransportEcdhKey` and `clientTransportMlkemKey` are required on every operation: they are the per-request ephemeral public keys the browser uses to encrypt the response back to the caller.

**Encrypt-specific behavior:**

- `algorithm` must be one of the AEAD primitives accepted by the server: `A256GCM` or `C20P` (or an alias)
- `value` carries the plaintext bytes to encrypt (base64url); `additionalData` is optional
- `nonce` and `tag` must be empty
- The approved response envelope carries the ciphertext, nonce, and tag. See `GET /v2/request/result/:state` below

**Decrypt-specific behavior:**

- `algorithm` must be one of the AEAD primitives accepted by the server: `A256GCM` or `C20P` (or an alias). It must match what was used at encryption time
- `value`, `nonce`, and `tag` carry the ciphertext, nonce, and authentication tag respectively (base64url); `additionalData` must match what was used at encryption time
- The approved response envelope carries the recovered plaintext

**Sign-specific behavior:**

- `algorithm` must be `ES256`, `Ed25519`, or `Ed25519ph`
- `value` carries the bytes to sign (base64url), which depend on the algorithm:
  - `ES256`: the 32-byte SHA-256 digest of the message
  - `Ed25519`: the message itself, up to 100 KB
  - `Ed25519ph`: the 64-byte SHA-512 digest of the message
- `nonce`, `tag`, and `additionalData` must be empty
- ECDSA signatures are randomized: signing the same digest twice produces different signatures, and both are valid
- The approved response carries a detached signature. See `GET /v2/request/result/:state` below

---

### `GET /v2/request/pubkey`

Get the user's public encryption keys, along with the hybrid anchor public keys and the signatures over them. The CLI uses the encryption keys to encrypt request payloads end-to-end, pins the anchor keys (TOFU), and verifies both signatures, to detect a server that substitutes its own keys.

**Response:** `200 OK`

```json
{
  "userId": "<uuid>",
  "ecdhP256": {
    "kty": "EC",
    "crv": "P-256",
    "x": "<base64url>",
    "y": "<base64url>"
  },
  "mlkem768": "<base64url>",
  "anchorEs384PublicKey": "<canonical JWK body>",
  "anchorMldsa87PublicKey": "<base64url>",
  "wrappedKeyEpoch": 1,
  "pubkeyBundleVersion": 2,
  "pubkeyBundleSignatureEs384": "<base64url>",
  "pubkeyBundleSignatureMldsa87": "<base64url>"
}
```

`pubkeyBundleVersion` tells the verifier which canonical payload the signatures cover: `1` (legacy, the payload includes `wrappedKeyEpoch`) or `2` (the payload includes an explicit `v` line instead). The bundle is signed once at signup and never signed again.

`wrappedKeyEpoch` is kept for older CLIs that verify version-1 bundles: it's the epoch included in version-1 signatures, which is always `1`. It doesn't track the user's current wrapped key epoch, which increases on password changes.

Returns `412 Precondition Failed` if the user has not completed signup (no encryption keys configured).

---

### `GET /v2/request/signing-pubkey`

Get the public key of one of the user's signing keys, with its publication proof when the key is published.

**Query parameters:**

| Parameter | Required | Description |
| --- | --- | --- |
| `label` | Yes | Key label |
| `algorithm` | No | `ES256` (default), `Ed25519`, or `Ed25519ph` |

**Response:** `200 OK`

```json
{
  "id": "<key-id>",
  "algorithm": "ES256",
  "keyLabel": "release-signing",
  "jwk": { "kty": "EC", "crv": "P-256", "x": "…", "y": "…" },
  "publicationPayload": "<canonical body>",
  "publicationSignatureEs384": "<base64url>",
  "publicationSignatureMldsa87": "<base64url>"
}
```

The `publication*` fields are omitted when the key has no publication proof. Clients should verify the proof against the user's pinned anchor before trusting the key.

Returns `404 Not Found` if the user has no signing key with that label and algorithm.

---

### `GET /v2/request/result/:state`

Long-poll for the result of a previously submitted request. The server holds the connection until the request is completed, canceled, or expires, or until the client disconnects. If another client starts polling the same request, the server answers the earlier one with the pending response.

A final result can be retrieved only once: after that, the server returns `404 Not Found`.

This endpoint accepts the `resultToken` returned when the request was created, in the `Authorization: ResultToken <resultToken>` header. It also accepts the same credentials as the other request endpoints.

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
  "signature": "<base64url>",
  "signingKeyId": "<key-id>"
}
```

- `signature` is the 64-byte detached signature. For `ES256`, it's in raw `r || s` form, *not* ASN.1 DER
- `algorithm` and `keyLabel` echo the request, so the client can check that they match before accepting the signature
- `signingKeyId` is the ID of the key that produced the signature (its RFC 7638 JWK thumbprint)
- Clients that need DER-encoded signatures (e.g., for OpenSSL) must convert them themselves. The CLI can produce a compact JWS with `--format jws` (see the [CLI docs](/cli/revaulter-cli/))

**Failed/canceled/expired response:** `409 Conflict`

```json
{
  "state": "<uuid>",
  "failed": true
}
```

---

## API endpoints (`/v2/api`)

These endpoints are used by the web UI to list, view, and approve or cancel requests, and to manage signing keys. All endpoints require an authenticated session (session cookie or bearer token).

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

**Streaming mode:** Set the `Accept` header to `application/x-ndjson` to receive an NDJSON stream. The server sends the initial list, followed by updates as requests arrive, are approved, or expire.

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

Authentication and user management endpoints. Registration and login endpoints are public, and so are the device login endpoints and the pairing endpoints that the new device calls; all others require an authenticated session.

The web app keeps its session in a cookie. A native app gets its session as a token from the device login, and sends it as `Authorization: Bearer <sessionToken>`.

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
    "requestKeyEnabled": true,
    "requestOidcEnabled": false,
    "requestOidcIssuers": [],
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
    "requestKeyEnabled": true,
    "requestOidcEnabled": false,
    "requestOidcIssuers": [],
    "anchorFingerprint": "<fingerprint>",
    "wrappedKeyEpoch": 1,
    "allowedIps": [],
    "ttl": 300
  },
  "wrappedPrimaryKey": "<base64url>",
  "wrappedAnchorKey": "<base64url>",
  "credentialWrappedKeyEpoch": 1,
  "wrappedKeyStale": false
}
```

When `wrappedKeyStale` is `true`, the password was changed while signed in with a different passkey, so this passkey's wrapped key still uses the old password. See [Cryptography architecture](/docs/crypto-architecture/).

### Device login

Native apps sign in with a device credential, added by [pairing](#device-pairing). The device signs a challenge with two keys, one classical and one post-quantum, and both signatures must verify. See [Cryptography architecture](/docs/crypto-architecture/#device-credentials).

#### `POST /v2/auth/device/login/begin`

Get a challenge for a device. The response is the same whether or not the user and device exist.

**Request body:**

```json
{
  "userId": "<uuid>",
  "credentialId": "<base64url, 16 bytes>"
}
```

**Response:** `200 OK`

```json
{
  "challengeId": "<uuid>",
  "challenge": "<base64url, 32 bytes>",
  "expiresAt": 1713200060
}
```

The challenge expires after 60 seconds.

#### `POST /v2/auth/device/login/finish`

Complete a device login.

**Request body:**

```json
{
  "challengeId": "<uuid>",
  "credentialId": "<base64url>",
  "signatureP256": "<base64url, 64 bytes>",
  "signatureMldsa65": "<base64url, 3309 bytes>"
}
```

**Response:** `200 OK`

```json
{
  "authenticated": true,
  "sessionToken": "<token>",
  "sessionExpiresAt": 1713200300,
  "userId": "<uuid>",
  "wrappedPrimaryKey": "<base64url>",
  "wrappedAnchorKey": "<base64url>",
  "credentialWrappedKeyEpoch": 1,
  "wrappedKeyStale": false
}
```

The rest of the session comes from `GET /v2/auth/session`. Returns `401 Unauthorized` if a signature doesn't verify, `409 Conflict` if the challenge was already used or has expired, and `429 Too Many Requests` under the same per-user limit as passkey logins.

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
  "requestKeyEnabled": true,
  "requestOidcEnabled": true,
  "requestOidcIssuers": [
    {
      "id": "<uuid>",
      "displayName": "Release workflow",
      "issuer": "https://token.actions.githubusercontent.com",
      "audience": "https://revaulter.example.com",
      "subject": "repo:my-org/my-app:ref:refs/tags/*",
      "createdAt": 1713200000
    }
  ],
  "anchorFingerprint": "<fingerprint>",
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

Upload the user's wrapped keys, public encryption keys, and anchor public keys after registration. The browser calls this after creating the keys and wrapping them with the WebAuthn PRF output.

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
  "wrappedPrimaryKey": "<base64url>",
  "anchorEs384PublicKey": "<canonical JWK body>",
  "anchorMldsa87PublicKey": "<base64url>",
  "pubkeyBundleSignatureEs384": "<base64url>",
  "pubkeyBundleSignatureMldsa87": "<base64url>",
  "pubkeyBundleVersion": 2,
  "wrappedAnchorKey": "<base64url>",
  "attestationPayload": "<canonical body>",
  "attestationSignatureEs384": "<base64url>",
  "attestationSignatureMldsa87": "<base64url>"
}
```

`pubkeyBundleVersion` selects the canonical payload the signatures cover: `1` (legacy, includes `wrappedKeyEpoch`, which is always `1` at signup) or `2` (includes an explicit `v` line instead). Current clients always sign version `2`. When omitted, `1` is assumed for compatibility with older clients.

**Response:** `200 OK`

```json
{
  "ok": true
}
```

### User settings

#### `POST /v2/auth/allowed-ips`

Set the list of IP addresses and ranges allowed to submit requests for this user. Requests from other addresses are rejected. An empty list allows all addresses.

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

#### `POST /v2/auth/request-auth-methods`

Enable or disable the credentials the CLI can use to authenticate requests for this user: the static request key and JWTs from the user's trusted OIDC issuers.

**Request body:**

```json
{
  "requestKeyEnabled": false,
  "requestOidcEnabled": true
}
```

**Response:** `200 OK`

```json
{
  "ok": true,
  "requestKeyEnabled": false,
  "requestOidcEnabled": true
}
```

#### `POST /v2/auth/request-oidc-issuers/add`

Add a trusted OIDC issuer. Each user can have up to 25.

**Request body:**

```json
{
  "displayName": "Release workflow",
  "issuer": "https://token.actions.githubusercontent.com",
  "audience": "https://revaulter.example.com",
  "subject": "repo:my-org/my-app:ref:refs/tags/*",
  "jwksUrl": ""
}
```

| Field | Required | Description |
| --- | --- | --- |
| `displayName` | No | Name shown in the web UI (max 100 chars) |
| `issuer` | Yes | Value of the token's `iss` claim, matched exactly (max 512 chars) |
| `audience` | Yes | Value that must appear in the token's `aud` claim (max 512 chars) |
| `subject` | Yes | Pattern the token's `sub` claim must match, where `*` matches any sequence of characters (max 512 chars). It can't consist only of wildcards |
| `jwksUrl` | No | HTTPS URL of the issuer's JWKS. When empty, it's resolved with OpenID Connect discovery, which requires `issuer` to be an HTTPS URL |

**Response:** `200 OK`, with the updated list

```json
{
  "ok": true,
  "requestOidcIssuers": [
    {
      "id": "<uuid>",
      "displayName": "Release workflow",
      "issuer": "https://token.actions.githubusercontent.com",
      "audience": "https://revaulter.example.com",
      "subject": "repo:my-org/my-app:ref:refs/tags/*",
      "createdAt": 1713200000
    }
  ]
}
```

Returns `400 Bad Request` when a field is invalid, and `409 Conflict` when the user already has the maximum number of issuers.

#### `POST /v2/auth/request-oidc-issuers/delete`

Remove a trusted OIDC issuer.

**Request body:**

```json
{
  "id": "<uuid>"
}
```

**Response:** `200 OK`, with the updated list

```json
{
  "ok": true,
  "requestOidcIssuers": []
}
```

Returns `404 Not Found` if the issuer doesn't exist.

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

Update the wrapped primary key and wrapped anchor key for a credential, for example after setting, changing, or removing the password.

**Request body:**

```json
{
  "credentialId": "<base64url>",
  "wrappedPrimaryKey": "<base64url>",
  "wrappedAnchorKey": "<base64url>",
  "advanceEpoch": true
}
```

Set `advanceEpoch` to `true` when the password changes, so the user's other passkeys are marked as stale.

To update several credentials at once, such as the current passkey and every device after a password change, send `updates` instead of the single-credential fields. Either all of them are updated, together with the epoch, or none are:

```json
{
  "advanceEpoch": true,
  "updates": [
    { "credentialId": "<base64url>", "wrappedPrimaryKey": "<base64url>", "wrappedAnchorKey": "<base64url>" },
    { "credentialId": "<base64url>", "wrappedPrimaryKey": "<base64url>", "wrappedAnchorKey": "<base64url>" }
  ]
}
```

`updates` takes up to 100 credentials.

**Response:** `200 OK`

```json
{
  "ok": true
}
```

Returns `409 Conflict` while a passkey is being added or a device is being paired.

### Credential management

#### `GET /v2/auth/credentials`

List the passkeys and devices of the authenticated user.

**Response:** `200 OK`

```json
[
  {
    "id": "<uuid>",
    "credentialId": "<base64url>",
    "type": "passkey",
    "displayName": "YubiKey 5",
    "wrappedKeyEpoch": 1,
    "wrappedKeyStale": false,
    "createdAt": 1713100000,
    "lastUsedAt": 1713200000
  },
  {
    "id": "<uuid>",
    "credentialId": "<base64url>",
    "type": "device",
    "displayName": "Alice's iPhone",
    "wrappedKeyEpoch": 1,
    "wrappedKeyStale": false,
    "createdAt": 1713150000,
    "lastUsedAt": 1713200000,
    "publicKeys": {
      "signP256": "<base64url>",
      "kaP256": "<base64url>",
      "signMldsa65": "<base64url>",
      "kemMlkem768": "<base64url>"
    },
    "attestationPayload": "<canonical body>",
    "attestationSignatureEs384": "<base64url>",
    "attestationSignatureMldsa87": "<base64url>"
  }
]
```

Rename and delete take `id`, and update-wrapped-key takes `credentialId`. A client must verify a device's attestation, signed by the anchor key, before it wraps a key for the device.

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
  "wrappedPrimaryKey": "<base64url>",
  "wrappedAnchorKey": "<base64url>",
  "attestationPayload": "<canonical body>",
  "attestationSignatureEs384": "<base64url>",
  "attestationSignatureMldsa87": "<base64url>"
}
```

The attestation, signed by the user's anchor key, proves that the user approved the new passkey.

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

Delete a credential. The user must keep at least one credential, and at least one passkey.

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

### Device pairing

Pairing adds a device for a native app, from a client that is already signed in. The existing client starts a session and shows a payload, as a QR code, a link, or text. The new device answers with a hello, the existing client checks it and sends a nonce, and both screens show a 6-digit code for the user to compare. The existing client then completes the pairing. See [Cryptography architecture](/docs/crypto-architecture/#pairing).

The new device isn't signed in. It identifies the session with the `userId` and `sessionId` from the payload. A user has one pairing session at a time, and it expires after 5 minutes.

Both clients poll for the session's status every 1 to 2 seconds. The two status endpoints allow 180 requests per minute per IP.

The `status` of a session is `created`, `hello`, `nonce`, `completed`, `canceled`, or `expired`.

#### `POST /v2/auth/pairing/create`

Start a pairing session, replacing the user's previous one. Called by the existing client.

**Request body:**

```json
{
  "server": "https://revaulter.example.com"
}
```

`server` is the server URL that goes in the payload. It must use `https`, or `http` on a loopback address.

**Response:** `200 OK`

```json
{
  "sessionId": "<base64url, 16 bytes>",
  "expiresAt": 1713200300
}
```

Returns `409 Conflict` while a passkey is being added.

#### `POST /v2/auth/pairing/hello`

Send the new device's hello. Called by the new device. The body can be up to 16 KiB.

**Request body:**

```json
{
  "userId": "<uuid>",
  "sessionId": "<base64url>",
  "hello": {
    "deviceName": "Alice's iPhone",
    "credentialId": "<base64url, 16 bytes>",
    "publicKeys": {
      "signP256": "<base64url>",
      "kaP256": "<base64url>",
      "signMldsa65": "<base64url>",
      "kemMlkem768": "<base64url>"
    },
    "signatureP256": "<base64url>",
    "signatureMldsa65": "<base64url>",
    "mac": "<base64url>"
  }
}
```

The server checks both signatures. Only the existing client can check `mac`.

**Response:** `200 OK`

```json
{
  "ok": true
}
```

Returns `404 Not Found` for an unknown session, and `409 Conflict` if the session already has a hello or has ended.

#### `GET /v2/auth/pairing/:id`

Get the session's status and, once it arrives, the device's hello. Called by the existing client.

**Response:** `200 OK`

```json
{
  "sessionId": "<base64url>",
  "status": "hello",
  "expiresAt": 1713200300,
  "hello": { "...as sent to /v2/auth/pairing/hello..." }
}
```

#### `POST /v2/auth/pairing/nonce`

Send the nonce, after checking the hello. Called by the existing client.

**Request body:**

```json
{
  "sessionId": "<base64url>",
  "nonce": "<base64url, 32 bytes>",
  "nonceMac": "<base64url, 32 bytes>"
}
```

**Response:** `200 OK`

```json
{
  "ok": true
}
```

#### `POST /v2/auth/pairing/device-status`

Get the session's status and, once it's set, the nonce. Called by the new device.

**Request body:**

```json
{
  "userId": "<uuid>",
  "sessionId": "<base64url>"
}
```

**Response:** `200 OK`

```json
{
  "status": "nonce",
  "expiresAt": 1713200300,
  "nonce": "<base64url>",
  "nonceMac": "<base64url>"
}
```

#### `POST /v2/auth/pairing/complete`

Add the device, once the user has confirmed that both screens show the same code. Called by the existing client.

**Request body:**

```json
{
  "sessionId": "<base64url>",
  "displayName": "Alice's iPhone",
  "wrappedPrimaryKey": "<base64url>",
  "wrappedAnchorKey": "<base64url>",
  "attestationPayload": "<canonical body>",
  "attestationSignatureEs384": "<base64url>",
  "attestationSignatureMldsa87": "<base64url>"
}
```

`displayName` is optional, and defaults to the device's name. The attestation, signed by the user's anchor key, must be for this device's keys, at the user's current wrapped key epoch, and created within 2 minutes.

**Response:** `200 OK`

```json
{
  "id": "<uuid>",
  "credentialId": "<base64url>"
}
```

Returns `409 Conflict` if the session isn't ready to complete, or if the password changed during the pairing.

#### `POST /v2/auth/pairing/cancel`

End the session. Called by the existing client.

**Request body:**

```json
{
  "sessionId": "<base64url>"
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

Third-party verifiers can fetch signing public keys by a stable key ID. The ID is the RFC 7638 JWK thumbprint of the public key, base64url-encoded: `base64url(SHA-256(canonical-JWK))`, where the canonical JWK is the JSON object with its members in lexicographic order: `{"crv":"P-256","kty":"EC","x":"…","y":"…"}` for `ES256` keys, and `{"crv":"Ed25519","kty":"OKP","x":"…"}` for `Ed25519` and `Ed25519ph` keys.

The server stores each key in both JWK and PEM (PKIX) form, with a `published` flag. Only published keys are served by the public endpoints below. Unpublished keys, including the ones stored automatically after a sign operation, are hidden from public lookups.

Publishing a key requires a publication proof: a payload describing the key, signed by the user's anchor keys (ES384 and ML-DSA-87). The web UI creates it when you publish a key. Verifiers can check the proof against the user's anchor, so a compromised server can't publish a key of its own.

Each user can have one key per `(algorithm, keyLabel)` pair. Creating a key under a label and algorithm that already have one is rejected with `409 Conflict`: delete the existing key first.

To revoke a key, unpublish it (reversible) or delete it (permanent). Consumers should treat a `404` for a known key ID as revocation.

### Authenticated endpoints

#### `GET /v2/api/signing-keys`

List the authenticated user's signing keys. The list doesn't include the JWK and PEM: fetch them by ID with the endpoint below.

**Response:** `200 OK`

```json
[
  {
    "id": "<key-id>",
    "algorithm": "ES256",
    "keyLabel": "release-signing",
    "published": true,
    "hasProof": true,
    "createdAt": "2026-04-17T12:00:00Z",
    "updatedAt": "2026-04-17T12:00:00Z"
  }
]
```

#### `GET /v2/api/signing-keys/:id`

Return a single signing key owned by the current user, including the stored JWK and PEM, and the publication proof if there is one.

**Response:** `200 OK`

```json
{
  "id": "<key-id>",
  "algorithm": "ES256",
  "keyLabel": "release-signing",
  "published": false,
  "hasProof": false,
  "createdAt": "2026-04-17T12:00:00Z",
  "updatedAt": "2026-04-17T12:00:00Z",
  "jwk": { "kty": "EC", "crv": "P-256", "x": "…", "y": "…" },
  "pem": "-----BEGIN PUBLIC KEY-----\n…\n-----END PUBLIC KEY-----\n"
}
```

Returns `404 Not Found` when the ID doesn't match a key belonging to the authenticated user, so a guessed ID can't probe another user's keys.

#### `POST /v2/api/signing-keys`

Create a new signing key for the current user. The `published` flag in the request body controls whether the key is served by the public endpoints below. The server checks that:

- `algorithm` is `ES256`, `Ed25519`, or `Ed25519ph`
- `keyLabel` is 1-24 characters long and contains only letters, digits, and `_ . + -`. It's stored in lowercase
- `jwk` is a valid public JWK for the algorithm: an EC P-256 key for `ES256`, or an OKP Ed25519 key for the others. JWKs with private key material (`d`), or with an invalid point, are rejected
- `pem` parses as a valid PKIX `SubjectPublicKeyInfo`
- The JWK and PEM describe the same public key (otherwise, the response is `400 Bad Request`)
- When `published` is `true`, the publication proof is present and valid

**Request body:**

```json
{
  "algorithm": "ES256",
  "keyLabel": "release-signing",
  "jwk": { "kty": "EC", "crv": "P-256", "x": "…", "y": "…" },
  "pem": "-----BEGIN PUBLIC KEY-----\n…\n-----END PUBLIC KEY-----\n",
  "published": true,
  "publicationPayload": "<canonical body>",
  "publicationSignatureEs384": "<base64url>",
  "publicationSignatureMldsa87": "<base64url>"
}
```

The `publication*` fields are required when `published` is `true`, and optional otherwise.

**Response:** `201 Created`

```json
{
  "id": "<key-id>",
  "algorithm": "ES256",
  "keyLabel": "release-signing",
  "published": true,
  "hasProof": true,
  "createdAt": "2026-04-17T12:00:00Z",
  "updatedAt": "2026-04-17T12:00:00Z"
}
```

This endpoint never overwrites a key: if the user already has a key with the same algorithm and label, created earlier or stored automatically after a sign operation, the request is rejected with `409 Conflict`. To store a different key under the same label, delete the existing one first. To publish or unpublish an existing key, use `POST /v2/api/signing-keys/:id`.

#### `POST /v2/api/signing-keys/:id`

Publish or unpublish a signing key owned by the current user. For example, use it to unpublish a key, or to publish a key that was stored automatically after a sign operation.

**Request body:**

```json
{ "published": false }
```

To publish a key that doesn't have a publication proof yet, include `publicationPayload`, `publicationSignatureEs384`, and `publicationSignatureMldsa87`, as for `POST /v2/api/signing-keys`.

**Response:** `200 OK`

```json
{
  "id": "<key-id>",
  "algorithm": "ES256",
  "keyLabel": "release-signing",
  "published": false,
  "hasProof": true,
  "createdAt": "2026-04-17T12:00:00Z",
  "updatedAt": "2026-04-17T12:00:00Z"
}
```

Returns `404 Not Found` when the ID doesn't match a key belonging to the authenticated user, so a guessed ID can't probe another user's keys.

#### `DELETE /v2/api/signing-keys/:id`

Permanently delete a signing key owned by the current user. Its ID stops resolving, and you can create a new key with the same algorithm and label.

**Response:** `200 OK`

```json
{ "deleted": true }
```

Returns `404 Not Found` when the ID doesn't match a key belonging to the authenticated user, so a guessed ID can't probe another user's keys. Deleting the same ID again also returns `404`.

### Public (unauthenticated) endpoints

These endpoints take only the key ID. There's no endpoint to list keys, so clients must get the key ID some other way.

Both endpoints are rate-limited and return `Cache-Control: public, max-age=600`. Unknown IDs return `404 Not Found`.

#### `GET /v2/signing-keys/:id.jwk`

**Alias: `GET /v2/signing-keys/:id.json`**

Returns the stored JWK, with the key's metadata, its publication proof, and the user's anchor public keys.

**Response:** `200 OK`

```json
{
  "id": "<key-id>",
  "algorithm": "ES256",
  "keyLabel": "release-signing",
  "createdAt": "2026-04-17T12:00:00Z",
  "jwk": { "kty": "EC", "crv": "P-256", "x": "…", "y": "…" },
  "publicationPayload": "<canonical body>",
  "publicationSignatureEs384": "<base64url>",
  "publicationSignatureMldsa87": "<base64url>",
  "anchorEs384PublicKey": "<canonical JWK body>",
  "anchorMldsa87PublicKey": "<base64url>"
}
```

#### `GET /v2/signing-keys/:id.pem`

**Alias: `GET /v2/signing-keys/:id.pub`**

Returns the stored PEM with `Content-Type: application/x-pem-file`. This is the form consumed by OpenSSL and many standard verifier libraries.

### Verification

An external verifier receives a message, a detached signature (64 bytes), and the signer's published key ID or PEM. To verify an `ES256` signature (raw `r || s`):

1. Import the PEM (or JWK) public key
2. Convert the raw `r || s` signature to the format your library expects (ASN.1 DER for OpenSSL, while WebCrypto's `verify` API accepts the raw form)
3. Verify the signature over the message with ECDSA P-256 and SHA-256

`Ed25519` signatures are verified over the message with any standard Ed25519 library. `Ed25519ph` signatures are verified with Ed25519ph (RFC 8032), over the message's SHA-512 digest.

> ECDSA signatures are non-deterministic: signing the same digest twice produces two different signatures, and both are valid. Don't compare signatures to check whether two messages are the same.
