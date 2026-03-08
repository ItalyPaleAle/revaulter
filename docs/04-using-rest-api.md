# Using Revaulter REST APIs (v2)

Revaulter v2 exposes REST APIs for request submission, admin approval, and result polling.

## Request flow

1. Client submits `POST /v2/request/[operation]`.
2. Client long-polls `GET /v2/request/result/[state]`.
3. Admin authenticates in the web UI (`/v2/auth/*`) and approves the request.
4. Browser performs the crypto operation locally and sends an encrypted response envelope via `POST /v2/api/confirm`.
5. Revaulter relays the encrypted envelope to the client.
6. Client decrypts the envelope locally using its ephemeral private key.

## Supported CLI-facing endpoints

- `POST /v2/request/encrypt`
- `POST /v2/request/decrypt`
- `POST /v2/request/wrapkey`
- `POST /v2/request/unwrapkey`
- `GET /v2/request/result/:state`

## Create request body (example)

```json
{
  "targetUser": "alice",
  "keyLabel": "boot-disk",
  "algorithm": "aes-gcm-256",
  "value": "SGVsbG8",
  "timeout": "5m",
  "note": "boot unlock",
  "clientTransportKey": {
    "kty": "EC",
    "crv": "P-256",
    "x": "...",
    "y": "..."
  }
}
```

Notes:

- `clientTransportKey` must be a public EC JWK (`P-256`), with no private fields (`d` is rejected).
- `value`, `nonce`, `tag`, and `additionalData` are base64/base64url-encoded strings.
- `targetUser` identifies the admin who is allowed to approve the request.

## Create request response

```json
{
  "state": "<uuid>",
  "pending": true
}
```

## Result polling responses

Pending:

```json
{
  "state": "<uuid>",
  "pending": true
}
```

Completed:

```json
{
  "state": "<uuid>",
  "done": true,
  "responseEnvelope": {
    "transportAlg": "ecdh-p256+a256gcm",
    "browserEphemeralPublicKey": {
      "kty": "EC",
      "crv": "P-256",
      "x": "...",
      "y": "..."
    },
    "nonce": "...",
    "ciphertext": "...",
    "aad": "...",
    "resultType": "bytes"
  }
}
```

Failed/expired/canceled requests return a failure response with an error status.

## Admin endpoints (browser/UI)

Authenticated admin flows use:

- `POST /v2/auth/register/begin`
- `POST /v2/auth/register/finish`
- `POST /v2/auth/login/begin`
- `POST /v2/auth/login/finish`
- `GET /v2/auth/session`
- `POST /v2/auth/logout`
- `GET /v2/api/list`
- `GET /v2/api/request/:state`
- `POST /v2/api/confirm`

See [`docs/05-revaulter-v2.md`](./05-revaulter-v2.md) for protocol and security details.
