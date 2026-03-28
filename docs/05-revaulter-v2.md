# Revaulter v2 (WebAuthn + Browser Crypto)

Revaulter v2 replaces the Azure AD + Azure Key Vault execution model with a browser-executed cryptography flow.

## Summary

- Requests are submitted by the CLI to `/v2/request/*`.
- Revaulter stores requests in a database (SQLite or Postgres).
- Admins authenticate in the browser with WebAuthn.
- The browser performs crypto operations locally using WebCrypto.
- Results are encrypted to the CLI using ephemeral ECDH (P-256) + AES-GCM and relayed by Revaulter.

Revaulter v2 does not need Azure AD or Azure Key Vault.

## Configuration

Enable by configuring:

- `databaseDSN`
- `secretKey`

Optional auth settings:

- `webauthnRpId`
- `webauthnRpName`
- `webauthnOrigins`
- `passwordFactorMode`
- `passwordPbkdf2Iterations`

Revaulter is v2-only. Legacy v1 endpoints (`/auth`, `/api`, `/request`) return `410 Gone` for compatibility.

## DSN rules

- `postgres://...` or `postgresql://...` => Postgres (native `pgx`)
- `sqlite://...` => SQLite
- no scheme (for example `./data/revaulter.db`) => local SQLite file

SQLite is initialized with WAL mode enabled.

## Supported operations (v2)

- `encrypt`
- `decrypt`

Initial algorithm support:

- `aes-gcm-256`

## CLI usage (v2)

Use the `v2` command group:

```bash
revaulter-cli v2 encrypt \
  --server https://revaulter.example \
  --target-user alice \
  --key-label boot-disk \
  --algorithm aes-gcm-256 \
  --value <base64url>
```

The CLI automatically:

- generates an ephemeral P-256 transport keypair
- sends the public key as a JWK in `clientTransportKey`
- waits for `/v2/request/result/:state`
- decrypts the returned envelope locally

## Admin workflow

### First admin

- `POST /v2/auth/register/begin`
- `POST /v2/auth/register/finish`

The first admin self-registers when there are zero admins in the database.

### Additional admins

Authenticated admins can register additional admins:

- `POST /v2/auth/admin/register/begin`
- `POST /v2/auth/admin/register/finish`

### Login/logout/session

- `POST /v2/auth/login/begin`
- `POST /v2/auth/login/finish`
- `GET /v2/auth/session`
- `POST /v2/auth/logout`

## Request/approval endpoints

CLI-facing:

- `POST /v2/request/encrypt`
- `POST /v2/request/decrypt`
- `GET /v2/request/result/:state`

Admin-facing:

- `GET /v2/api/list`
- `GET /v2/api/request/:state`
- `POST /v2/api/confirm`

## Key transport format (JWK)

Shared ephemeral public keys are JSON Web Keys (JWK), not SPKI.

Example:

```json
{
  "kty": "EC",
  "crv": "P-256",
  "x": "<base64url>",
  "y": "<base64url>"
}
```

## Security notes

- Sensitive request payloads and response envelopes are encrypted at rest in the DB.
- Password factor (if enabled) is verified server-side via HMAC proof and used locally in browser key derivation.
- The final operation result returned to the CLI is encrypted in transit with a per-request ECDH-derived AES-GCM key.
