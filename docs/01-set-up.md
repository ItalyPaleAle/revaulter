# Set up (v2)

Revaulter v2 does not require Azure AD or Azure Key Vault. All cryptographic operations are performed in the user's browser using WebAuthn (PRF) and WebCrypto.

## Requirements

- A server where Revaulter can run and expose HTTPS
- TLS certificates for the Revaulter server
- A database:
  - SQLite (local file, WAL mode is enabled automatically)
  - or Postgres (`postgres://` / `postgresql://` DSN)
- A webhook endpoint (Slack/Discord/plain) for notifications
- A modern browser with WebAuthn support (and PRF-capable authenticator/passkey)
- The `revaulter-cli` binary for requesting operations

## Choose Your URL

Pick the HTTPS URL users will use to access Revaulter (for example `https://revaulter.example.com`).

This URL is used for:

- Browser access to the web UI
- WebAuthn RP/origin validation (directly or via derived defaults)
- Links included in webhook notifications

## Prepare a Database

Examples:

- SQLite file: `./data/revaulter.db`
- SQLite URI: `sqlite://./data/revaulter.db`
- Postgres: `postgres://user:pass@db.example.com:5432/revaulter?sslmode=require`

## Generate a Secret Key

Set `secretKey` to a strong secret. For example:

```bash
openssl rand -base64 32
```

> **⚠️ WARNING: Rotating `secretKey` will brick every existing account** on this instance, essentially making them unable to sign in.
> Treat this value as immutable for the lifetime of the instance.

> **Note:** `secretKey` is **not** used to encrypt anything stored in the database.
> All request payloads are end-to-end encrypted in the browser; the server only relays opaque ciphertext. `secretKey` is the input used to derive the instance-wide WebAuthn PRF salt that every user's in-browser key derivation is bound to.

## Account Registration

Users can create their own accounts from the main web UI using WebAuthn, unless `disableSignup` is set to `true` in the server configuration.
