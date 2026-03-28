# Set up (v2)

Revaulter v2 does not require Azure AD or Azure Key Vault. All cryptographic operations are performed in the administrator's browser using WebAuthn (PRF) and WebCrypto.

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

Pick the HTTPS URL admins will use to access Revaulter (for example `https://revaulter.example.com`).

This URL is used for:

- Browser access to the admin UI
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

## First Admin Registration

After the server starts and no admins exist yet, the first user to open the web UI can self-register as an admin using WebAuthn.

Subsequent admins are added through the authenticated admin UI/API.
