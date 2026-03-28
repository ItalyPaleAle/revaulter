# Install and configure Revaulter (v2)

Revaulter runs as a lightweight HTTPS service. Admins connect to the web UI to approve requests; CLI clients call the `/v2/request/*` APIs.

## Installation

Install the server binary on a machine that:

- is reachable by admins over HTTPS
- can reach your database
- can send outbound webhook requests

## Configuration file

Revaulter loads `config.yaml` from one of:

- `/etc/revaulter/config.yaml`
- `$HOME/.revaulter/config.yaml`
- the same directory as the Revaulter binary

You can override the path with `REVAULTER_CONFIG`.

Use [`config.sample.yaml`](../config.sample.yaml) as the full reference.

## Minimum v2 configuration

Required:

- `webhookUrl`
- `databaseDSN`
- `secretKey`

Recommended:

- `baseUrl`
- `origins`
- `tlsPath` (or `tlsCertPEM` + `tlsKeyPEM`)
- `requestKey`
- `allowedIps`
- `cookieEncryptionKey`
- `tokenSigningKey`

Optional auth settings:

- `webauthnRpId`
- `webauthnRpName`
- `webauthnOrigins`
- `passwordFactorMode` (`disabled` or `required`)
- `passwordPbkdf2Iterations`

## DSN behavior

- `postgres://...` / `postgresql://...` => Postgres (native `pgx`)
- `sqlite://...` => SQLite
- no scheme (for example `./data/revaulter.db`) => SQLite local file

SQLite is initialized with:

- `PRAGMA journal_mode=WAL`
- `PRAGMA foreign_keys=ON`

## Start the server

```bash
revaulter
```

Then open the web UI, self-register the first admin, and use `revaulter-cli v2 ...` to submit requests.
