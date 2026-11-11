---
title: "Installing Revaulter"
weight: 25
---

Revaulter is distributed as a container image and runs as a single-container service. With PostgreSQL, you can also run [multiple replicas](/docs/multiple-replicas/).

## Requirements

- A container runtime (Docker, Podman, etc.)
- A database: **SQLite** or **PostgreSQL**
- HTTPS access for the web UI
- Optional: a webhook endpoint for notifications (including Discord, Slack, ntfy, Telegram, Teams, or any HTTP endpoint)

> HTTPS is required because browsers only allow passkeys and WebCrypto on secure pages.  
> You can either have Revaulter serve HTTPS itself, with your TLS certificates, or use a reverse proxy that terminates TLS, such as Caddy, Traefik, or Nginx. See [TLS](#tls).

## Container images

| Image | Description |
| ---- | ---- |
| `ghcr.io/italypaleale/revaulter:2` | Revaulter server |
| `ghcr.io/italypaleale/revaulter-cli:2` | Revaulter CLI |
| `ghcr.io/italypaleale/revaulter-edit:2` | Revaulter local file encryption utility |

Images are available for `amd64`, `arm64` and `arm/v7`.

## Configuration

Revaulter reads its configuration from a YAML file, from environment variables, or both. It loads the first `config.yaml` it finds in:

1. The path set in the `REVAULTER_CONFIG` environment variable
2. The current working directory
3. `$HOME/.revaulter/`
4. `/etc/revaulter/`

In a container, mount the file at `/etc/revaulter/config.yaml`.

### Required configuration

| Key | Env var | Description |
| ---- | ---- | ---- |
| `databaseDSN` | `REVAULTER_DATABASEDSN` | Database connection string (see [Database](#database) below) |
| `secretKey` | `REVAULTER_SECRETKEY` | Instance-wide secret for key derivation (see [Secret key](#secret-key) below) |
| `baseUrl` | `REVAULTER_BASEURL` | Public URL where users access the web UI, such as `https://revaulter.example.com`. Passkeys are registered for this address, and notifications link to it |

### Recommended configuration

| Key | Env var | Default | Description |
| ---- | ---- | ---- | ---- |
| `sessionSigningKey` | `REVAULTER_SESSIONSIGNINGKEY` | Random at startup | Secret used to sign session tokens. Set this in production so sessions survive restarts. |
| `tlsPath` | `REVAULTER_TLSPATH` | Config file directory | Directory containing `tls-cert.pem` and `tls-key.pem`. Revaulter watches for changes and auto-reloads. |
| `tlsCertPEM` | `REVAULTER_TLSCERTPEM` | | PEM-encoded TLS certificate (alternative to `tlsPath`) |
| `tlsKeyPEM` | `REVAULTER_TLSKEYPEM` | | PEM-encoded TLS key (alternative to `tlsPath`) |

### Optional configuration

| Key | Env var | Default | Description |
| ---- | ---- | ---- | ---- |
| `webhookUrl` | `REVAULTER_WEBHOOKURL` | | Webhook endpoint for notifications. Leave unset to disable webhook notifications. A notification that fails is retried up to 2 more times, unless the request isn't pending anymore. |
| `webhookFormat` | `REVAULTER_WEBHOOKFORMAT` | `plain` | Webhook format: `plain`, `slack`, `discord`, `ntfy`, `telegram`, `googlechat`, or `teams` |
| `webhookKey` | `REVAULTER_WEBHOOKKEY` | | Value sent as `Authorization` header on webhook requests (include the scheme, e.g. `Bearer abc123`) |
| `webhookAllowPrivateAddresses` | `REVAULTER_WEBHOOKALLOWPRIVATEADDRESSES` | `false` | Allow sending webhook notifications to private addresses (e.g. those in the LAN), which are refused by default. Enable it only if the receiver is on a private network, for example a self-hosted ntfy, Gotify, or alert router on your LAN |
| `port` | `REVAULTER_PORT` or `PORT` | `8080` | Port to bind to |
| `bind` | `REVAULTER_BIND` | `0.0.0.0` | Address/interface to bind to |
| `disableSignup` | `REVAULTER_DISABLESIGNUP` | `false` | Disable creation of new user accounts |
| `oidcAllowPrivateAddresses` | `REVAULTER_OIDCALLOWPRIVATEADDRESSES` | `false` | Allow fetching the discovery documents and JWKS of [trusted OIDC issuers](/docs/oidc-authentication/) from private, loopback, and link-local addresses, which are refused by default. Enable it only if your issuers are on a private network, and you trust every user who can configure issuers |
| `sessionTimeout` | `REVAULTER_SESSIONTIMEOUT` | `5m` | Session duration before re-authentication is required (max: `1h`) |
| `requestTimeout` | `REVAULTER_REQUESTTIMEOUT` | `5m` | Default timeout for requests. Each request can set its own timeout, up to `24h` |
| `trustedProxies` | `REVAULTER_TRUSTEDPROXIES` | | List of IPs or CIDRs of proxies whose `X-Forwarded-*` headers are trusted (comma-separated in the env var) |
| `trustedRequestIdHeader` | `REVAULTER_TRUSTEDREQUESTIDHEADER` | | Header to trust as request ID (e.g. `X-Request-ID`, `CF-Ray`) |
| `logHealthChecks` | `REVAULTER_LOGHEALTHCHECKS` | `false` | Include `/healthz` requests in the request logs |
| `logLevel` | `REVAULTER_LOGLEVEL` | `info` | Log level: `debug`, `info`, `warn`, `error` |
| `logAsJson` | `REVAULTER_LOGASJSON` | auto | Emit JSON logs (defaults to `true` when no TTY is attached) |
| `francisPeerAddress` | `REVAULTER_FRANCISPEERADDRESS` | `127.0.0.1:7571` | Address (host and port) the other replicas use to reach this one when [running multiple replicas](/docs/multiple-replicas/) |
| `francisBindPort` | `REVAULTER_FRANCISBINDPORT` | Port of `francisPeerAddress` | UDP port this replica listens on for the other replicas, if it's different from the port in `francisPeerAddress` |
| `francisDatabaseDSN` | `REVAULTER_FRANCISDATABASEDSN` | Derived from `databaseDSN` | Where [short-lived data](#short-lived-data) is stored |

### Optional WebAuthn configuration

These settings are necessary in some scenarios only. By default, Revaulter derives them from `baseUrl`.

| Key | Env var | Default | Description |
| ---- | ---- | ---- | ---- |
| `webauthnRpId` | `REVAULTER_WEBAUTHNRPID` | Derived from `baseUrl` | WebAuthn Relying Party ID |
| `webauthnRpName` | `REVAULTER_WEBAUTHNRPNAME` | `Revaulter` | WebAuthn Relying Party display name |
| `webauthnOrigins` | `REVAULTER_WEBAUTHNORIGINS` | | Additional origins allowed to use passkeys. `baseUrl` is always allowed |

## Database

Revaulter supports SQLite and PostgreSQL. The backend is detected automatically from the DSN:

| DSN format | Backend |
| ---- | ---- |
| `postgres://user:pass@host:5432/dbname` | PostgreSQL |
| `sqlite:///path/to/file.db` | SQLite |
| `/path/to/file.db` (no scheme) | SQLite |

SQLite requires no external dependencies and is a good default for a single server. To run [multiple replicas](/docs/multiple-replicas/), use PostgreSQL.

For PostgreSQL, use a standard connection string, for example:

```
postgres://revaulter:password@db.example.com:5432/revaulter
```

> ⚠️ **Warning:** When using SQLite, the database file must **not** be stored on a networked filesystem, like NFS or SMB.

### Short-lived data

Revaulter keeps short-lived data, including pending requests, in an embedded [Francis](https://gofrancis.dev) actor host, which stores it separately from the main database:

| Main database | Francis data storage |
| --- | --- |
| PostgreSQL | A `francis` schema in the same database, created automatically |
| SQLite, e.g. `/data/revaulter.db` | A file in the same folder, e.g. `/data/revaulter.francis.db` |

Set `francisDatabaseDSN` to store it elsewhere. Like the main SQLite file, this database must not be stored on a networked filesystem.

The data stored in Francis is ephemeral and never included in backups.

## Secret key

Generate a secret key:

```bash
openssl rand -base64 32
```

> ⚠️ **Warning:** Changing `secretKey` makes every existing account on the instance unusable. The secret key is used to derive the WebAuthn PRF salt, which every user's keys depend on.  
> Treat this value as **immutable** for the lifetime of the instance. If you must change it, every user will need to register again from scratch.

> 📝 **Note:** `secretKey` is **not** used to encrypt anything stored in the database. All request payloads and responses are end-to-end encrypted in the browser; the server only stores opaque envelopes.

## Session signing key

Generate a session signing key:

```bash
openssl rand -base64 32
```

Set `sessionSigningKey` in production so session tokens remain valid across restarts. If it's not set, Revaulter generates a random signing key at startup, and existing sessions end whenever the process restarts.

When [running multiple replicas](/docs/multiple-replicas/), `sessionSigningKey` is required, and it must be the same on all of them.

## TLS

Passkeys only work over HTTPS. You have two options:

1. **Reverse proxy** (recommended): terminate TLS at a reverse proxy, such as Caddy, Traefik, or Nginx, and forward plain HTTP to Revaulter. Set `trustedProxies` to the proxy's address, so Revaulter sees the clients' real IP addresses, which it uses for IP restrictions, rate limiting, and the audit log.
2. **Direct TLS**: provide certificates with `tlsPath` (a directory containing `tls-cert.pem` and `tls-key.pem`), or with `tlsCertPEM` and `tlsKeyPEM`. Revaulter watches the `tlsPath` directory and reloads certificates automatically when they change.

## Docker Compose example

```yaml
services:
  revaulter:
    image: ghcr.io/italypaleale/revaulter:2
    ports:
      - "8080:8080"
    volumes:
      - ./config.yaml:/etc/revaulter/config.yaml:ro
      - revaulter-data:/data
    restart: unless-stopped

volumes:
  revaulter-data:
```

The container runs as a non-root user (UID 65532). If you mount a host directory at `/data` instead of a volume, make that user its owner, for example with `sudo chown 65532:65532 ./data`. On hosts with SELinux enforcing, also add `:Z` to the mount.

With a `config.yaml`:

```yaml
databaseDSN: "/data/revaulter.db"
secretKey: "<your-secret-key>"
sessionSigningKey: "<your-session-signing-key>"
baseUrl: "https://revaulter.example.com"
```

To enable Discord notifications, add:

```yaml
webhookUrl: "https://discord.com/api/webhooks/your-webhook-id/your-webhook-token"
webhookFormat: "discord"
```

If you want Revaulter to handle TLS directly:

```yaml
services:
  revaulter:
    image: ghcr.io/italypaleale/revaulter:2
    ports:
      - "443:8080"
    volumes:
      - ./config.yaml:/etc/revaulter/config.yaml:ro
      - ./tls:/etc/revaulter/tls:ro
      - revaulter-data:/data
    restart: unless-stopped

volumes:
  revaulter-data:
```

And add to `config.yaml`:

```yaml
tlsPath: "/etc/revaulter/tls"
port: 8080
```

Place `tls-cert.pem` and `tls-key.pem` in the `./tls` directory.

## Podman Quadlet example

First, store the config file as a Podman secret:

```bash
podman secret create revaulter-config ~/.config/revaulter/config.yaml
```

Create a container unit file at `~/.config/containers/systemd/revaulter.container` (rootless) or `/etc/containers/systemd/revaulter.container` (rootful):

```ini
[Unit]
Description=Revaulter
After=network-online.target

[Container]
Image=ghcr.io/italypaleale/revaulter:2
PublishPort=8080:8080
Secret=revaulter-config,target=/etc/revaulter/config.yaml
Volume=revaulter-data.volume:/data
AutoUpdate=registry

[Service]
Restart=always

[Install]
WantedBy=default.target
```

Create a volume unit file at the same location, `revaulter-data.volume`:

```ini
[Volume]
```

Then reload and start:

```bash
# Rootless
systemctl --user daemon-reload
systemctl --user enable --now revaulter

# Rootful
systemctl daemon-reload
systemctl enable --now revaulter
```

To update the config later, recreate the secret and restart the service:

```bash
podman secret rm revaulter-config
podman secret create revaulter-config ~/.config/revaulter/config.yaml
systemctl --user restart revaulter
```

## User setup

After starting Revaulter:

1. Open the web UI at your configured `baseUrl`.
2. Create an account: registration uses WebAuthn, so you'll need a passkey-capable authenticator with PRF support.
   > Finish creating the account within 24 hours of registering the passkey, or you'll need to start over.
3. After registration, the UI shows your **request key**, which the CLI uses to send you requests. You can also find it under **Settings → Request auth**.
4. Optionally, restrict the IP addresses that can use your account under **Settings → Firewall**.

> After creating your accounts, you can turn off self-registration by setting `disableSignup: true`.
