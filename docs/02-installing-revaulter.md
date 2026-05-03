# Installing Revaulter

Revaulter is distributed as a container image and runs as a single-container service.

## Requirements

- A container runtime (Docker, Podman, etc.)
- A database: **SQLite** or **PostgreSQL**
- HTTPS access for the web UI: TLS certificates or a reverse proxy (this is required because of WebCrypto)
- A webhook endpoint for notifications (Discord, Slack, or any HTTP endpoint)

## Container images

| Image | Description |
|-------|-------------|
| `ghcr.io/italypaleale/revaulter:2` | Revaulter server |
| `ghcr.io/italypaleale/revaulter-cli:2` | Revaulter CLI |

Both images are available for `amd64` and `arm64`.

## Configuration

Revaulter is configured via a YAML file and/or environment variables. Inside the container, it looks for `config.yaml` at:

1. The path set in the `REVAULTER_CONFIG` environment variable
2. `/etc/revaulter/config.yaml`
3. `$HOME/.revaulter/config.yaml`
4. The same directory as the binary

### Required configuration

| Key | Env var | Description |
|-----|---------|-------------|
| `webhookUrl` | `WEBHOOKURL` | Webhook endpoint for notifications |
| `databaseDSN` | `DATABASEDSN` | Database connection string (see [Database](#database) below) |
| `secretKey` | `SECRETKEY` | Instance-wide secret for key derivation (see [Secret key](#secret-key) below) |

### Recommended configuration

| Key | Env var | Default | Description |
|-----|---------|---------|-------------|
| `baseUrl` | `BASEURL` | `https://localhost:<port>` | Public URL where users access the web UI. Used for webhook links and WebAuthn origin validation. |
| `sessionSigningKey` | `SESSIONSIGNINGKEY` | Random at startup | Secret used to sign session tokens. Set this in production so sessions survive restarts. |
| `tlsPath` | `TLSPATH` | Config file directory | Directory containing `tls-cert.pem` and `tls-key.pem`. Revaulter watches for changes and auto-reloads. |
| `tlsCertPEM` | `TLSCERTPEM` | | PEM-encoded TLS certificate (alternative to `tlsPath`) |
| `tlsKeyPEM` | `TLSKEYPEM` | | PEM-encoded TLS key (alternative to `tlsPath`) |

### Optional configuration

| Key | Env var | Default | Description |
|-----|---------|---------|-------------|
| `webhookFormat` | `WEBHOOKFORMAT` | `plain` | Webhook format: `plain`, `slack`, or `discord` |
| `webhookKey` | `WEBHOOKKEY` | | Value sent as `Authorization` header on webhook requests (include the scheme, e.g. `Bearer abc123`) |
| `port` | `PORT` | `8080` | Port to bind to |
| `bind` | `BIND` | `0.0.0.0` | Address/interface to bind to |
| `disableSignup` | `DISABLESIGNUP` | `false` | Disable creation of new user accounts |
| `sessionTimeout` | `SESSIONTIMEOUT` | `5m` | Session duration before re-authentication is required (max: `1h`) |
| `requestTimeout` | `REQUESTTIMEOUT` | `5m` | Default timeout for requests (can be overridden per-request; max: `24h`) |
| `trustedProxies` | `TRUSTEDPROXIES` | | Comma-separated list of IPs/CIDRs to trust for `X-Forwarded-*` headers |
| `forceSecureCookies` | `FORCESECURECOOKIES` | `false` | Force the `Secure` flag on cookies (set to `true` when behind a TLS-terminating reverse proxy) |
| `trustedRequestIdHeader` | `TRUSTEDREQUESTIDHEADER` | | Header to trust as request ID (e.g. `X-Request-ID`, `CF-Ray`) |
| `logHealthChecks` | `LOGHEALTHCHECKS` | `false` | Include `/healthz` requests in the request logs |
| `logLevel` | `LOGLEVEL` | `info` | Log level: `debug`, `info`, `warn`, `error` |
| `logAsJson` | `LOGASJSON` | auto | Emit JSON logs (defaults to `true` when no TTY is attached) |

### Optional WebAuthn configuration

These settings are necessary in some scenarios only. Revaulter derives sensible defaults from `baseUrl`.

| Key | Env var | Default | Description |
|-----|---------|---------|-------------|
| `webauthnRpId` | `WEBAUTHNRPID` | Derived from `baseUrl` | WebAuthn Relying Party ID |
| `webauthnRpName` | `WEBAUTHNRPNAME` | `Revaulter` | WebAuthn Relying Party display name |
| `webauthnOrigins` | `WEBAUTHNORIGINS` | `baseUrl` | Allowed WebAuthn origins |

## Database

Revaulter supports SQLite and PostgreSQL. The backend is detected automatically from the DSN:

| DSN format | Backend |
|------------|---------|
| `postgres://user:pass@host:5432/dbname` | PostgreSQL |
| `sqlite:///path/to/file.db` | SQLite |
| `/path/to/file.db` (no scheme) | SQLite |

SQLite requires no external dependencies and is a good default for single-node deployments.

For PostgreSQL, use a standard connection string with `sslmode=require` in production:

```
postgres://revaulter:password@db.example.com:5432/revaulter?sslmode=require
```

> ⚠️ **Warning:** When using SQLite, the database file must **not** be stored on a networked filesystem, like NFS or SMB.

## Backing up Revaulter

Revaulter's database is critical state and must be backed up.

Even though request payloads and responses are encrypted with keys derived from passkeys, the database stores the wrapped key material that is required to use Revaulter with each passkey. If you lose the database, users will no longer be able to decrypt messages encrypted with a passkey or sign new digests.

Database loss is irrecoverable.

Back up the database regularly, keep backups outside the same host or volume, and test that you can restore them.

> You should also preserve the same `secretKey` from your configuration because restores must use the original value.

### Built-in `backup` and `restore` subcommands

The `revaulter` server binary ships with `backup` and `restore` subcommands that produce a backend-agnostic snapshot of the database. The format contains data only and embeds the source schema migration level, so a backup taken from SQLite can be restored into PostgreSQL, or vice versa.

Both subcommands read the same configuration as the server and connect to the database at `databaseDSN`.

```bash
revaulter backup --out /backups/revaulter-$(date +%F).bak

# or stream it directly through another tool, e.g.
revaulter backup | gzip > /backups/revaulter-$(date +%F).bak.gz
```

Restore into an existing database, reading from stdin or from the path given via `-in`:

```bash
revaulter restore --in /backups/revaulter-2026-05-01.bak
```

The `restore` command applies migrations up to the schema level recorded in the backup before inserting rows; any newer migrations bundled with the binary are left for the application to run on its next startup. Restoring into a database that already contains data is not supported — restore into a fresh database.

> Stop the running Revaulter instance before restoring into its database.

### SQLite backups

With SQLite, the critical data is the database file itself.

In addition to the built-in `revaulter backup` subcommand above, you can use an application-aware backup such as SQLite's `.backup` command, or stop Revaulter briefly before copying the file. This avoids taking a backup from a live database file in an inconsistent state.

Store the backup on a different disk, host, or backup service.

Example:

```bash
sqlite3 /data/revaulter.db ".backup /backups/revaulter-$(date +%F).db"
```

### PostgreSQL backups

With PostgreSQL, in addition to the built-in `revaulter backup` subcommand above, you can use standard backup tooling such as `pg_dump` for logical backups, or physical backups and WAL archiving if you need point-in-time recovery. Make sure your backup strategy covers the Revaulter database, retains copies off-host, and is tested by restoring into a fresh PostgreSQL instance.

After restoring PostgreSQL, start Revaulter with the restored database and the same `secretKey` value that was used originally.

## Secret key

Generate a secret key:

```bash
openssl rand -base64 32
```

> ⚠️ **Warning:** Rotating `secretKey` bricks every existing account on the instance. The secret key is used to derive the WebAuthn PRF salt that every user's in-browser key derivation is bound to. Treat this value as **immutable** for the lifetime of the instance. If you must rotate it, every user will need to re-register from scratch.

> 📝 **Note:** `secretKey` is **not** used to encrypt anything stored in the database. All request payloads and responses are end-to-end encrypted in the browser; the server only stores opaque envelopes.

## Session signing key

Generate a session signing key:

```bash
openssl rand -base64 32
```

Set `sessionSigningKey` in production so session tokens remain valid across restarts. If this value is omitted, Revaulter generates a random signing key at startup; existing sessions are invalidated whenever the process restarts.

## TLS

Revaulter requires HTTPS for WebAuthn to work (browsers enforce a secure context). You have two options:

1. **Reverse proxy** (recommended): Terminate TLS at a reverse proxy (Caddy, Traefik, Nginx, etc.) and forward plain HTTP to Revaulter.
   - Set `forceSecureCookies: true` in this case.
2. **Direct TLS**: Provide certificates via `tlsPath` (a directory containing `tls-cert.pem` and `tls-key.pem`) or via `tlsCertPEM`/`tlsKeyPEM`. Revaulter watches the `tlsPath` directory and auto-reloads certificates.

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

With a `config.yaml`:

```yaml
webhookUrl: "https://discord.com/api/webhooks/your-webhook-id/your-webhook-token"
webhookFormat: "discord"
databaseDSN: "/data/revaulter.db"
secretKey: "<your-secret-key>"
sessionSigningKey: "<your-session-signing-key>"
baseUrl: "https://revaulter.example.com"
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
Image=ghcr.io/italypaleale/revaulter:latest
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
3. After registration, the UI shows your **request key**: this is the per-user key that CLI requests are routed by.
4. Optionally configure allowed IP addresses for your account from the settings page.

> Account self-registration can be disabled by setting `disableSignup: true` after initial setup.
