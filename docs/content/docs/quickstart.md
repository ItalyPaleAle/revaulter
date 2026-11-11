---
title: "Quickstart"
weight: 23
---

Run your own Revaulter server in a few minutes.

## Docker Compose

You can run Revaulter with Docker Compose:

```yaml
# docker-compose.yml
services:
  revaulter:
    image: ghcr.io/italypaleale/revaulter:2
    ports:
      - "8080:8080"
    volumes:
      - ./config.yaml:/etc/revaulter/config.yaml:ro
      - ./data:/data
    restart: unless-stopped
```

Create a minimal `config.yaml`:

```yaml
databaseDSN: "/data/revaulter.db"
secretKey: "<generate with: openssl rand -base64 32>"
baseUrl: "https://revaulter.example.com"
```

To send notifications when requests are waiting, add `webhookUrl` and `webhookFormat`.

Revaulter runs as a non-root user (UID 65532), which must be able to write to the `data` directory. Create it before starting the container:

```bash
mkdir -p data
sudo chown 65532:65532 data
```

On hosts with SELinux enforcing, such as Fedora or RHEL, also add `:Z` to the volume: `./data:/data:Z`.

Revaulter must be reachable at `baseUrl` over HTTPS, because passkeys don't work on plain HTTP pages (excluding from localhost). Put it behind a reverse proxy that terminates TLS, or see [TLS](/docs/installing-revaulter/#tls) for other options.

Then start the server with `docker compose up`, open the web UI, and create your first account.

## Full setup instructions

See [Installing Revaulter](/docs/installing-revaulter) for more details on how to install and run Revaulter.
