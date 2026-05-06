---
title: "Quickstart"
weight: 23
---

Launch your Revaulter server in minutes with the quickstart.

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
webhookUrl: "https://discord.com/api/webhooks/..."
databaseDSN: "/data/revaulter.db"
secretKey: "<generate with: openssl rand -base64 32>"
baseUrl: "https://revaulter.example.com"
```

Then start the server with `docker compose up`, open the web UI, and create your first account.

## Full setup instructions

See [Installing Revaulter](/docs/installing-revaulter) for more details on how to install and run Revaulter.
