# Revaulter

Revaulter is an approval-gated cryptography relay.

Revaulter v2 performs cryptographic operations in the user's browser using WebAuthn (with PRF) and WebCrypto, then returns the result to the CLI encrypted with an ephemeral ECDH + AES-GCM transport envelope. Revaulter stores pending requests in a database and relays notifications/results, but does not perform the cryptographic operation itself.

Supported operations:

- Encrypt / decrypt

![Example of a notification sent by Revaulter (to a Discord chat)](/notification-example.png)

## How It Works

1. A CLI client submits a request to `/v2/request/*` with the operation payload and an ephemeral P-256 public key (JWK).
2. Revaulter stores the request in the database (sensitive payload encrypted at rest) and sends a webhook notification.
3. A user signs in to the web UI with WebAuthn (and optionally a password factor).
4. The browser derives the operation key, performs the crypto locally, and encrypts the result to the CLI using ECDH + AES-GCM.
5. Revaulter relays the encrypted response envelope to the CLI.
6. The CLI decrypts the envelope locally and prints the result.

## Quick Start

1. Configure `databaseDSN` and `secretKey` in `config.yaml`.
2. Configure `baseUrl` and TLS.
3. Start Revaulter.
4. Open the web UI and either sign in or create an account.
5. Use `revaulter-cli v2 ...` commands to submit requests.

## Docs

1. [Set up (v2)](./docs/01-set-up.md)
2. [Install and configure Revaulter](./docs/02-install-and-configure-revaulter.md)
3. [Using the Revaulter CLI (v2)](./docs/03-interacting-with-revaulter-cli.md)
4. [Using the REST APIs (v2)](./docs/04-using-rest-api.md)
5. [Architecture and protocol overview (v2)](./docs/05-revaulter-v2.md)
