# Revaulter

**🛡️ Encrypt and decrypt with passkeys**

Revaulter uses WebAuthn passkeys to protect cryptographic operations. Data is encrypted end-to-end: your encryption keys live in the browser, derived from your passkey, and the server never sees the key or the plaintext. When a CLI or script needs to encrypt or decrypt something, the passkey holder confirms the operation from a web app, and the browser performs the crypto locally.

![Example of a notification sent by Revaulter (to a Discord chat)](/notification-example.png)

## How it works

1. A CLI or script submits an encrypt or decrypt request to Revaulter
2. The passkey holder gets notified (Discord, Slack, or a webhook)
3. They open the web app, authenticate with their passkey, and review the request
4. On approval, the browser derives the key from the passkey and performs the crypto operation locally
5. The CLI receives the encrypted result and decrypts it locally

The Revaulter server is just a relay. Encryption keys are derived from the passkey in the browser, they never leave the user's device. The server stores only opaque, end-to-end encrypted envelopes.

## Usage examples

### Encrypt and decrypt any message

Protect sensitive data with your passkey. Use `revaulter-cli` to encrypt a value, and the passkey holder confirms the operation from their browser:

```bash
MESSAGE=$(echo -n 'my secret message' | base64)
REQUEST_KEY="AbCdEf0123456789GhIj"

# Encrypt
revaulter-cli encrypt \
  --server https://revaulter.example.com \
  --request-key $REQUEST_KEY \
  --key-label my-secret \
  --algorithm A256GCM \
  --value "$MESSAGE"

# Decrypt
revaulter-cli decrypt \
  --server https://revaulter.example.com \
  --request-key $REQUEST_KEY \
  --key-label my-secret \
  --algorithm A256GCM \
  --value <ciphertext> --nonce <nonce> --tag <tag>
```

### Wrap encryption keys safely

Use Revaulter to wrap (encrypt) database encryption keys, TLS private keys, or any other key material. The wrapped key can be stored alongside the data it protects, only someone with the right passkey can unwrap it.

For example, you can use Revaulter together with age to encrypt large files: [see full example](./docs/06-examples.md#encrypting-large-files-with-age-and-revaulter) in the docs.

### Unlock encrypted disks at boot

Integrate Revaulter into your boot process to unlock LUKS/dm-crypt volumes. A script calls `revaulter-cli decrypt` to retrieve the disk encryption key, and an admin authenticates with their passkey to release it. No unattended keys on disk. [See full example](./docs/06-examples.md#unlocking-luks-encrypted-drives-at-boot) in the docs

## Key features

- **Passkey-derived keys** — encryption keys are derived from WebAuthn passkeys (with PRF support) directly in the browser; the server never has access to them
- **End-to-end encryption** — all cryptographic operations happen in the user's browser using WebCrypto; the server stores only opaque, encrypted envelopes
- **Self-hosted** — runs on your infrastructure; you own your data and keys
- **Webhook notifications** — get notified on Discord, Slack, or any webhook endpoint when a request is waiting
- **Lightweight** — single binary, single container; requires only a database (SQLite or PostgreSQL)
- **Strong cryptography** — includes support for quantum-resistant asymmetric cryptography

## Quick start

Run Revaulter with Docker:

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

Then start the server, open the web UI, and create your first account.

## Documentation

- [What is Revaulter](./docs/01-what-is-revaulter.md) — how it works, security model, webhooks
- [Installing Revaulter](./docs/02-installing-revaulter.md) — Docker setup, configuration reference, Docker Compose and Podman examples
- [Using the CLI](./docs/03-revaulter-cli.md) — commands, flags, and examples
- [Cryptography architecture](./docs/04-crypto-architecture.md) — key layers, wrapping, derivation, transport encryption
- [REST API reference](./docs/05-rest-api-reference.md) — all endpoints with request/response schemas
- [Examples](./docs/06-examples.md) — LUKS disk unlock at boot, encrypting files with age

## License

See [LICENSE](./LICENSE).
