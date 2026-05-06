---
title: "Encrypt, decrypt, and sign with passkeys"
nav_title: "Introduction"
weight: 11
source_path: "README.md"
---

Encryption keys and signing keys don't belong in environment variables or on disk. Revaulter keeps them in your passkey: scripts submit a request with the CLI, you approve it in your browser with a passkey, and the browser performs the crypto locally. Everything is End-to-End Encrypted (E2EE) between the CLI and your browser.

**What you can use Revaulter for:**

- [Encrypt/decrypt messages, secrets, keys](/examples/encrypt-and-decrypt-short-messages)
- [Unlock encrypted disks at boot](/examples/unlocking-luks-encrypted-drives-at-boot)
- [Protect backup repository passwords](/examples/backing-up-with-restic)
- [SSH logins with a passkey-backed SSH agent](/examples/authenticate-to-ssh-servers)
- [Sign release binaries from CI](/examples/signing-a-release-binary-from-github-actions)
- [Issue long-lived JWTs](/examples/issuing-a-long-lived-jwt)
- [Encrypt/decrypt very large files with age and Revaulter](/examples/encrypting-large-files-with-age-and-revaulter)

{{< figure light="docs/img/readme-screenshot-light.png" dark="docs/img/readme-screenshot-dark.png" alt="Screenshot of Revaulter, showing 3 requests pending approval: one for encrypting, one for signing, one for decrypting" resize="1200x webp q80" >}}

Revaulter is [fully open source](https://github.com/ItalyPaleAle/revaulter) and released under a permissive MIT license.

## How it works

1. A CLI or script submits an encrypt or decrypt request to Revaulter
2. The passkey holder gets notified (Discord, Slack, or a webhook)
3. They open the web app, authenticate with their passkey, and review the request
4. On approval, the browser derives the key from the passkey and performs the crypto operation locally
5. The CLI receives the encrypted result and decrypts it locally

Encryption keys are derived from the passkey in the browser (leveraging the PRF extension), they never leave the user's device. The Revaulter server is just a relay: it temporarily stores only opaque, end-to-end encrypted envelopes.

![Example of a notification sent by Revaulter to a Discord channel](/docs/img/notification-example.webp)

## Key features

- **Passkey-derived keys** — encryption keys are derived from WebAuthn passkeys (with PRF) directly in the browser; the server never has access to them
- **End-to-end encryption** — all cryptographic operations happen in the user's browser using WebCrypto, the server stores only opaque, encrypted envelopes
- **Self-hosted** — runs on your infrastructure, you own your data and keys
- **Webhook notifications** — get notified on Discord, Slack, or any webhook endpoint when a request is waiting
- **Lightweight** — single binary, requires only a database (SQLite or PostgreSQL)
- **Strong cryptography** — includes support for hybrid, quantum-resistant asymmetric cryptography
