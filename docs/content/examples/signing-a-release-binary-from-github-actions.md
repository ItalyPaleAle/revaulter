---
title: "Signing a release binary from GitHub Actions"
weight: 36
---

You can wire `revaulter-cli sign` into a GitHub Actions release workflow to sign release binaries (or archives, container manifests…) without exposing the signing key to the runner. The signing key lives in the maintainer's passkey, and the workflow blocks until the maintainer approves on their phone.

## Setup

1. Sign in to the Revaulter web UI, open the signing keys section, and publish an ES256 signing key under a label like `release-signing`. Note the published key ID: verifiers fetch the public half from `https://revaulter.example.com/v2/signing-keys/<KEY_ID>.pem`.  
  See [Fetching a public key to verify a signature](/examples/fetching-a-public-key-to-verify-a-signature/) for the verifier flow.
2. Add the following as GitHub repository secrets:
    - `REVAULTER_SERVER`: the public URL of your Revaulter server
    - `REVAULTER_REQUEST_KEY`: the per-user request key from your Revaulter settings page

## Workflow

```yaml
name: release
on:
  push:
    tags: ['v*']

jobs:
  build-and-sign:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
      - uses: actions/setup-go@v6
        with: { go-version: '1.26' }

      - name: Build
        run: |
          GOOS=linux GOARCH=amd64 go build -o dist/myapp-linux-amd64 ./cmd/myapp

      - name: Install revaulter-cli
        run: |
          curl -fsSL https://github.com/ItalyPaleAle/revaulter/releases/latest/download/revaulter-cli-linux-amd64 \
            -o /usr/local/bin/revaulter-cli
          chmod 0755 /usr/local/bin/revaulter-cli

      - name: Sign the binary (waits for passkey approval)
        env:
          REVAULTER_SERVER: ${{ secrets.REVAULTER_SERVER }}
          REVAULTER_REQUEST_KEY: ${{ secrets.REVAULTER_REQUEST_KEY }}
        run: |
          revaulter-cli sign \
            --server "$REVAULTER_SERVER" \
            --request-key "$REVAULTER_REQUEST_KEY" \
            --key-label release-signing \
            --algorithm ES256 \
            --input dist/myapp-linux-amd64 \
            --format raw \
            --output dist/myapp-linux-amd64.sig \
            --note "release ${{ github.ref_name }}" \
            --timeout 30m

      - uses: softprops/action-gh-release@v3
        with:
          files: |
            dist/myapp-linux-amd64
            dist/myapp-linux-amd64.sig
```

The workflow pauses on the `revaulter-cli sign` step until the maintainer approves the request from their phone. The CLI hashes the binary with SHA-256, sends only the 32-byte digest end-to-end, gets back the raw `r || s` ECDSA signature, and writes it to a sidecar `.sig` file alongside the binary.

## Verifying

Anyone who has pinned the public key (see [Fetching a public key to verify a signature](/examples/fetching-a-public-key-to-verify-a-signature/)) can verify the binary without contacting Revaulter. The signature is 64 bytes of raw `r || s` (no DER, no JWS wrapper), so verification is a one-liner with most ECDSA libraries.

## Why this pattern works

- **The signing key is never on the runner**: there's no key file, no secret variable to leak, and no service account to compromise.
- **Every release requires a live human**: a hostile push can't ship a signed binary without passkey approval.
- **Self-contained sidecar**: the `.sig` file is just 64 bytes, can be attached to any release page or CDN.
- **Standard primitive**: ES256 + raw `r || s` is the same shape Cosign and most ECDSA tooling produce, so existing verification tools work.
