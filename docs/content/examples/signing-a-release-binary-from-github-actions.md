---
title: "Signing a release binary from GitHub Actions"
weight: 37
---

You can add `revaulter-cli sign` to a GitHub Actions release workflow to sign release binaries (or archives, container manifests, and more) without exposing the signing key to the runner. The signing key is derived from the maintainer's passkey, and the workflow waits until the maintainer approves on their phone.

## Setup

1. Sign in to the Revaulter web UI, open **Settings → Signing keys**, and publish an ES256 signing key with a label like `release-signing`. Note the key ID: verifiers fetch the public key from `https://revaulter.example.com/v2/signing-keys/<KEY_ID>.pem`.  
  See [Fetching a public key to verify a signature](/examples/fetching-a-public-key-to-verify-a-signature/) for the verifier flow.
2. In the Revaulter web UI, open **Settings → Request auth**, enable **OIDC tokens**, and add a trusted issuer. The workflow authenticates with the OIDC token GitHub Actions issues to each job, so there's no request key to store in the repository. See [Authenticating with OIDC tokens](/docs/oidc-authentication/) for details.
    - **Issuer**: `https://token.actions.githubusercontent.com`
    - **Audience**: the public URL of your Revaulter server, such as `https://revaulter.example.com`
    - **Subject**: `repo:<owner>/<repo>:environment:release`, replacing `<owner>/<repo>` with your repository. This only accepts jobs that use the `release` environment, which you can protect with [deployment protection rules](https://docs.github.com/en/actions/deployment/targeting-different-environments/using-environments-for-deployment)
3. On the same page, copy your **User ID**. If you don't use the request key anywhere else, you can also disable **Request key**.
4. In the GitHub repository, create an environment called `release`, and add the following as repository or environment variables:
    - `REVAULTER_SERVER`: the public URL of your Revaulter server
    - `REVAULTER_USER_ID`: your Revaulter user ID

## Workflow

```yaml
name: release
on:
  push:
    tags: ['v*']

jobs:
  build-and-sign:
    runs-on: ubuntu-latest
    environment: release
    permissions:
      # Required to request the OIDC token
      id-token: write
      # Required to create the release
      contents: write
    steps:
      - uses: actions/checkout@v7
      - uses: actions/setup-go@v6
        with: { go-version: '1.27.4' }

      - name: Build
        run: |
          GOOS=linux GOARCH=amd64 go build -o dist/myapp-linux-amd64 ./cmd/myapp

      - name: Install revaulter-cli
        env:
          GH_TOKEN: ${{ github.token }}
          # Set this, e.g. "2.2.0"
          REVAULTER_VERSION: ''
        run: |
          archive="revaulter-${REVAULTER_VERSION}-linux-amd64.tar.gz"
          curl -fsSLO "https://github.com/ItalyPaleAle/revaulter/releases/download/v${REVAULTER_VERSION}/${archive}"

          # Check the build provenance before trusting the binary
          gh attestation verify "${archive}" --repo ItalyPaleAle/revaulter

          tar -xzf "${archive}"
          sudo install -m 0755 \
            "revaulter-${REVAULTER_VERSION}-linux-amd64/revaulter-cli" \
            /usr/local/bin/revaulter-cli

      - name: Sign the binary (waits for passkey approval)
        env:
          REVAULTER_SERVER: ${{ vars.REVAULTER_SERVER }}
          REVAULTER_USER_ID: ${{ vars.REVAULTER_USER_ID }}
        run: |
          # Request an OIDC token for the Revaulter server
          token="$(curl -sSf \
            -H "Authorization: Bearer ${ACTIONS_ID_TOKEN_REQUEST_TOKEN}" \
            "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=${REVAULTER_SERVER}" | jq -r .value)"
          echo "::add-mask::${token}"

          revaulter-cli sign \
            --server "$REVAULTER_SERVER" \
            --request-key "$token" \
            --user-id "$REVAULTER_USER_ID" \
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

> To use a static request key instead of an OIDC token, keep **Request key** enabled in Revaulter, store the key in a `REVAULTER_REQUEST_KEY` repository secret, and pass it with `--request-key "${{ secrets.REVAULTER_REQUEST_KEY }}"` instead of requesting a token.

The workflow pauses on the `revaulter-cli sign` step until the maintainer approves the request from their phone.

The CLI hashes the binary with SHA-256, sends only the 32-byte digest end-to-end, gets back the raw `r || s` ECDSA signature, and writes it to a sidecar `.sig` file alongside the binary.

## Verifying

Anyone who has pinned the public key (see [Fetching a public key to verify a signature](/examples/fetching-a-public-key-to-verify-a-signature/)) can verify the binary without contacting Revaulter. The signature is 64 bytes of raw `r || s`, with no DER encoding or JWS wrapper.

## Why this pattern works

- **The signing key is never on the runner**: there's no key file, no secret variable to leak, and no service account to compromise.
- **No long-lived credentials**: the OIDC token identifies this repository and environment, and expires within minutes.
- **Every release requires a live human**: a hostile push can't ship a signed binary without passkey approval.
- **Self-contained sidecar**: the `.sig` file is only 64 bytes, and you can attach it to any release page or host it on a CDN.
- **Standard primitive**: ES256 is a standard algorithm, so existing verification tools work. Some need the signature converted to DER first, as shown in the verification examples.
