---
title: "Verifying the web client's integrity"
weight: 43
---

Revaulter's web client handles the sensitive operations in your browser: it derives keys, encrypts plaintext, and shows approval prompts. If a compromised server, or a proxy between the server and your browser, replaced one of its JavaScript files with a malicious version, that file could silently steal plaintext before it's ever encrypted.

Revaulter includes a separate way to detect this tampering: **signed asset manifests**, which you can verify with `revaulter-cli check` against Sigstore's public infrastructure.

## TL;DR

```bash
revaulter-cli check --server https://revaulter.example.com
```

A successful run looks like:

```text
Signature verified subject=https://github.com/ItalyPaleAle/revaulter/.github/workflows/release.yaml@refs/tags/v2.1.0 issuer=https://token.actions.githubusercontent.com
Integrity verified: version 2.1.0 (commit abc1234), 42 files
```

A failing run reports the specific file(s) that differ from the signed manifest and exits non-zero.

## What it actually checks

**At release/build time**, the GitHub Actions release workflow:

1. Builds the web client (`client/web/dist/`).
2. Hashes every file and writes a **plain-text manifest**, with one `path|size|sha256` line per file, plus headers for the version, commit, and build date.
3. Signs the manifest bytes with **cosign keyless**. The signer's identity is the release workflow itself, recorded in Sigstore's **Rekor** transparency log.
4. Embeds both the manifest and the cosign bundle into the server binary.

**At verification time**, `revaulter-cli check`:

1. Fetches `GET /info` to read the server's version, commit, and whether it has an integrity manifest at all
2. Fetches `GET /info/integrity` to retrieve the signed manifest and cosign bundle
3. Verifies the cosign signature against the Sigstore trust roots embedded in the CLI binary:
   - the signing certificate chains to Fulcio's root CA
   - its subject matches Revaulter's release workflow, running on a tag or on another ref set when the CLI was built (such as the `main` branch for edge builds)
   - its Rekor transparency log entry is genuine
4. Checks that the manifest's version and commit match the server's `/info` response
5. Fetches every file listed in the manifest from the server, hashes it, and compares it to the manifest. On any mismatch, it prints the paths that differ and exits with a non-zero status code.
6. Compares the server's version with the CLI's own version, and with `--min-version` if you set it (see [Older releases](#older-releases))

If any of those steps fails, you have evidence that the server binary was swapped, the assets were replaced after install, or a proxy is rewriting responses in transit.

## Older releases

A signature only proves that a release is genuine, not that it's the latest one. A compromised server can pass the check by serving an older release that was genuinely signed, for example one with a known vulnerability.

To help catch this, `revaulter-cli check` prints a warning when the server runs an older release than the CLI itself.

To make the check fail instead, pass the oldest version you're willing to accept:

```bash
revaulter-cli check --server https://revaulter.example.com --min-version 2.9.0
```

## Trust model

Cosign keyless has no long-lived signing key. Each signing operation uses a new, temporary key pair. Fulcio issues a short-lived X.509 certificate for its public key, which records the workflow's OIDC identity, and the private key is discarded right after signing. The public key that verifies a release is *inside the cosign bundle*, in a certificate signed by Fulcio.

What the CLI embeds is therefore not a signing key, but Sigstore's stable infrastructure trust roots:

| Embedded material | What it verifies |
| --- | --- |
| Fulcio root CA | That Fulcio issued the temporary signing certificate to a caller presenting a GitHub OIDC token |
| Rekor public key | That the log entry's Signed Entry Timestamp (SET) is genuinely from Rekor |
| Certificate Transparency log keys | That Fulcio recorded the certificate in a Certificate Transparency log (detects Fulcio misbehavior) |

These roots change rarely (every few years), through Sigstore's TUF-managed process with long overlap periods. So a CLI binary can verify releases made long before and after it was built (see [Refreshing the CLI's trust roots](#refreshing-the-clis-trust-roots)).

The CLI accepts only signatures from Revaulter's release workflow:

- Issuer: `https://token.actions.githubusercontent.com`
- Subject regex: `^https://github\.com/ItalyPaleAle/revaulter/\.github/workflows/release\.yaml@refs/(${SIGNING_REF_PATTERN})$`, where `SIGNING_REF_PATTERN` matches release tags and the branches set when the CLI was built

A signature from any other workflow, repository, or branch is rejected.

## When a manifest is and isn't signed

| Build trigger | Manifest behavior |
| --- | --- |
| Tag push (`v*`) | **Always** signed. |
| Configured release-branch push whose head commit carries a `Sign-Web-Client` trailer in its commit message | Signed. |
| Configured release-branch push without that trailer | **Not** signed: the server reports `hasIntegrity: false`. |
| Other branches, PR builds, local dev builds | Not signed. |

The trailer works like `Co-Authored-By`: a separate line at the end of the commit message, parsed by `git interpret-trailers --parse`. For example:

```text
Fix navigation overflow on small screens

Description of the fix...

Sign-Web-Client: yes
```

## What the `check` command does *not* protect against

- **A compromised CLI binary.** That's covered separately: the CLI is published by GitHub Actions with SLSA provenance, which you can verify with `gh attestation verify`. If you don't trust your CLI, its integrity checks mean nothing.
- **Protection in users' browsers.** `check` is a tool for operators and auditors, not a browser extension. Users visiting the web UI can't run it. It also can't detect browser extensions that change how the page behaves, or other scripts injected into the page while it runs.
- **A compromised server binary.** The release workflow attests the server binary separately, and you can verify it with `gh attestation verify`. The web client manifest covers only what the browser loads.
- **Weaknesses in the protocol.** Unmodified assets on an unmodified server are only as trustworthy as Revaulter's encryption protocol, described in [Cryptography architecture](/docs/crypto-architecture/).

## Running from Docker

```bash
docker run --rm ghcr.io/italypaleale/revaulter-cli:2 check \
  --server https://revaulter.example.com
```

## Flags

| Flag | Short | Required | Description |
| --- | --- | --- | --- |
| `--server` | `-s` | Yes | Address of the Revaulter server to check |
| `--timeout` | `-t` | No | Overall timeout for the check (e.g. `60s`, `2m`); defaults to 60s |
| `--min-version` | | No | Fail if the server runs a release older than this version (e.g. `x.y.z`) |
| `--no-rekor-fallback` | | No | Don't query the Rekor transparency log when the signature bundle can't be verified on its own |
| `--insecure` | | No | Skip TLS certificate validation (not recommended) |
| `--no-h2c` | | No | Do not attempt HTTP/2 Cleartext when the server is on plain HTTP |
| `--verbose` | `-V` | No | Show debug-level logs, including per-file OK messages |

## Exit codes

- **0**: integrity verified (the signature, identity, Rekor entry, and file hashes all match).
- **Non-zero**: verification failed. See stderr for details. Common causes:
  - `hasIntegrity: false` on `/info`: the server is a development build without an embedded manifest.
  - Signature identity mismatch: the manifest wasn't signed by Revaulter's release workflow.
  - File hash mismatch: the listed files differ from what the signed manifest records. This is the tampering the check looks for.
  - Manifest version or commit doesn't match `/info`: possible downgrade or binary swap.
  - With `--min-version` set, the server runs an older release or a build that isn't a release.

## When to run it

- After installing or upgrading a Revaulter server, as an acceptance check.
- Periodically from a scheduled job, to catch silent replacement of server assets.
- Before trusting a new Revaulter instance you didn't set up yourself.
- As part of incident response if you suspect the server was compromised.

## Refreshing the CLI's trust roots

The Sigstore trust roots embedded in the CLI change occasionally, and new CLI releases include the updated roots. Older CLIs keep verifying releases signed while their trust roots were valid, but may fail to verify *new* releases signed after a change. When that happens, upgrade the CLI.
