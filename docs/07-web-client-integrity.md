# Verifying the web client's integrity

Revaulter's browser-based web client handles sensitive operations with WebCrypto: it derives keys, encrypts plaintext, and shows approval prompts. If a compromised server, or a proxy sitting between the server and your browser, replaced one of those JavaScript files with a malicious version, it could silently exfiltrate plaintext before the end-to-end encrypted envelope is ever built.

Revaulter ships with an out-of-band way to detect this tampering: **signed asset manifests**, verifiable with `revaulter-cli check` against Sigstore's public infrastructure.

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

At release time, the GitHub Actions release workflow:

1. Builds the web client (`client/web/dist/`).
2. Hashes every file and writes a **plain-text manifest** (`path|size|sha256` per line, plus version/commit/build-date headers).
3. Signs the manifest bytes with **cosign keyless**. The signer's identity is the release workflow itself, recorded in Sigstore's **Rekor** transparency log.
4. Embeds both the manifest and the cosign bundle into the server binary via `//go:embed`.

At verification time, `revaulter-cli check`:

1. Fetches `GET /info` to read the server's version, commit, and whether it has an integrity manifest at all.
2. Fetches `GET /info/integrity` to retrieve the signed manifest + cosign bundle.
3. Verifies the cosign signature against **Sigstore infrastructure roots embedded in the CLI binary**:
   - The signing cert chains to Fulcio's root CA;
   - Its subject matches this repo's release workflow on a tag or another ref baked into the CLI build;
   - Its Rekor transparency-log entry is genuine.
4. Asserts the manifest's version and commit match the server's `/info` response (downgrade protection).
5. `GET`s every file listed in the manifest from the server, hashes it, compares to the manifest. Any mismatch → non-zero exit with the offending paths.

If any of those steps fails, you have evidence that either the server binary has been swapped, the assets have been replaced after install, or a proxy is rewriting responses in-flight.

## Trust model

Cosign keyless has **no persistent per-release signing key**. Each signing operation uses an ephemeral keypair whose public half is bound to the workflow's OIDC identity by a short-lived Fulcio-issued X.509 certificate; the private half is immediately discarded. The public key that verifies a release lives *inside the cosign bundle*, inside a cert signed by Fulcio.

What the CLI embeds is therefore **not** a signing key — it's Sigstore's stable infrastructure trust roots:

| Embedded material | What it verifies |
|---|---|
| Fulcio root CA | That the ephemeral signing cert was issued by Fulcio to a caller presenting a GitHub OIDC token |
| Rekor public key | That the log entry's Signed Entry Timestamp (SET) is genuinely from Rekor |
| Certificate Transparency log keys | That Fulcio's cert issuance was CT-logged (detects Fulcio misbehavior) |

These roots rotate rarely (on the order of years) under Sigstore's TUF-managed trust process with long overlap windows. One CLI binary therefore verifies past, present, and future releases.

The CLI's identity policy pins the signature to *this repo's* release workflow:

- Issuer: `https://token.actions.githubusercontent.com`
- Subject regex: `^https://github\.com/ItalyPaleAle/revaulter/\.github/workflows/release\.yaml@refs/(${SIGNING_REF_PATTERN})$`

A signature from any other workflow, repo, or branch is rejected.

## When a manifest is and isn't signed

| Build trigger | Manifest behavior |
|---|---|
| Tag push (`v*`) | **Always** signed. |
| Configured release-branch push whose head commit carries a `Sign-Web-Client` trailer in its commit message | Signed. |
| Configured release-branch push without that trailer | **Not** signed — server reports `hasIntegrity: false`. |
| Other branches, PR builds, local dev builds | Not signed. |

The trailer convention is the same one used for `Co-Authored-By`: a standalone line at the end of the commit message, parsed by `git interpret-trailers --parse`. Example commit message:

```text
Fix navigation overflow on small screens

Description of the fix...

Sign-Web-Client: yes
```

The content after the colon is ignored — any value is accepted.
The trailer's presence alone is the gate.
The exact ref regex is injected into the CLI at build time from the release workflow.

## What the `check` command does *not* protect against

- **The CLI binary itself being compromised.** That's covered by a separate layer: the CLI is published with SLSA provenance (`attest-build-provenance`) and can be verified with `gh attestation verify`. If you don't trust your CLI, no integrity check it reports is meaningful.
- **Browser-side runtime protection for normal users.** `check` is an operator/auditor tool, not a browser plugin. Real users visiting the UI have no way to run it.
- **Files outside `client/web/dist/`.** The Go server binary itself is attested separately by the release workflow (`attest-build-provenance`) and can be verified with `gh attestation verify`. The web client manifest covers only what the browser loads.
- **Server-side code behavior.** Correct assets running on a correct server are still only as trustworthy as the server's encryption protocol (documented in [04-crypto-architecture.md](./04-crypto-architecture.md)).

## Running from Docker

```bash
docker run --rm ghcr.io/italypaleale/revaulter-cli:2 check \
  --server https://revaulter.example.com
```

## Flags

| Flag | Short | Required | Description |
|------|-------|----------|-------------|
| `--server` | `-s` | Yes | Address of the Revaulter server to check |
| `--timeout` | `-t` | No | Overall timeout for the check (e.g. `60s`, `2m`); defaults to 60s |
| `--insecure` | | No | Skip TLS certificate validation (not recommended) |
| `--no-h2c` | | No | Do not attempt HTTP/2 Cleartext when the server is on plain HTTP |
| `--verbose` | `-V` | No | Show debug-level logs, including per-file OK messages |

## Exit codes

- **0** — integrity verified (signature, identity, Rekor entry, file hashes all match).
- **non-zero** — verification failed. See stderr for specifics. Common causes:
  - `hasIntegrity: false` on `/info` — the server is a dev/canary build without an embedded manifest.
  - Signature identity mismatch — the signing workflow is not this repo's release workflow.
  - File hash mismatch — the listed paths differ from what the signed manifest records. This is the signal of interest.
  - Manifest version/commit don't match `/info` — possible downgrade or binary swap.

## When to run it

- After installing or upgrading a Revaulter server, as an acceptance check.
- Periodically from a scheduled job, to catch silent replacement of server assets.
- Before trusting a new Revaulter instance you didn't set up yourself.
- As part of incident response if you suspect the server was compromised.

## Refreshing the CLI's trust roots

The Sigstore trust roots embedded in the CLI occasionally rotate. When a new CLI release ships with an updated copy, older CLIs continue verifying existing releases that were signed during their trust-root's validity window, but may eventually fail to verify *new* releases signed after a trust-root rotation. When that happens, upgrade the CLI.
