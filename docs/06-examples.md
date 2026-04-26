# Examples

## Unlocking LUKS-encrypted drives at boot

You can use Revaulter to protect the encryption key for a LUKS volume. Instead of storing the key on disk or typing a passphrase at the console, a script calls `revaulter-cli` during boot and an admin approves the unlock from their phone.

### Setup

1. Generate a random key and encrypt the LUKS volume with it:

    ```bash
    dd if=/dev/urandom bs=32 count=1 | base64 > /tmp/disk-key.txt
    cryptsetup luksFormat /dev/sdX --key-file /tmp/disk-key.txt
    ```

2. Wrap the key with Revaulter:

    ```bash
    revaulter-cli encrypt \
      --server https://revaulter.example.com \
      --request-key AbCdEf0123456789GhIj \
      --key-label boot-disk \
      --algorithm A256GCM \
      --input /tmp/disk-key.txt
    ```

3. Approve the request in the Revaulter web UI. The CLI outputs a JSON envelope with the ciphertext, nonce, and tag. Save this output (for example, in `/etc/revaulter/boot-disk.json`).

4. Securely delete the plaintext key:

    ```bash
    shred -u /tmp/disk-key.txt
    ```

### Boot script

Create a script that runs early in the boot process (e.g. a systemd unit that runs before the mount target):

```bash
#!/usr/bin/env bash
set -euo pipefail

REVAULTER_SERVER="https://revaulter.example.com"
REQUEST_KEY="AbCdEf0123456789GhIj"
KEY_LABEL="boot-disk"
WRAPPED_KEY="/etc/revaulter/boot-disk.json"

# Read the wrapped key components
CIPHERTEXT=$(jq -r '.value' "$WRAPPED_KEY")
NONCE=$(jq -r '.nonce' "$WRAPPED_KEY")
TAG=$(jq -r '.tag' "$WRAPPED_KEY")

# Ask Revaulter to decrypt — an admin must approve from their browser
PLAINTEXT_KEY=$(revaulter-cli decrypt \
  --server "$REVAULTER_SERVER" \
  --request-key "$REQUEST_KEY" \
  --key-label "$KEY_LABEL" \
  --algorithm A256GCM \
  --value "$CIPHERTEXT" \
  --nonce "$NONCE" \
  --tag "$TAG" \
  --format raw \
  --note "boot unlock" \
  --timeout 10m)

# Unlock the LUKS volume
echo -n "$PLAINTEXT_KEY" | cryptsetup luksOpen /dev/sdX encrypted-root --key-file=-

# Clear the variable
unset PLAINTEXT_KEY
```

When the server boots, it pauses at this script and sends a webhook notification. The admin opens Revaulter on their phone, authenticates with their passkey, and approves the unlock. The disk key is decrypted in the admin's browser, returned to the CLI, and piped directly into `cryptsetup` — it never touches disk.

### systemd unit (optional)

```ini
[Unit]
Description=Unlock encrypted root via Revaulter
DefaultDependencies=no
Before=local-fs.target
After=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/revaulter-unlock.sh
RemainAfterExit=yes

[Install]
WantedBy=local-fs.target
```

## Encrypting large files with age and Revaulter

[age](https://github.com/FiloSottile/age) is a file encryption tool. You can use Revaulter to wrap the age private key so that decrypting files requires passkey approval.

### Setup

1. Generate an age keypair:

    ```bash
    age-keygen -o age-key.txt
    ```

    This creates a file containing both the private key (`AGE-SECRET-KEY-...`) and a comment with the public key (`age1...`). Note the public key — you will use it for encryption.

2. Wrap the age private key with Revaulter:

    ```bash
    revaulter-cli encrypt \
      --server https://revaulter.example.com \
      --request-key AbCdEf0123456789GhIj \
      --key-label age-key \
      --algorithm A256GCM \
      --input age-key.txt
    ```

3. Approve the request in the Revaulter web UI. Save the CLI output (ciphertext, nonce, tag) to a file, for example `age-key-wrapped.json`.

4. Securely delete the plaintext age key:

    ```bash
    shred -u age-key.txt
    ```

You now have:

- The age **public key** (`age1...`) — safe to store anywhere, used for encryption
- The age **private key** wrapped by Revaulter (`age-key-wrapped.json`) — cannot be used without passkey approval

### Encrypting a file

Anyone with the public key can encrypt. No Revaulter interaction is needed:

```bash
age -r age1xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx \
  -o backup.tar.age \
  backup.tar
```

### Decrypting a file

Decryption requires unwrapping the age private key through Revaulter:

```bash
#!/usr/bin/env bash
set -euo pipefail

REVAULTER_SERVER="https://revaulter.example.com"
REQUEST_KEY="AbCdEf0123456789GhIj"
WRAPPED_KEY="age-key-wrapped.json"

CIPHERTEXT=$(jq -r '.value' "$WRAPPED_KEY")
NONCE=$(jq -r '.nonce' "$WRAPPED_KEY")
TAG=$(jq -r '.tag' "$WRAPPED_KEY")

# Unwrap the age private key — requires passkey approval
revaulter-cli decrypt \
  --server "$REVAULTER_SERVER" \
  --request-key "$REQUEST_KEY" \
  --key-label age-key \
  --algorithm A256GCM \
  --value "$CIPHERTEXT" \
  --nonce "$NONCE" \
  --tag "$TAG" \
  --format raw \
  --output /dev/stdin \
  --note "age decrypt" \
  2>/dev/null \
  | age \
    --decrypt \
    -i - \
    -o backup.tar \
    backup.tar.age
```

### Why this pattern works

- **Encryption is unattended**: anyone with the age public key can encrypt files without Revaulter.
- **Decryption requires approval**: the age private key is wrapped by Revaulter, so decrypting always requires a passkey holder to approve.
- **The private key never lives on disk in plaintext** (after initial setup): it is stored only in Revaulter's encrypted envelope and briefly materialized in memory or a temporary file during decryption.
- **age handles the heavy lifting**: age is designed for encrypting large files efficiently; Revaulter protects only the small private key.

## Backing up with restic

[restic](https://restic.net) uses a single password to derive its repository encryption key. Storing that password unattended on the backup host largely defeats the point of having backups: anyone who pops the host gets the repository. Wrapping the password with Revaulter means the backup script gets the password only after a passkey holder approves.

### Setup

1. Pick a strong password and put it in a temporary file:

    ```bash
    openssl rand -base64 32 > /tmp/restic-pw
    ```

2. Initialize the repository with that password:

    ```bash
    RESTIC_PASSWORD_FILE=/tmp/restic-pw restic \
      --repo s3:s3.example.com/my-bucket \
      init
    ```

3. Wrap the password with Revaulter and save the envelope:

    ```bash
    revaulter-cli encrypt \
      --server https://revaulter.example.com \
      --request-key AbCdEf0123456789GhIj \
      --key-label restic-pw \
      --algorithm A256GCM \
      --input /tmp/restic-pw \
      > /etc/restic/pw-wrapped.json
    ```

4. Approve the request in the web UI, then shred the plaintext file:

    ```bash
    shred -u /tmp/restic-pw
    ```

### Running a backup

restic supports `--password-command`: a script that prints the repository password on stdout. Plug Revaulter into it:

```bash
#!/usr/bin/env bash
# /usr/local/bin/restic-password.sh
set -euo pipefail

revaulter-cli decrypt \
  --server https://revaulter.example.com \
  --request-key AbCdEf0123456789GhIj \
  --key-label restic-pw \
  --algorithm A256GCM \
  --json /etc/restic/pw-wrapped.json \
  --format raw \
  --note "restic backup" \
  --timeout 10m
```

Mark the script executable and run a backup:

```bash
chmod 0755 /usr/local/bin/restic-password.sh

restic \
  --password-command /usr/local/bin/restic-password.sh \
  --repo s3:s3.example.com/my-bucket \
  backup /var/data
```

restic invokes the script, the script blocks waiting for approval, the maintainer approves on their phone, and restic gets the password and runs the backup.

### Why this pattern works

- **The host can't restore on its own**: a compromised backup host cannot decrypt the repository even if the wrapped blob and the request key both leak.
- **One file to deploy**: the wrapped JSON is the only secret on the host, and it's useless without Revaulter.
- **Live audit trail**: every restore (or recurring backup) requires interactive approval, so unusual activity is visible in real time.

## Signing a release manifest with JWS

You can use Revaulter's `sign` operation with `--format jws` to produce a passkey-approved compact JWS. ES256 is a standard JOSE algorithm, so the output is verifiable by any JWT/JOSE library without any hand-rolled signature conversion.

### Setup

Sign in to the Revaulter web UI, open the signing keys section, and publish a key under a label like `release-signing`. Note the published key ID — it's the URL you'll share with verifiers:

```text
https://revaulter.example.com/v2/signing-keys/<KEY_ID>.jwk
```

### Signing a release

```bash
# Build a small JSON manifest describing the release
jq -n --arg v v1.2.3 --arg d "$(date -u +%FT%TZ)" \
  '{version:$v, releasedAt:$d, artifacts:[inputs]}' \
  <(sha256sum dist/*.tar.gz dist/*.zip) \
  > dist/manifest.json

# Produce a compact JWS
# The CLI builds the protected header, base64url-encodes manifest.json as the payload, and requests a signature — a maintainer approves in-browser.
revaulter-cli sign \
  --server https://revaulter.example.com \
  --request-key AbCdEf0123456789GhIj \
  --key-label release-signing \
  --algorithm ES256 \
  --input dist/manifest.json \
  --format jws \
  --jws-header '{"kid":"<KEY_ID>","typ":"JWT"}' \
  --output dist/manifest.jws \
  --note "release v1.2.3"
```

Publish `dist/manifest.jws` alongside the artifacts. It's self-contained: the payload (manifest) and signature are both in the JWS.

### Verifying a release

Any JOSE library works. First, fetch the published JWK:

```bash
KEY_ID="<key-id-from-publisher>"
curl -fsSL "https://revaulter.example.com/v2/signing-keys/$KEY_ID.jwk" \
  | jq '.jwk' > release-signing.jwk
```

Then verify `dist/manifest.jws` with the verifier of your choice:

<details>
<summary><strong>Python (<code>jwcrypto</code>)</strong></summary>

```bash
pip install jwcrypto

python3 - <<'PY'
import json
from jwcrypto import jwk, jws
key = jwk.JWK(**json.load(open("release-signing.jwk")))
tok = jws.JWS()
tok.deserialize(open("dist/manifest.jws").read().strip())
tok.verify(key)
print(json.loads(tok.payload))
PY
```

</details>

<details>
<summary><strong>Node.js (<a href="https://github.com/panva/jose"><code>jose</code></a>)</strong></summary>

```bash
npm install jose
```

```js
import { readFile } from 'node:fs/promises'
import { importJWK, compactVerify } from 'jose'

const jwk = JSON.parse(await readFile('release-signing.jwk', 'utf8'))
const key = await importJWK(jwk, 'ES256')
const token = (await readFile('dist/manifest.jws', 'utf8')).trim()
const { payload, protectedHeader } = await compactVerify(token, key)
console.log(protectedHeader)
console.log(JSON.parse(new TextDecoder().decode(payload)))
```

</details>

<details>
<summary><strong><a href="https://github.com/latchset/jose"><code>jose</code> CLI</strong></a></summary>

```bash
jose jws ver -i dist/manifest.jws -k release-signing.jwk -O -
```

</details>

Once the JWS verifies, you have an authenticated manifest; check the artifact hashes against it with `sha256sum -c`.

### Why this pattern works

- **The signing key never leaves the browser**: CI cannot sign on its own: each release requires a live passkey approval from a maintainer.
- **Small, fixed-size payloads**: only the 32-byte SHA-256 digest of the JWS signing input is transmitted end-to-end, regardless of artifact size.
- **Stable key ID**: the signing key is derived deterministically from the maintainer's primary key, so the published JWK (and its ID) survives passkey rotations and password changes — downstream verifiers can pin it.
- **Standard verification**: ES256 is a JOSE algorithm, so any JWT/JOSE library verifies the output out of the box.

## Signing a release binary from GitHub Actions

You can wire `revaulter-cli sign` into a GitHub Actions release workflow to sign release binaries (or archives, container manifests…) without exposing the signing key to the runner. The signing key lives in the maintainer's passkey, and the workflow blocks until the maintainer approves on their phone.

### Setup

1. Sign in to the Revaulter web UI, open the signing keys section, and publish an ES256 signing key under a label like `release-signing`. Note the published key ID: verifiers fetch the public half from `https://revaulter.example.com/v2/signing-keys/<KEY_ID>.pem`.  
  See [Fetching a public key to verify a signature](#fetching-a-public-key-to-verify-a-signature) for the verifier flow.
2. Add the following as GitHub repository secrets:
    - `REVAULTER_SERVER`: the public URL of your Revaulter server
    - `REVAULTER_REQUEST_KEY`: the per-user request key from your Revaulter settings page

### Workflow

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

### Verifying

Anyone who has pinned the public key (see [Fetching a public key to verify a signature](#fetching-a-public-key-to-verify-a-signature)) can verify the binary without contacting Revaulter. The signature is 64 bytes of raw `r || s` (no DER, no JWS wrapper), so verification is a one-liner with most ECDSA libraries.

### Why this pattern works

- **The signing key is never on the runner**: there's no key file, no secret variable to leak, and no service account to compromise.
- **Every release requires a live human**: a hostile push can't ship a signed binary without passkey approval.
- **Self-contained sidecar**: the `.sig` file is just 64 bytes, can be attached to any release page or CDN.
- **Standard primitive**: ES256 + raw `r || s` is the same shape Cosign and most ECDSA tooling produce, so existing verification tools work.

## Issuing a long-lived JWT

Sometimes a service needs a JWT that lives for hours or days: for example, a service-to-service credential, an installer license, or a break-glass admin token. Revaulter's `sign --format jws` makes this a passkey-approved operation: the issuing host never holds the signing key, and the maintainer reviews the exact claims before approving.

### Setup

Publish an ES256 signing key as in the [release manifest example](#signing-a-release-manifest-with-jws). Note the key ID: embed it in the JWS protected header as `kid` so verifiers can locate the matching public key.

### Issuing the token

Build a small claims file and sign it as a compact JWS:

```bash
KEY_ID="<key-id-from-the-published-jwk>"
ISS="https://revaulter.example.com"
SUB="agent-prod-42"
EXP=$(( $(date -u +%s) + 90 * 24 * 3600 ))   # 90 days

jq -n \
  --arg iss "$ISS" \
  --arg sub "$SUB" \
  --argjson exp "$EXP" \
  '{iss:$iss, sub:$sub, exp:$exp, scope:"agent.enroll"}' \
  > claims.json

revaulter-cli sign \
  --server https://revaulter.example.com \
  --request-key AbCdEf0123456789GhIj \
  --key-label release-signing \
  --algorithm ES256 \
  --input claims.json \
  --format jws \
  --jws-header "{\"kid\":\"$KEY_ID\",\"typ\":\"JWT\"}" \
  --output agent-prod-42.jwt \
  --note "agent-prod-42, 90d"

shred -u claims.json
```

The maintainer sees the request in the web UI: they can read the claims, approve, and the CLI writes a compact JWS to `agent-prod-42.jwt`. Hand it to whoever needs it.

### Verifying

Any standard JOSE library verifies the token using the published JWK. See [Fetching a public key to verify a signature](#fetching-a-public-key-to-verify-a-signature) for the verifier side.

### Why this pattern works

- **The signing key is offline**: it lives in the maintainer's passkey, derived from their passkey; nothing on the issuing host can mint a token without approval.
- **Maintainer reviews claims**: the JWS payload is the claims JSON itself, so the in-browser preview shows exactly what's about to be signed (`iss`, `sub`, `exp`, scopes…).
- **Standard verification**: the token is a plain compact JWS with `alg=ES256` and an embedded `kid`: consumers verify it like any other JWT.
- **No long-lived signing infrastructure**: there's no HSM, no KMS account, no `AWS_ACCESS_KEY_ID` to rotate.

## Fetching a public key to verify a signature

Revaulter exposes the public half of every published signing key on an unauthenticated, cacheable endpoint. Verifiers fetch it once, pin it locally, and from then on can verify signatures fully offline.

### The endpoint

For a published key with id `<KEY_ID>`:

- `GET /v2/signing-keys/<KEY_ID>.jwk` (or `.json`): the JWK plus an anchor-signed publication proof
- `GET /v2/signing-keys/<KEY_ID>.pem` (or `.pub`): the public key as a PEM SubjectPublicKeyInfo

Both endpoints are public and un-authenticated.

### One-time pinning

Trust-on-first-use pins the key locally. After this, verification doesn't need to trust Revaulter at runtime.

```bash
KEY_ID="<key-id-from-publisher>"

# JWK form (for JOSE/JWT libraries)
curl -fsSL "https://revaulter.example.com/v2/signing-keys/$KEY_ID.jwk" \
  | jq '.jwk' > release-signing.jwk

# PEM form (for OpenSSL, Go, Python's `cryptography`, etc.)
curl -fsSL "https://revaulter.example.com/v2/signing-keys/$KEY_ID.pem" \
  > release-signing.pem
```

Inspect the key once, then commit the file to your repo (or distribute it via your usual configuration management). From this point on, none of the verification examples below talks to Revaulter.

### Verifying a JWS or JWT

Any JOSE library works against the JWK form. See the [release-manifest JWS section](#signing-a-release-manifest-with-jws) for runnable Python, Node.js, and CLI examples.

### Verifying a raw `r || s` signature

`sign --format raw` emits a 64-byte signature. Most ECDSA libraries accept it directly:

<details>
<summary><strong>Python (<code>cryptography</code>)</strong></summary>

```bash
pip install cryptography
```

```python
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

pub = serialization.load_pem_public_key(open("release-signing.pem", "rb").read())

# Read the raw r||s bytes and convert to ASN.1 DER for cryptography's verify()
sig_raw = open("dist/myapp-linux-amd64.sig", "rb").read()
assert len(sig_raw) == 64
r = int.from_bytes(sig_raw[:32], "big")
s = int.from_bytes(sig_raw[32:], "big")
sig_der = utils.encode_dss_signature(r, s)

with open("dist/myapp-linux-amd64", "rb") as f:
    pub.verify(sig_der, f.read(), ec.ECDSA(hashes.SHA256()))

print("OK")
```

</details>

<details>
<summary><strong>Go</strong></summary>

```go
package main

import (
    "crypto/ecdsa"
    "crypto/sha256"
    "crypto/x509"
    "encoding/pem"
    "log"
    "math/big"
    "os"
)

func main() {
    pemBytes, _ := os.ReadFile("release-signing.pem")
    block, _ := pem.Decode(pemBytes)
    pubAny, _ := x509.ParsePKIXPublicKey(block.Bytes)
    pub := pubAny.(*ecdsa.PublicKey)

    body, _ := os.ReadFile("dist/myapp-linux-amd64")
    sig, _ := os.ReadFile("dist/myapp-linux-amd64.sig")
    if len(sig) != 64 {
        log.Fatal("expected 64-byte raw r||s signature")
    }
    r := new(big.Int).SetBytes(sig[:32])
    s := new(big.Int).SetBytes(sig[32:])

    digest := sha256.Sum256(body)
    if !ecdsa.Verify(pub, digest[:], r, s) {
        log.Fatal("signature verification failed")
    }
    log.Println("OK")
}
```

</details>

<details>
<summary><strong>OpenSSL (after DER conversion)</strong></summary>

OpenSSL's `dgst -verify` requires DER-encoded signatures, so wrap the raw bytes once:

```bash
python3 - <<'PY' dist/myapp-linux-amd64.sig dist/myapp-linux-amd64.sig.der
import sys
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
raw = open(sys.argv[1], "rb").read()
r = int.from_bytes(raw[:32], "big"); s = int.from_bytes(raw[32:], "big")
open(sys.argv[2], "wb").write(encode_dss_signature(r, s))
PY

openssl dgst -sha256 \
  -verify release-signing.pem \
  -signature dist/myapp-linux-amd64.sig.der \
  dist/myapp-linux-amd64
```

</details>

### Optional: full anchor-signed verification

The `.jwk`/`.json` response also carries `publicationPayload`, two anchor signatures, and the user's anchor public keys.

Verifying both anchor signatures over the canonical payload proves the same maintainer who registered with Revaulter authorized the publication of this key. Pinning the *anchor* (instead of the published JWK directly) lets the same trust survive signing-key rotations: the anchor is the user's long-lived identity root; the signing key is just a leaf.

This deeper verification matters for high-stakes deployments (auditable supply-chain metadata, multi-tenant servers); for a single-team setup, pinning the JWK once is usually enough.
