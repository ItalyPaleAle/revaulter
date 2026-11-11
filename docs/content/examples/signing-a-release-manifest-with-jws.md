---
title: "Signing a release manifest with JWS"
weight: 36
---

You can use Revaulter's `sign` operation with `--format jws` to produce a passkey-approved compact JWS. ES256 is a standard JOSE algorithm, so any JWT or JOSE library can verify the output without converting the signature.

## Setup

Sign in to the Revaulter web UI, open **Settings → Signing keys**, and publish an ES256 key with a label like `release-signing`. Note the key ID: verifiers fetch the public key from this URL:

```text
https://revaulter.example.com/v2/signing-keys/<KEY_ID>.jwk
```

## Signing a release

```bash
# Build a small JSON manifest describing the release
jq -nR --arg v v1.2.3 --arg d "$(date -u +%FT%TZ)" \
  '{version:$v, releasedAt:$d, artifacts:[inputs]}' \
  <(sha256sum dist/*.tar.gz dist/*.zip) \
  > dist/manifest.json

# Produce a compact JWS
# The CLI builds the protected header, base64url-encodes manifest.json as the payload, and requests a signature, which a maintainer approves in the browser
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

## Verifying a release

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
<summary><strong><a href="https://github.com/latchset/jose"><code>jose</code> CLI</a></strong></summary>

```bash
jose jws ver -i dist/manifest.jws -k release-signing.jwk -O -
```

</details>

Once the JWS verifies, you have an authenticated manifest. Check the artifacts' hashes against it with `sha256sum -c`.

## Why this pattern works

- **The signing key never leaves the browser**: CI can't sign on its own, and each release needs a maintainer to approve it with a passkey.
- **Small, fixed-size payloads**: only the 32-byte SHA-256 digest of the JWS signing input is sent end-to-end, whatever the size of the artifacts.
- **Stable key ID**: the signing key is derived from the maintainer's primary key, so the published JWK and its ID stay the same when passkeys are added or removed, or the password changes. Verifiers can pin it.
- **Standard verification**: ES256 is a JOSE algorithm, so any JWT or JOSE library can verify the output.
