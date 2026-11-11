---
title: "Fetching a public key to verify a signature"
weight: 39
---

Revaulter serves the public key of every published signing key on a public, cacheable endpoint. Verifiers fetch it once and save it locally, and from then on can verify signatures offline.

## The endpoint

For a published key with ID `<KEY_ID>`:

- `GET /v2/signing-keys/<KEY_ID>.jwk` (or `.json`): the JWK plus an anchor-signed publication proof
- `GET /v2/signing-keys/<KEY_ID>.pem` (or `.pub`): the public key as a PEM SubjectPublicKeyInfo

Both endpoints are public and don't require authentication.

## One-time pinning

Save the key locally the first time you fetch it (trust on first use). After that, verification doesn't depend on Revaulter.

```bash
KEY_ID="<key-id-from-publisher>"

# JWK form (for JOSE/JWT libraries)
curl -fsSL "https://revaulter.example.com/v2/signing-keys/$KEY_ID.jwk" \
  | jq '.jwk' > release-signing.jwk

# PEM form (for OpenSSL, Go, Python's `cryptography`, etc.)
curl -fsSL "https://revaulter.example.com/v2/signing-keys/$KEY_ID.pem" \
  > release-signing.pem
```

Check the key once, then commit the file to your repository, or distribute it with your usual configuration management. None of the verification examples below contact Revaulter.

## Verifying a JWS or JWT

Any JOSE library works against the JWK form. See the [release-manifest JWS section](/examples/signing-a-release-manifest-with-jws/) for runnable Python, Node.js, and CLI examples.

## Verifying a raw `r || s` signature

For `ES256`, `sign --format raw` writes a 64-byte `r || s` signature. Some libraries accept this form directly, such as Go's `crypto/ecdsa` and WebCrypto. Others, such as Python's `cryptography` and OpenSSL, need it converted to ASN.1 DER first:

{{< tabs >}}
{{< tab title="Python" >}}

This example uses the `cryptography` package:

```bash
pip install cryptography
```

Code:

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

{{< /tab >}}

{{< tab title="Go" >}}

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

{{< /tab >}}

{{< tab title="OpenSSL" >}}
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

{{< /tab >}}
{{< /tabs >}}

For `Ed25519`, the 64-byte signature is already in the standard format, so any Ed25519 library can verify it with the public key.

## Optional: full anchor-signed verification

The `.jwk`/`.json` response also carries `publicationPayload`, two anchor signatures, and the user's anchor public keys.

Verifying both anchor signatures over the canonical payload proves that the maintainer's own Revaulter account published this key, and not a compromised server. Pinning the *anchor*, instead of the published JWK, means your trust carries over when the maintainer adds new signing keys: the anchor is the user's long-term identity, and each signing key is signed by it.

This extra verification matters for high-stakes deployments, such as auditable supply-chain metadata or shared servers. For a single team, pinning the JWK once is usually enough.
