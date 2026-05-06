---
title: "Issuing a long-lived JWT"
weight: 37
---

Sometimes a service needs a JWT that lives for hours or days: for example, a service-to-service credential, an installer license, or a break-glass admin token. Revaulter's `sign --format jws` makes this a passkey-approved operation: the issuing host never holds the signing key, and the maintainer reviews the exact claims before approving.

## Setup

Publish an ES256 signing key as in the [release manifest example](/examples/signing-a-release-manifest-with-jws/). Note the key ID: embed it in the JWS protected header as `kid` so verifiers can locate the matching public key.

## Issuing the token

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

## Verifying

Any standard JOSE library verifies the token using the published JWK. See [Fetching a public key to verify a signature](/examples/fetching-a-public-key-to-verify-a-signature/) for the verifier side.

## Why this pattern works

- **The signing key is offline**: it lives in the maintainer's passkey, derived from their passkey; nothing on the issuing host can mint a token without approval.
- **Maintainer reviews claims**: the JWS payload is the claims JSON itself, so the in-browser preview shows exactly what's about to be signed (`iss`, `sub`, `exp`, scopes…).
- **Standard verification**: the token is a plain compact JWS with `alg=ES256` and an embedded `kid`: consumers verify it like any other JWT.
- **No long-lived signing infrastructure**: there's no HSM, no KMS account, no `AWS_ACCESS_KEY_ID` to rotate.
