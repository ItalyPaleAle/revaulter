---
title: "Issuing a long-lived JWT"
weight: 38
---

Sometimes a service needs a JWT that lives for hours or days: for example, a service-to-service credential, an installer license, or a break-glass admin token. Revaulter's `sign --format jws` makes issuing one a passkey-approved operation: the issuing host never holds the signing key, and the maintainer approves each token.

## Setup

Publish an ES256 signing key as in the [release manifest example](/examples/signing-a-release-manifest-with-jws/). Note the key ID, and add it to the JWS protected header as `kid`, so verifiers can find the matching public key.

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

The maintainer sees the request in the web UI, with the key label and the note. The browser receives only a digest of the token, not the claims, so use the note to say what the token is for. Once they approve, the CLI writes a compact JWS to `agent-prod-42.jwt`. Hand it to whoever needs it.

## Verifying

Any standard JOSE library verifies the token using the published JWK. See [Fetching a public key to verify a signature](/examples/fetching-a-public-key-to-verify-a-signature/) for the verifier side.

## Why this pattern works

- **The signing key is offline**: it's derived from the maintainer's passkey, so nothing on the issuing host can create a token without approval.
- **Every token is approved**: each token needs the maintainer's approval, which is recorded in the audit log.
- **Standard verification**: the token is a plain compact JWS with `alg=ES256` and an embedded `kid`, so consumers verify it like any other JWT.
- **No long-lived signing infrastructure**: there's no HSM, no KMS account, no `AWS_ACCESS_KEY_ID` to rotate.
