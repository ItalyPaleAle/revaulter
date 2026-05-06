---
title: "Encrypting large files with age and Revaulter"
weight: 33
---

[age](https://github.com/FiloSottile/age) is a file encryption tool. You can use Revaulter to wrap the age private key so that decrypting files requires passkey approval.

## Setup

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

## Encrypting a file

Anyone with the public key can encrypt. No Revaulter interaction is needed:

```bash
age -r age1xxxxxxxxxxxxxxxxx \
  -o backup.tar.age \
  backup.tar
```

## Decrypting a file

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

## Why this pattern works

- **Encryption is unattended**: anyone with the age public key can encrypt files without Revaulter.
- **Decryption requires approval**: the age private key is wrapped by Revaulter, so decrypting always requires a passkey holder to approve.
- **The private key never lives on disk in plaintext** (after initial setup): it is stored only in Revaulter's encrypted envelope and briefly materialized in memory or a temporary file during decryption.
- **age handles the heavy lifting**: age is designed for encrypting large files efficiently; Revaulter protects only the small private key.
