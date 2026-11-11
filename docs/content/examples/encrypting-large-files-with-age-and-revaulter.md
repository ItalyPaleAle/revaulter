---
title: "Encrypting large files with age and Revaulter"
weight: 34
---

[age](https://github.com/FiloSottile/age) is a file encryption tool. You can use Revaulter to wrap the age private key, so that decrypting files requires passkey approval.

## Setup

1. Generate an age keypair:

    ```bash
    age-keygen -o age-key.txt
    ```

    This creates a file containing the private key (`AGE-SECRET-KEY-...`) and a comment with the public key (`age1...`). Note the public key: you'll use it for encryption.

2. Wrap the age private key with Revaulter, and save the result:

    ```bash
    revaulter-cli encrypt \
      --server https://revaulter.example.com \
      --request-key AbCdEf0123456789GhIj \
      --key-label age-key \
      --algorithm A256GCM \
      --input age-key.txt \
      > age-key-wrapped.json
    ```

3. Approve the request in the Revaulter web UI. The CLI writes the wrapped key to `age-key-wrapped.json`.

4. Securely delete the plaintext age key:

    ```bash
    shred -u age-key.txt
    ```

You now have:

- The age **public key** (`age1...`), which is safe to store anywhere and is used for encryption
- The age **private key**, wrapped by Revaulter (`age-key-wrapped.json`), which can't be used without passkey approval

## Encrypting a file

Anyone with the public key can encrypt, without involving Revaulter:

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

# Unwrap the age private key, which requires passkey approval, and pass it to age
revaulter-cli decrypt \
    --server "$REVAULTER_SERVER" \
    --request-key "$REQUEST_KEY" \
    --json "$WRAPPED_KEY" \
    --format raw \
    --note "age decrypt" \
  | age \
    --decrypt \
    -i - \
    -o backup.tar \
    backup.tar.age
```

## Why this pattern works

- **Encryption is unattended**: anyone with the age public key can encrypt files without Revaulter.
- **Decryption requires approval**: the age private key is wrapped by Revaulter, so decrypting always requires a passkey holder to approve.
- **The private key is never on disk in plaintext** (after the initial setup): it's stored only in Revaulter's encrypted envelope, and exists in memory only briefly during decryption.
- **age handles the content encryption**: age is designed to encrypt large files efficiently and Revaulter protects only the small private key.
