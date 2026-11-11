---
title: "Encrypt and decrypt short messages"
weight: 31
---

Use Revaulter to encrypt and decrypt short sensitive values, with passkey approval. This works well for secrets small enough to send to the browser, which performs the operation locally: database connection strings, TLS private keys, API tokens, repository passwords, and keys for other systems.

The **payload limit is 100 KB**.  
For larger files or messages, use Revaulter to wrap a file encryption key instead. See [Encrypting large files with age and Revaulter](/examples/encrypting-large-files-with-age-and-revaulter).

## Encrypt a message

Pipe the message into Revaulter and submit an encrypt request:

```bash
REQUEST_KEY="AbCdEf0123456789GhIj"

echo -n 'my secret message' \
  | revaulter-cli encrypt \
    --server https://revaulter.example.com \
    --request-key "$REQUEST_KEY" \
    --key-label my-secret \
    --algorithm A256GCM \
    --input - \
  > message.wrapped.json
```

Approve the request in the Revaulter web UI. The CLI writes a JSON envelope with the ciphertext, nonce, and tag. Store that envelope wherever the encrypted secret needs to live.

## Decrypt a message

Pass the JSON envelope to `revaulter-cli decrypt`. It includes the key label and algorithm, so you don't need to pass them again:

```bash
revaulter-cli decrypt \
  --server https://revaulter.example.com \
  --request-key "$REQUEST_KEY" \
  --json message.wrapped.json \
  --format raw
```

The passkey holder approves the request in the browser, and the CLI writes the decrypted plaintext to stdout.
