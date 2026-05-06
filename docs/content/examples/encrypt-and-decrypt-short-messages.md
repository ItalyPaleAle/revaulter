---
title: "Encrypt and decrypt short messages"
weight: 31
---

Use Revaulter to encrypt and decrypt short sensitive values with passkey approval. This works well for secrets that are small enough to send to the browser for local cryptographic processing, including database connection strings, TLS private keys, API tokens, repository passwords, and wrapped keys for other systems.

The **payload limit is 100 KB**: Revaulter sends the encrypted request to the browser, where the passkey holder authenticates and the browser performs the operation locally.

For larger files or messages, use Revaulter to wrap a file-encryption key instead; see [Encrypting large files with age and Revaulter](/examples/encrypting-large-files-with-age-and-revaulter).

## Encrypt a message

Pipe the message into Revaulter and submit an encrypt request:

```bash
REQUEST_KEY="AbCdEf0123456789GhIj"

echo -n 'my secret message'
  | revaulter-cli encrypt \
    --server https://revaulter.example.com \
    --request-key "$REQUEST_KEY" \
    --key-label my-secret \
    --algorithm A256GCM \
    --input - \
  > message.wrapped.json
```

Approve the request in the Revaulter web UI. The CLI returns a JSON envelope containing the ciphertext, nonce, and tag. Store that envelope wherever the wrapped secret needs to live.

## Decrypt a message

Pass the JSON envelope back to `revaulter-cli decrypt`:

```bash
revaulter-cli decrypt \
  --server https://revaulter.example.com \
  --request-key "$REQUEST_KEY" \
  --json message.wrapped.json \
  --format raw
```

The passkey holder approves the request in the browser, and the CLI writes the decrypted plaintext locally.
