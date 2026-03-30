# Interacting with Revaulter using the CLI (v2)

The Revaulter CLI (`revaulter-cli`) submits v2 crypto requests and waits for approval/results.

## Flow

1. The CLI submits a request to `/v2/request/[operation]`.
2. Revaulter stores the request and notifies users.
3. A user approves in the browser.
4. The browser performs the crypto operation locally and encrypts the result to the CLI.
5. The CLI receives the encrypted response envelope and decrypts it locally.

## Commands

- `revaulter-cli encrypt`
- `revaulter-cli decrypt`

## Common flags

Required:

- `--server`
- `--target-user`
- `--key-label`
- `--algorithm` (currently `aes-gcm-256`)

Optional:

- `--secret-key` (for server-side `requestKey` protection)
- `--timeout`
- `--note`
- `--insecure`
- `--no-h2c`

## Example: encrypt

```bash
revaulter-cli encrypt \
  --server https://revaulter.example.com \
  --target-user alice \
  --key-label boot-disk \
  --algorithm aes-gcm-256 \
  --value SGVsbG8
```

## Example: decrypt

```bash
revaulter-cli decrypt \
  --server https://revaulter.example.com \
  --target-user alice \
  --key-label boot-disk \
  --algorithm aes-gcm-256 \
  --value <base64-ciphertext> \
  --nonce <base64-nonce> \
  --tag <base64-tag>
```

## Output

The CLI prints JSON after decrypting the response envelope locally. If a request is denied, canceled, expired, or otherwise fails, the CLI exits with an error.
