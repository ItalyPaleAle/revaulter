# Using the Revaulter CLI

The Revaulter CLI (`revaulter-cli`) is the primary way to submit encrypt and decrypt requests.

**Using the CLI is strongly recommended** over calling the REST API directly: it handles transport key generation, end-to-end encryption, long-polling, and result decryption automatically.

## Installing the CLI

### Pre-compiled binary (recommended)

Download the latest release from [GitHub Releases](https://github.com/ItalyPaleAle/revaulter/releases). Binaries are available for Linux (`amd64`, `arm64`), macOS (`amd64`, `arm64`), and Windows.

### Docker

```bash
docker run --rm ghcr.io/italypaleale/revaulter-cli:2 <command> [flags]
```

For example:

```bash
docker run --rm ghcr.io/italypaleale/revaulter-cli:2 encrypt \
  --server https://revaulter.example.com \
  --request-key AbCdEf0123456789GhIj \
  --key-label my-key \
  --algorithm aes-gcm-256 \
  --value SGVsbG8
```

## Commands

### `encrypt`

Submit an encryption request for approval.

```bash
revaulter-cli encrypt [flags]
```

| Flag | Short | Required | Description |
|------|-------|----------|-------------|
| `--server` | `-s` | Yes | Address of the Revaulter server (e.g. `https://revaulter.example.com`) |
| `--request-key` | | Yes | Per-user request key (shown in the web UI after registration) |
| `--key-label` | | Yes | Logical key label used for key derivation |
| `--algorithm` | `-a` | Yes | Algorithm identifier (currently `aes-gcm-256`) |
| `--value` | | Yes | The message to encrypt (base64-encoded) |
| `--nonce` | | No | Nonce/IV for the operation (base64-encoded) |
| `--aad` | | No | Additional authenticated data (base64-encoded) |
| `--timeout` | `-t` | No | Timeout for the operation (number of seconds or Go duration, e.g. `5m`, `300`) |
| `--note` | `-n` | No | Message displayed alongside the request (up to 40 chars, alphanumeric and `. / _ -` only) |
| `--output` | `-o` | No | Write the result to a file instead of stdout (mode 0600, refuses symlinks) |
| `--raw` | | No | Output raw decrypted bytes instead of the default JSON envelope |
| `--insecure` | | No | Skip TLS certificate validation |
| `--no-h2c` | | No | Do not attempt HTTP/2 Cleartext when not using TLS |
| `--verbose` | `-V` | No | Show debug-level logs |

**Example:**

```bash
revaulter-cli encrypt \
  --server https://revaulter.example.com \
  --request-key AbCdEf0123456789GhIj \
  --key-label boot-disk \
  --algorithm aes-gcm-256 \
  --value SGVsbG8 \
  --note "boot unlock"
```

---

### `decrypt`

Submit a decryption request for approval.

```bash
revaulter-cli decrypt [flags]
```

| Flag | Short | Required | Description |
|------|-------|----------|-------------|
| `--server` | `-s` | Yes | Address of the Revaulter server (e.g. `https://revaulter.example.com`) |
| `--request-key` | | Yes | Per-user request key (shown in the web UI after registration) |
| `--key-label` | | Yes | Logical key label used for key derivation |
| `--algorithm` | `-a` | Yes | Algorithm identifier (currently `aes-gcm-256`) |
| `--value` | | Yes | The ciphertext to decrypt (base64-encoded) |
| `--tag` | | No | Authentication tag (base64-encoded) |
| `--nonce` | | No | Nonce/IV (base64-encoded) |
| `--aad` | | No | Additional authenticated data (base64-encoded) |
| `--timeout` | `-t` | No | Timeout for the operation (number of seconds or Go duration, e.g. `5m`, `300`) |
| `--note` | `-n` | No | Message displayed alongside the request (up to 40 chars, alphanumeric and `. / _ -` only) |
| `--output` | `-o` | No | Write the result to a file instead of stdout (mode 0600, refuses symlinks) |
| `--raw` | | No | Output raw decrypted bytes instead of the default JSON envelope |
| `--insecure` | | No | Skip TLS certificate validation |
| `--no-h2c` | | No | Do not attempt HTTP/2 Cleartext when not using TLS |
| `--verbose` | `-V` | No | Show debug-level logs |

**Example:**

```bash
revaulter-cli decrypt \
  --server https://revaulter.example.com \
  --request-key AbCdEf0123456789GhIj \
  --key-label boot-disk \
  --algorithm aes-gcm-256 \
  --value <base64-ciphertext> \
  --nonce <base64-nonce> \
  --tag <base64-tag>
```

**Write result to a file:**

```bash
revaulter-cli decrypt \
  --server https://revaulter.example.com \
  --request-key AbCdEf0123456789GhIj \
  --key-label boot-disk \
  --algorithm aes-gcm-256 \
  --value <base64-ciphertext> \
  --nonce <base64-nonce> \
  --tag <base64-tag> \
  --output /tmp/decrypted.bin \
  --raw
```

---

### `check`

Verify that a Revaulter server is serving unmodified web client assets, signed by this repo's release workflow. See [Verifying the web client's integrity](./07-web-client-integrity.md) for a deeper explanation of the trust model and when to run this.

```bash
revaulter-cli check --server https://revaulter.example.com
```

| Flag | Short | Required | Description |
|------|-------|----------|-------------|
| `--server` | `-s` | Yes | Address of the Revaulter server |
| `--timeout` | `-t` | No | Overall timeout for the check (e.g. `60s`, `2m`); defaults to 60s |
| `--insecure` | | No | Skip TLS certificate validation |
| `--no-h2c` | | No | Do not attempt HTTP/2 Cleartext when not using TLS |
| `--verbose` | `-V` | No | Show debug-level logs |

---

### `version`

Print the CLI version.

```bash
revaulter-cli version
```

## How it works

When you run `revaulter-cli encrypt` or `decrypt`, the CLI:

1. Fetches the user's public encryption keys from the server
2. Generates an ephemeral ECDH P-256 keypair and an ML-KEM-768 encapsulation
3. Encrypts the request payload end-to-end to the user's public keys
4. Submits the encrypted request to the server
5. Long-polls for the result
6. Decrypts the response envelope locally using its ephemeral private key

The server never has access to the plaintext request or response data.

## Output

By default, the CLI writes a JSON envelope to stdout after decrypting the response:

```json
{
  "value": "<base64>"
}
```

With `--raw`, it writes the decrypted plaintext as raw bytes — useful for piping into other commands or writing binary data to a file with `--output`.

## Exit codes

- **0** — the operation completed successfully
- **non-zero** — the request was denied, canceled, expired, or an error occurred (details are printed to stderr)
