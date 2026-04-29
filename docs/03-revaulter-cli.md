# Using the Revaulter CLI

The Revaulter CLI (`revaulter-cli`) is the primary way to submit encrypt, decrypt, and sign requests.

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
  --algorithm A256GCM \
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
| `--request-key` | `-k` | Yes | Per-user request key (shown in the web UI after registration) |
| `--key-label` | `-l` | Yes | Logical key label used for key derivation |
| `--algorithm` | `-a` | Yes | AEAD algorithm identifier: `A256GCM` (alias `aes-256-gcm`) or `C20P` (alias `chacha20-poly1305`) |
| `--message` | `-m` | One of `--message`, `--input`, or `--json` is required | The message to encrypt as a raw UTF-8 string. |
| `--input` | `-i` | One of `--message`, `--input`, or `--json` is required | Path to a file whose bytes will be encrypted; use `-` to read from stdin |
| `--json` | | One of `--message`, `--input`, or `--json` is required | Path to a JSON file (or `-` to read from stdin) of shape `{"value":"<base64url>","additionalData":"<base64url>"}` (`additionaldata` is optional) |
| `--aad` | | No | Additional authenticated data (base64-encoded). Not allowed with `--json` |
| `--timeout` | `-t` | No | Timeout for the operation (number of seconds or Go duration, e.g. `5m`, `300`) |
| `--note` | `-n` | No | Message displayed alongside the request (up to 40 chars, alphanumeric and `. / _ -` only) |
| `--output` | `-o` | No | Write the result to a file instead of stdout |
| `--format` | | No | Output format: `json` (only). Encrypt always emits the JSON envelope on stdout |
| `--insecure` | | No | Skip TLS certificate validation |
| `--no-h2c` | | No | Do not attempt HTTP/2 Cleartext when not using TLS |
| `--verbose` | `-V` | No | Show debug-level logs |

**Example (raw string):**

```bash
revaulter-cli encrypt \
  --server https://revaulter.example.com \
  --request-key AbCdEf0123456789GhIj \
  --key-label boot-disk \
  --algorithm A256GCM \
  --message "Hello, world" \
  --note "boot unlock"
```

**Example (read plaintext from a file):**

```bash
revaulter-cli encrypt \
  --server https://revaulter.example.com \
  --request-key AbCdEf0123456789GhIj \
  --key-label boot-disk \
  --algorithm A256GCM \
  --input ./secret.bin
```

**Example (JSON input):**

```bash
echo '{"value":"SGVsbG8"}' | revaulter-cli encrypt \
  --server https://revaulter.example.com \
  --request-key AbCdEf0123456789GhIj \
  --key-label boot-disk \
  --algorithm A256GCM \
  --json -
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
| `--request-key` | `-k` | Yes | Per-user request key (shown in the web UI after registration) |
| `--key-label` | `-l` | Yes | Logical key label used for key derivation |
| `--algorithm` | `-a` | Yes | AEAD algorithm identifier: `A256GCM` (alias `aes-256-gcm`) or `C20P` (alias `chacha20-poly1305`). Must match what was used at encryption time |
| `--value` | `-m` | One of `--value` or `--json` is required | The ciphertext to decrypt, base64-encoded |
| `--tag` | `-g` | Required when not using `--json` | Authentication tag, base64-encoded |
| `--nonce` | | Required when not using `--json` | Nonce/IV, base64-encoded |
| `--aad` | | No | Additional authenticated data, base64-encoded (only allowed not using `--json`) |
| `--json` | `-j` | One of `--value` or `--json` is required | Path to a JSON file (or `-` to read from stdin) in the shape produced by `encrypt` (`{"value":"<base64url>","nonce":"<base64url>","tag":"<base64url>","additionalData":"<base64url>"}`). Mutually exclusive with `--value`, `--tag`, `--nonce`, and `--aad` |
| `--timeout` | `-t` | No | Timeout for the operation (number of seconds or Go duration, e.g. `5m`, `300`) |
| `--note` | `-n` | No | Message displayed alongside the request (up to 40 chars, alphanumeric and `. / _ -` only) |
| `--output` | `-o` | No | Write the result to a file instead of stdout |
| `--format` | | No | Output format: `json` (default — JSON envelope) or `raw` (write the decrypted plaintext as raw bytes) |
| `--insecure` | | No | Skip TLS certificate validation |
| `--no-h2c` | | No | Do not attempt HTTP/2 Cleartext when not using TLS |
| `--verbose` | `-V` | No | Show debug-level logs |

**Example:**

```bash
revaulter-cli decrypt \
  --server https://revaulter.example.com \
  --request-key AbCdEf0123456789GhIj \
  --key-label boot-disk \
  --algorithm A256GCM \
  --value <base64-ciphertext> \
  --nonce <base64-nonce> \
  --tag <base64-tag>
```

**Example (JSON input — pipes encrypt's output back in):**

```bash
revaulter-cli encrypt --message "secret" ... \
  | revaulter-cli decrypt \
    --server https://revaulter.example.com \
    --request-key AbCdEf0123456789GhIj \
    --key-label boot-disk \
    --algorithm A256GCM \
    --json - \
    --format raw
```

**Write result to a file ("raw" format):**

```bash
revaulter-cli decrypt \
  --server https://revaulter.example.com \
  --request-key AbCdEf0123456789GhIj \
  --key-label boot-disk \
  --algorithm A256GCM \
  --value <base64-ciphertext> \
  --nonce <base64-nonce> \
  --tag <base64-tag> \
  --output /tmp/decrypted.bin \
  --format raw
```

---

### `sign`

Submit a signing request for approval. The CLI always pre-hashes the message with SHA-256 client-side, so only the 32-byte digest is sent to the server — the raw message is never transmitted.

```bash
revaulter-cli sign [flags]
```

| Flag | Short | Required | Description |
|------|-------|----------|-------------|
| `--server` | `-s` | Yes | Address of the Revaulter server |
| `--request-key` | `-k` | Yes | Per-user request key |
| `--key-label` | `-l` | Yes | Logical key label used for signing-key derivation |
| `--algorithm` | `-a` | Yes | Signing algorithm identifier (currently `ES256`) |
| `--input` | `-i` | One of `--input` or `--digest` is required | Path to the message file to sign; use `-` for stdin. The CLI hashes the file contents with SHA-256 |
| `--digest` | `-d` | One of `--input` or `--digest` is required | A pre-computed 32-byte SHA-256 digest, encoded as hex or base64url. Mutually exclusive with `--format jws` |
| `--format` | | No | Output format: `json` (default — JSON envelope with base64url `r \|\| s` signature), `jws` (compact JWS string), or `raw` (the 64-byte `r \|\| s` signature). `jws` requires `--input` |
| `--jws-header` | | No | JSON fragment merged into the default protected header when building a JWS from `--input`. The `alg` field is always forced to `ES256`; other fields like `kid` or `typ` can be supplied |
| `--timeout` | `-t` | No | Timeout for the operation |
| `--note` | `-n` | No | Message displayed alongside the request |
| `--output` | `-o` | No | Write the result to a file instead of stdout |
| `--insecure` | | No | Skip TLS certificate validation |
| `--no-h2c` | | No | Do not attempt HTTP/2 Cleartext when not using TLS |
| `--verbose` | `-V` | No | Show debug-level logs |

**Examples:**

Sign a file (default output is a JSON envelope containing the base64url `r || s` signature):

```bash
revaulter-cli sign \
  --server https://revaulter.example.com \
  --request-key AbCdEf0123456789GhIj \
  --key-label release-signing \
  --algorithm ES256 \
  --input manifest.json
```

Sign data piped from stdin:

```bash
echo "hello" | revaulter-cli sign \
  --server https://revaulter.example.com \
  --request-key AbCdEf0123456789GhIj \
  --key-label release-signing \
  --algorithm ES256 \
  --input -
```

Sign a pre-computed SHA-256 digest (useful when integrating with other tooling that already hashes):

```bash
revaulter-cli sign \
  --server https://revaulter.example.com \
  --request-key AbCdEf0123456789GhIj \
  --key-label release-signing \
  --algorithm ES256 \
  --digest d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592
```

Emit a compact JWS over a file, merging a custom `kid` into the protected header:

```bash
revaulter-cli sign \
  --server https://revaulter.example.com \
  --request-key AbCdEf0123456789GhIj \
  --key-label release-signing \
  --algorithm ES256 \
  --input manifest.json \
  --format jws \
  --jws-header '{"kid":"release-signing-2026"}'
```

Write just the raw 64-byte `r || s` signature to a file (useful for pipelines that verify with a separate tool):

```bash
revaulter-cli sign \
  --server https://revaulter.example.com \
  --request-key AbCdEf0123456789GhIj \
  --key-label release-signing \
  --algorithm ES256 \
  --input manifest.json \
  --format raw \
  --output manifest.sig
```

> Note: ECDSA signatures are non-deterministic by design (a fresh random `k` per signature, per FIPS 186-5). Signing the same input twice produces two different but equally valid signatures — this is expected.

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

When you run `revaulter-cli encrypt`, `decrypt`, or `sign`, the CLI:

1. Fetches the user's public encryption keys from the server
2. Generates an ephemeral ECDH P-256 keypair and an ML-KEM-768 encapsulation
3. Encrypts the request payload end-to-end to the user's public keys
4. Submits the encrypted request to the server
5. Long-polls for the result
6. Decrypts the response envelope locally using its ephemeral private key

For `sign` specifically, the CLI pre-hashes the input with SHA-256 before encrypting, so only the 32-byte digest is ever transmitted end-to-end. The server and the browser never see the raw message.

The server never has access to the plaintext request or response data.

## Output

By default, the CLI writes a JSON envelope (`--format json`) to stdout after decrypting the response:

```json
{
  "value": "<base64>"
}
```

- For `decrypt`: `--format raw` writes the decrypted plaintext as raw bytes — useful for piping into other commands or writing binary data to a file with `--output`.
- For `sign`: `--format` also accepts `jws` (compact JWS) and `raw` (the 64-byte `r || s` signature).

## Exit codes

- **0** — the operation completed successfully
- **non-zero** — the request was denied, canceled, expired, or an error occurred (details are printed to stderr)
