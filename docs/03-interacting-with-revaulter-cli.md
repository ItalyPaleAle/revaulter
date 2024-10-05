# Interacting with Revaulter using the CLI

The Revaulter CLI (`revaulter-cli`) offers a simplified method to interact with Revaulter to perform the six cryptographic operations supported by Azure Key Vault: encrypting and decrypting messages, wrapping and unwrapping keys, and computing and verifying digital signatures.

## Flow

Regardless of the operation in use, the regular flow is the same:

1. The application that requires the operation invokes `revaulter-cli` to start the operation. The CLI will automatically wait for the completion.
2. Revaulter receives the request and sends a notification to an admin.
3. An admin visits the Revaulter page, authenticates with Azure AD, and then approves the operation. If the admin denies the operation, or the request expires, Revaulter removes the request from its state and the flow stops.
4. Once the request is approved, Revaulter performs the operation within the Key Vault.
5. Revaulter sends the result to the CLI. The response is sent only once.

Revaulter uses delegated permissions to access Azure Key Vault. It uses the access token the user provides after logging in with Azure AD to make requests to Azure Key Vault, with the access level granted to the user.

> The ["headless" flow](./04-using-rest-api.md#headless-flow), which doesn't require approval from an admin, is only supported using the REST APIs.

## Installing the Revaulter CLI

The Revaulter CLI is available as a standalone binary for Windows, macOS, and Linux, or as a Linux container.

- Binaries: you can download the `revaulter-cli` binary from the [Releases page on GitHub](https://github.com/ItalyPaleAle/revaulter/releases/latest).
- Container: containers are [published](https://github.com/ItalyPaleAle/revaulter/pkgs/container/revaulter-cli) on GitHub Container Registry:  

   ```sh
   # Using Docker
   docker pull ghcr.io/italypaleale/revaulter-cli:1
   # Using Podman
   podman pull ghcr.io/italypaleale/revaulter-cli:1
   ```

It's recommended to always use the version of the Revaulter CLI that matches the version of the Revaulter server you're talking to.

## Using the Revaulter CLI

The Revaulter CLI is designed to run on a client machine and interact with a Revaulter server over HTTP(S).

- Adding `--help` to a command shows a detailed help page
- You can check the version of the CLI with `revaulter-cli version`
- Use the `--verbose` / `-V` flag to enable debug-level logs

The CLI outputs the result of each operation as a JSON message on the standard output stream (stdout), so it can be piped into another command, such as `jq`. Logs are emitted to the standard error stream (stderr).

> In the containers, `revaulter-cli` is set as entrypoint, so sub-commands can be invoked by adding their names directly after the container image. For example, to get the version of the CLI:
>
> ```sh
> # Using Docker
> docker run --rm ghcr.io/italypaleale/revaulter-cli:1 version
> # Using Podman
> podman run --rm ghcr.io/italypaleale/revaulter-cli:1 version
> ```

### Encrypt a message

The `encrypt` sub-command can be used to request a message to be encrypted using Revaulter:

```sh
# Standalone
revaulter-cli encrypt

# Using Docker
docker run --rm ghcr.io/italypaleale/revaulter-cli:1 encrypt

# Using Podman
podman run --rm ghcr.io/italypaleale/revaulter-cli:1 encrypt
```

The `encrypt` command accepts these flags:

- **`--server` / `-s`** (string): Address of the Revaulter server. For example: `-s https://10.20.30.40:8080/`
- **`--algorithm` / `-a`** (string): Algorithm to use to encrypt the message. The string is a constant defined by the JSON Web Encryption (JWE) standard, for example `RSA-OAEP-256`. See the list of supported values in the [Azure Key Vault documentation](https://learn.microsoft.com/en-us/azure/key-vault/keys/about-keys-details).
- **`--value`** (base64-encoded string): The message to encrypt.
- **`--key-id` / `-k`** (string): The name of the key stored in the Key Vault.
- **`--vault` / `-v`** (string): The name or URL of the Azure Key Vault instance where the key is stored.
- Optional arguments:
  - **`--nonce`** (base64-encoded string): Nonce (or Initialization Vector) for the encryption operation. Although this flag is optional, it may be required by some algorithms, and omitting that may cause Azure Key Vault to return an error. The length of the nonce depends on the algorithm used.
  - **`--aad`** (base64-encoded string): Additional Authenticated Data for the encryption operation. Note that not all algorithms support this flag.
  - **`--key-version`** (string): The version of the key stored in Key Vault to use; if omitted, it defaults to the latest version of the key.
  - **`--timeout` / `-t`** (string or integer): An optional timeout for the operation, as a Go duration (e.g. "2m") or a number of seconds. If empty, uses the default value set in the server. If an admin doesn't approve (or deny) the operation in that timeframe, the request is automatically canceled.
  - **`--note` / `-n`** (string): A freeform message (up to 40 characters) that is displayed to clients alongside the request. For example, it can be used to add an identifier to the request.
  - **`--secret-key` / `-K`** (string): Secret pre-shared key if required by the server to access the `/request` endpoints.
  - **`--insecure`** (boolean): Skip TLS certificate validation when connecting to the Revaulter server.
  - **`--no-h2c`** (boolean): Do not attempt connecting with HTTP/2 Cleartext when not using TLS.

Once the operation is approved by an admin, the encrypted message is returned to the command's standard output (stdout). The response is JSON-encoded with the following schema:

```json
{
  "data": "<base64-encoded encrypted data>",
  "nonce": "<base64-encoded nonce>",
  "tag": "<base64-encoded tag>"
}
```

The `nonce` and `tag` fields are returned by some algorithms/ciphers only, and are omitted if empty.

### Decrypt a message

The `decrypt` sub-command can be used to request a message to be decrypted using Revaulter:

```sh
# Standalone
revaulter-cli decrypt

# Using Docker
docker run --rm ghcr.io/italypaleale/revaulter-cli:1 decrypt

# Using Podman
podman run --rm ghcr.io/italypaleale/revaulter-cli:1 decrypt
```

The `decrypt` command accepts these flags:

- **`--server` / `-s`** (string): Address of the Revaulter server. For example: `-s https://10.20.30.40:8080/`
- **`--algorithm` / `-a`** (string): Algorithm to use to decrypt the message. The string is a constant defined by the JSON Web Encryption (JWE) standard, for example `RSA-OAEP-256`. See the list of supported values in the [Azure Key Vault documentation](https://learn.microsoft.com/en-us/azure/key-vault/keys/about-keys-details).
- **`--value`** (base64-encoded string): The message to decrypt.
- **`--key-id` / `-k`** (string): The name of the key stored in the Key Vault.
- **`--vault` / `-v`** (string): The name or URL of the Azure Key Vault instance where the key is stored.
- Optional arguments:
  - **`--nonce`** (base64-encoded string): Nonce (or Initialization Vector) for the decryption operation. Although this flag is optional, it may be required by some algorithms, and omitting that may cause Azure Key Vault to return an error. The length of the nonce depends on the algorithm used.
  - **`--tag`** (base64-encoded string): Authentication tag for the decryption operation. Although this flag is optional, it may be required by some algorithms (such as authenticated ciphers), and omitting that may cause Azure Key Vault to return an error.
  - **`--aad`** (base64-encoded string): Additional Authenticated Data for the decryption operation. Note that not all algorithms support this flag.
  - **`--key-version`** (string): The version of the key stored in Key Vault to use; if omitted, it defaults to the latest version of the key.
  - **`--timeout` / `-t`** (string or integer): An optional timeout for the operation, as a Go duration (e.g. "2m") or a number of seconds. If empty, uses the default value set in the server. If an admin doesn't approve (or deny) the operation in that timeframe, the request is automatically canceled.
  - **`--note` / `-n`** (string): A freeform message (up to 40 characters) that is displayed to clients alongside the request. For example, it can be used to add an identifier to the request.
  - **`--secret-key` / `-K`** (string): Secret pre-shared key if required by the server to access the `/request` endpoints.
  - **`--insecure`** (boolean): Skip TLS certificate validation when connecting to the Revaulter server.
  - **`--no-h2c`** (boolean): Do not attempt connecting with HTTP/2 Cleartext when not using TLS.

Once the operation is approved by an admin, the decrypt message is returned to the command's standard output (stdout). The response is JSON-encoded with the following schema:

```json
{
  "data": "<base64-encoded decrypted data>"
}
```

### Sign a message

The `sign` sub-command can be used to request a message's digest (hash) to be signed.

```sh
# Standalone
revaulter-cli sign

# Using Docker
docker run --rm ghcr.io/italypaleale/revaulter-cli:1 sign

# Using Podman
podman run --rm ghcr.io/italypaleale/revaulter-cli:1 sign
```

The `sign` command accepts these flags:

- **`--server` / `-s`** (string): Address of the Revaulter server. For example: `-s https://10.20.30.40:8080/`
- **`--algorithm` / `-a`** (string): Algorithm to use to encrypt the message. The string is a constant defined by the JSON Web Encryption (JWE) standard, for example `RSA-OAEP-256`. See the list of supported values in the [Azure Key Vault documentation](https://learn.microsoft.com/en-us/azure/key-vault/keys/about-keys-details).
- **`--digest`** (base64-encoded string): The digest (hash) of the message to sign. The length of the digest (and thus the algorithm used to compute it) depends on the algorithm used for the signature; for example, for algorithm `PS256`, the digest should be computed with SHA-256.
- **`--key-id` / `-k`** (string): The name of the key stored in the Key Vault.
- **`--vault` / `-v`** (string): The name or URL of the Azure Key Vault instance where the key is stored.
- Optional arguments:
  - **`--key-version`** (string): The version of the key stored in Key Vault to use; if omitted, it defaults to the latest version of the key.
  - **`--timeout` / `-t`** (string or integer): An optional timeout for the operation, as a Go duration (e.g. "2m") or a number of seconds. If empty, uses the default value set in the server. If an admin doesn't approve (or deny) the operation in that timeframe, the request is automatically canceled.
  - **`--note` / `-n`** (string): A freeform message (up to 40 characters) that is displayed to clients alongside the request. For example, it can be used to add an identifier to the request.
  - **`--secret-key` / `-K`** (string): Secret pre-shared key if required by the server to access the `/request` endpoints.
  - **`--insecure`** (boolean): Skip TLS certificate validation when connecting to the Revaulter server.
  - **`--no-h2c`** (boolean): Do not attempt connecting with HTTP/2 Cleartext when not using TLS.

Once the operation is approved by an admin, the signature is returned to the command's standard output (stdout). The response is JSON-encoded with the following schema:

```json
{
  "data": "<base64-encoded signature>"
}
```

### Verify a digital signature

The `verify` sub-command can be used to verify the signature of a message's digest (hash).

```sh
# Standalone
revaulter-cli verify

# Using Docker
docker run --rm ghcr.io/italypaleale/revaulter-cli:1 verify

# Using Podman
podman run --rm ghcr.io/italypaleale/revaulter-cli:1 verify
```

The `verify` command accepts these flags:

- **`--server` / `-s`** (string): Address of the Revaulter server. For example: `-s https://10.20.30.40:8080/`
- **`--algorithm` / `-a`** (string): Algorithm to use to encrypt the message. The string is a constant defined by the JSON Web Encryption (JWE) standard, for example `RSA-OAEP-256`. See the list of supported values in the [Azure Key Vault documentation](https://learn.microsoft.com/en-us/azure/key-vault/keys/about-keys-details).
- **`--digest`** (base64-encoded string): The digest (hash) of the message to sign. The length of the digest (and thus the algorithm used to compute it) depends on the algorithm used for the signature; for example, for algorithm `PS256`, the digest should be computed with SHA-256.
- **`--signature`** (base64-encoded string): The signature to verify.
- **`--key-id` / `-k`** (string): The name of the key stored in the Key Vault.
- **`--vault` / `-v`** (string): The name or URL of the Azure Key Vault instance where the key is stored.
- Optional arguments:
  - **`--key-version`** (string): The version of the key stored in Key Vault to use; if omitted, it defaults to the latest version of the key.
  - **`--timeout` / `-t`** (string or integer): An optional timeout for the operation, as a Go duration (e.g. "2m") or a number of seconds. If empty, uses the default value set in the server. If an admin doesn't approve (or deny) the operation in that timeframe, the request is automatically canceled.
  - **`--note` / `-n`** (string): A freeform message (up to 40 characters) that is displayed to clients alongside the request. For example, it can be used to add an identifier to the request.
  - **`--secret-key` / `-K`** (string): Secret pre-shared key if required by the server to access the `/request` endpoints.
  - **`--insecure`** (boolean): Skip TLS certificate validation when connecting to the Revaulter server.
  - **`--no-h2c`** (boolean): Do not attempt connecting with HTTP/2 Cleartext when not using TLS.

Once the operation is approved by an admin, the result is returned to the command's standard output (stdout). The response is JSON-encoded with the following schema:

```json
{
  "valid": true
}
```

The `valid` field is a boolean value indicating if the signature is valid for the message's hash.

### Wrap a key

The `wrapkey` sub-command can be used to request a key to be wrapped (encrypted) using Revaulter:

```sh
# Standalone
revaulter-cli wrapkey

# Using Docker
docker run --rm ghcr.io/italypaleale/revaulter-cli:1 wrapkey

# Using Podman
podman run --rm ghcr.io/italypaleale/revaulter-cli:1 wrapkey
```

The `encrypt` command accepts these flags:

- **`--server` / `-s`** (string): Address of the Revaulter server. For example: `-s https://10.20.30.40:8080/`
- **`--algorithm` / `-a`** (string): Algorithm to use to wrap the key. The string is a constant defined by the JSON Web Encryption (JWE) standard, for example `RSA-OAEP-256`. See the list of supported values in the [Azure Key Vault documentation](https://learn.microsoft.com/en-us/azure/key-vault/keys/about-keys-details).
- **`--value`** (base64-encoded string): The key to wrap.
- **`--key-id` / `-k`** (string): The name of the key stored in the Key Vault.
- **`--vault` / `-v`** (string): The name or URL of the Azure Key Vault instance where the key is stored.
- Optional arguments:
  - **`--nonce`** (base64-encoded string): Nonce (or Initialization Vector) for the wrapping operation. Although this flag is optional, it may be required by some algorithms, and omitting that may cause Azure Key Vault to return an error. The length of the nonce depends on the algorithm used.
  - **`--aad`** (base64-encoded string): Additional Authenticated Data for the wrapping operation. Note that not all algorithms support this flag.
  - **`--key-version`** (string): The version of the key stored in Key Vault to use; if omitted, it defaults to the latest version of the key.
  - **`--timeout` / `-t`** (string or integer): An optional timeout for the operation, as a Go duration (e.g. "2m") or a number of seconds. If empty, uses the default value set in the server. If an admin doesn't approve (or deny) the operation in that timeframe, the request is automatically canceled.
  - **`--note` / `-n`** (string): A freeform message (up to 40 characters) that is displayed to clients alongside the request. For example, it can be used to add an identifier to the request.
  - **`--secret-key` / `-K`** (string): Secret pre-shared key if required by the server to access the `/request` endpoints.
  - **`--insecure`** (boolean): Skip TLS certificate validation when connecting to the Revaulter server.
  - **`--no-h2c`** (boolean): Do not attempt connecting with HTTP/2 Cleartext when not using TLS.

Once the operation is approved by an admin, the wrapped key is returned to the command's standard output (stdout). The response is JSON-encoded with the following schema:

```json
{
  "data": "<base64-encoded wrapped key>",
  "nonce": "<base64-encoded nonce>",
  "tag": "<base64-encoded tag>"
}
```

The `nonce` and `tag` fields are returned by some algorithms/ciphers only, and are omitted if empty.

### Unwrap a key

The `unwrapkey` sub-command can be used to request a key to be unwrapped (decrypted) using Revaulter:

```sh
# Standalone
revaulter-cli unwrapkey

# Using Docker
docker run --rm ghcr.io/italypaleale/revaulter-cli:1 unwrapkey

# Using Podman
podman run --rm ghcr.io/italypaleale/revaulter-cli:1 unwrapkey
```

The `unwrapkey` command accepts these flags:

- **`--server` / `-s`** (string): Address of the Revaulter server. For example: `-s https://10.20.30.40:8080/`
- **`--algorithm` / `-a`** (string): Algorithm to use to unwrap the key The string is a constant defined by the JSON Web Encryption (JWE) standard, for example `RSA-OAEP-256`. See the list of supported values in the [Azure Key Vault documentation](https://learn.microsoft.com/en-us/azure/key-vault/keys/about-keys-details).
- **`--value`** (base64-encoded string): The key to unwrap.
- **`--key-id` / `-k`** (string): The name of the key stored in the Key Vault.
- **`--vault` / `-v`** (string): The name or URL of the Azure Key Vault instance where the key is stored.
- Optional arguments:
  - **`--nonce`** (base64-encoded string): Nonce (or Initialization Vector) for the unwrapping operation. Although this flag is optional, it may be required by some algorithms, and omitting that may cause Azure Key Vault to return an error. The length of the nonce depends on the algorithm used.
  - **`--tag`** (base64-encoded string): Authentication tag for the unwrapping operation. Although this flag is optional, it may be required by some algorithms (such as authenticated ciphers), and omitting that may cause Azure Key Vault to return an error.
  - **`--aad`** (base64-encoded string): Additional Authenticated Data for the unwrapping operation. Note that not all algorithms support this flag.
  - **`--key-version`** (string): The version of the key stored in Key Vault to use; if omitted, it defaults to the latest version of the key.
  - **`--timeout` / `-t`** (string or integer): An optional timeout for the operation, as a Go duration (e.g. "2m") or a number of seconds. If empty, uses the default value set in the server. If an admin doesn't approve (or deny) the operation in that timeframe, the request is automatically canceled.
  - **`--note` / `-n`** (string): A freeform message (up to 40 characters) that is displayed to clients alongside the request. For example, it can be used to add an identifier to the request.
  - **`--secret-key` / `-K`** (string): Secret pre-shared key if required by the server to access the `/request` endpoints.
  - **`--insecure`** (boolean): Skip TLS certificate validation when connecting to the Revaulter server.
  - **`--no-h2c`** (boolean): Do not attempt connecting with HTTP/2 Cleartext when not using TLS.

Once the operation is approved by an admin, the unwrapped key is returned to the command's standard output (stdout). The response is JSON-encoded with the following schema:

```json
{
  "data": "<base64-encoded unwrapped key>"
}
```
