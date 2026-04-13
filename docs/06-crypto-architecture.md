# Crypto Architecture: Primary Key Wrapping

## Overview

All encryption keys (request encryption ECDH/ML-KEM keys, operation AES keys) are derived from a randomly-generated 256-bit **primary key**.
The primary key is wrapped (encrypted) with a key derived from the WebAuthn PRF output and an optional Argon2id-stretched password, then stored on the server.

This architecture decouples encryption keys from the specific passkey: changing or rotating a passkey changes the PRF output, but only requires re-wrapping the primary key — not re-encrypting all stored data.
A successful unwrap proves credential and password correctness, replacing the separate password canary.

> **Security note:** The `wrappedPrimaryKey` blob is sensitive encrypted root-key material.
> It must never be logged, echoed back in diagnostics, or exposed through telemetry.

## Key Hierarchy

```mermaid
flowchart TD
    PRF["WebAuthn PRF → prfSecret (32 B)"]
    PW["Password (optional)"]
    A2["Argon2id(pw, salt) → stretched (32 B)"]
    WK["HKDF(prfSecret, stretched‖∅) → wrappingKey (32 B)"]
    UNWRAP["AES-256-GCM unwrap"]
    PK["primaryKey (random 256-bit)"]
    ECDH["HKDF → ECDH P-256 key pair"]
    MLKEM["HKDF → ML-KEM-768 key pair"]
    OP["HKDF → operation AES-256 key"]

    PRF --> WK
    PW --> A2
    A2 -->|salt| WK
    WK --> UNWRAP
    UNWRAP --> PK
    PK --> ECDH
    PK --> MLKEM
    PK --> OP
```

## Cryptographic Design

### Wrapping key derivation

```
If password is set:
  1. stretched = Argon2id(password, argon2id_salt,
                          m=128 MiB, t=4, p=1, hashLen=32)
  2. wrappingKey = HKDF-SHA256(
       IKM  = prfSecret,
       salt = stretched,
       info = "revaulter/v2/primaryKeyWrap\nuserId={userId}\nv=1",
       len  = 32)

If no password:
  wrappingKey = HKDF-SHA256(
       IKM  = prfSecret,
       salt = ∅,
       info = "revaulter/v2/primaryKeyWrap\nuserId={userId}\nv=1",
       len  = 32)
```

Argon2id is applied when a password is present because passwords can be low-entropy.
An attacker who obtains both the wrapped primary key (server compromise) and the PRF output (stolen passkey) could brute-force a weak password in the HKDF-only scheme.
Argon2id makes that infeasible.
When no password is set, HKDF alone is sufficient since the PRF output is 256-bit high-entropy.

### Primary key wrapping (AES-256-GCM)

| Parameter  | Value |
|------------|-------|
| Key        | wrappingKey (32 bytes) |
| Nonce      | random 12 bytes |
| Plaintext  | primaryKey (32 bytes) |
| AAD        | `revaulter/v2/wrapped-primary-key\nuserId={userId}\nv=1` |

### Wrapped key envelope format

The wrapped key is stored as a base64url-encoded JSON envelope:

```json
{
  "v": 1,
  "passwordRequired": true,
  "argon2id": {
    "m": 131072,
    "t": 4,
    "p": 1,
    "salt": "<base64url>"
  },
  "nonce": "<base64url>",
  "ciphertext": "<base64url>"
}
```

When `passwordRequired` is `false`, the `argon2id` object is omitted.

### Key derivation from primary key

All keys are derived via HKDF-SHA256 with `IKM = primaryKey` and `salt = ∅`:

| Purpose | Info string | Output length |
|---------|-------------|---------------|
| Request enc ECDH | `revaulter/v2/requestEncKey\nuserId={userId}\nv=1` | 384 bits |
| Request enc ML-KEM | `revaulter/v2/requestEncMlkemSeed\nuserId={userId}\nv=1` | 512 bits |
| Operation key | `algorithm={alg}\nkeyLabel={label}\nuserId={userId}\nv=1` | 256 bits |

## Flows

### Signup flow

```mermaid
sequenceDiagram
    participant B as Browser
    participant S as Server
    participant A as Authenticator

    B->>S: POST /v2/auth/register/begin
    S-->>B: challenge + basePrfSalt
    B->>A: WebAuthn create (with PRF)
    A-->>B: credential + prfSecret
    B->>S: POST /v2/auth/register/finish
    S-->>B: session

    Note over B: Generate random primaryKey (32 B)
    Note over B: Derive wrappingKey from prfSecret [+ Argon2id(pw)]
    Note over B: Wrap primaryKey → wrappedPrimaryKey envelope
    Note over B: Derive ECDH + ML-KEM key pairs from primaryKey

    B->>S: POST /v2/auth/finalize-signup
    Note right of B: {ecdhPubkey, mlkemPubkey, wrappedPrimaryKey}
    S-->>B: ok
```

### Login flow (with password)

```mermaid
sequenceDiagram
    participant B as Browser
    participant S as Server
    participant A as Authenticator

    B->>S: POST /v2/auth/login/begin
    S-->>B: challenge + basePrfSalt
    B->>A: WebAuthn assert (with PRF)
    A-->>B: assertion + prfSecret
    B->>S: POST /v2/auth/login/finish
    S-->>B: session + wrappedPrimaryKey

    Note over B: Parse envelope → passwordRequired: true
    Note over B: Prompt user for password

    Note over B: Argon2id(password, envelope.argon2id.salt) → stretched
    Note over B: HKDF(prfSecret, stretched) → wrappingKey
    Note over B: AES-GCM unwrap → primaryKey
    Note over B: (unwrap success = correct password)
```

### Login flow (no password)

```mermaid
sequenceDiagram
    participant B as Browser
    participant S as Server
    participant A as Authenticator

    B->>S: POST /v2/auth/login/begin
    S-->>B: challenge + basePrfSalt
    B->>A: WebAuthn assert (with PRF)
    A-->>B: assertion + prfSecret
    B->>S: POST /v2/auth/login/finish
    S-->>B: session + wrappedPrimaryKey

    Note over B: Parse envelope → passwordRequired: false
    Note over B: HKDF(prfSecret, ∅) → wrappingKey
    Note over B: AES-GCM unwrap → primaryKey
    Note over B: Enter ready state
```

### Encrypt/decrypt operation

```mermaid
sequenceDiagram
    participant CLI
    participant S as Server
    participant B as Browser

    CLI->>S: POST /v2/request/{requestKey}/encrypt
    Note right of CLI: {E2EE payload encrypted to browser's static keys}
    S-->>B: pending request (via SSE)

    Note over B: Derive ECDH + ML-KEM keys from primaryKey
    Note over B: Decrypt E2EE request payload
    Note over B: Derive operation AES key from primaryKey
    Note over B: Perform encrypt/decrypt
    Note over B: Encrypt result with ephemeral transport keys

    B->>S: POST /v2/api/confirm
    Note right of B: {transport-encrypted result}
    S-->>CLI: result
```

## Security Properties

- **Passkey independence:** Changing a passkey changes the PRF output, but only requires re-wrapping the primary key — not re-deriving all keys
- **Password verification:** A successful AES-GCM unwrap authenticates both the passkey (PRF) and the password (Argon2id salt), replacing the separate password canary
- **Offline attack resistance:** Argon2id (128 MiB, 4 iterations) makes brute-forcing a weak password infeasible even with access to both the wrapped key and PRF output
- **Key binding:** AAD in both wrapping and derivation binds keys to the user ID, preventing cross-user key substitution
- **Rate limiting:** The server rate-limits delivery of the wrapped primary key to 5 per hour per user after WebAuthn authentication
- **No password normalization:** Passwords are treated as exact user-provided byte strings with no trimming, lowercasing, or Unicode normalization

## Threat Model Notes

The wrapped primary key blob is more sensitive than the old password canary.
An attacker who obtains this blob (e.g. via server compromise) and later also obtains the PRF output from a compromised authenticator could:

1. Without password: directly derive the wrapping key and unwrap the primary key
2. With password: attempt offline brute-force against the Argon2id-protected password

The Argon2id parameters are chosen to make scenario (2) infeasible for non-trivial passwords.
The rate limiter protects against harvesting the blob through repeated WebAuthn logins.
