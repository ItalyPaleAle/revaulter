# Examples

## Unlocking LUKS-encrypted drives at boot

You can use Revaulter to protect the encryption key for a LUKS volume. Instead of storing the key on disk or typing a passphrase at the console, a script calls `revaulter-cli` during boot and an admin approves the unlock from their phone.

### Setup

1. Generate a random key and encrypt the LUKS volume with it:

    ```bash
    dd if=/dev/urandom bs=32 count=1 | base64 > /tmp/disk-key.txt
    cryptsetup luksFormat /dev/sdX --key-file /tmp/disk-key.txt
    ```

2. Wrap the key with Revaulter:

    ```bash
    revaulter-cli encrypt \
      --server https://revaulter.example.com \
      --request-key AbCdEf0123456789GhIj \
      --key-label boot-disk \
      --algorithm aes-gcm-256 \
      --value "$(cat /tmp/disk-key.txt)"
    ```

3. Approve the request in the Revaulter web UI. The CLI outputs a JSON envelope with the ciphertext, nonce, and tag. Save this output (for example, in `/etc/revaulter/boot-disk.json`).

4. Securely delete the plaintext key:

    ```bash
    shred -u /tmp/disk-key.txt
    ```

### Boot script

Create a script that runs early in the boot process (e.g. a systemd unit that runs before the mount target):

```bash
#!/usr/bin/env bash
set -euo pipefail

REVAULTER_SERVER="https://revaulter.example.com"
REQUEST_KEY="AbCdEf0123456789GhIj"
KEY_LABEL="boot-disk"
WRAPPED_KEY="/etc/revaulter/boot-disk.json"

# Read the wrapped key components
CIPHERTEXT=$(jq -r '.value' "$WRAPPED_KEY")
NONCE=$(jq -r '.nonce' "$WRAPPED_KEY")
TAG=$(jq -r '.tag' "$WRAPPED_KEY")

# Ask Revaulter to decrypt — an admin must approve from their browser
PLAINTEXT_KEY=$(revaulter-cli decrypt \
  --server "$REVAULTER_SERVER" \
  --request-key "$REQUEST_KEY" \
  --key-label "$KEY_LABEL" \
  --algorithm aes-gcm-256 \
  --value "$CIPHERTEXT" \
  --nonce "$NONCE" \
  --tag "$TAG" \
  --raw \
  --note "boot unlock" \
  --timeout 10m)

# Unlock the LUKS volume
echo -n "$PLAINTEXT_KEY" | cryptsetup luksOpen /dev/sdX encrypted-root --key-file=-

# Clear the variable
unset PLAINTEXT_KEY
```

When the server boots, it pauses at this script and sends a webhook notification. The admin opens Revaulter on their phone, authenticates with their passkey, and approves the unlock. The disk key is decrypted in the admin's browser, returned to the CLI, and piped directly into `cryptsetup` — it never touches disk.

### systemd unit (optional)

```ini
[Unit]
Description=Unlock encrypted root via Revaulter
DefaultDependencies=no
Before=local-fs.target
After=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/revaulter-unlock.sh
RemainAfterExit=yes

[Install]
WantedBy=local-fs.target
```

## Encrypting large files with age and Revaulter

[age](https://github.com/FiloSottile/age) is a file encryption tool. You can use Revaulter to wrap the age private key so that decrypting files requires passkey approval.

### Setup

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
      --algorithm aes-gcm-256 \
      --value "$(base64 < age-key.txt)"
    ```

3. Approve the request in the Revaulter web UI. Save the CLI output (ciphertext, nonce, tag) to a file, for example `age-key-wrapped.json`.

4. Securely delete the plaintext age key:

    ```bash
    shred -u age-key.txt
    ```

You now have:

- The age **public key** (`age1...`) — safe to store anywhere, used for encryption
- The age **private key** wrapped by Revaulter (`age-key-wrapped.json`) — cannot be used without passkey approval

### Encrypting a file

Anyone with the public key can encrypt. No Revaulter interaction is needed:

```bash
age -r age1xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx \
  -o backup.tar.age \
  backup.tar
```

### Decrypting a file

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
  --algorithm aes-gcm-256 \
  --value "$CIPHERTEXT" \
  --nonce "$NONCE" \
  --tag "$TAG" \
  --raw \
  --output /dev/stdin \
  --note "age decrypt" \
  2>/dev/null \
  | age \
    --decrypt \
    -i - \
    -o backup.tar \
    backup.tar.age
```

### Why this pattern works

- **Encryption is unattended**: anyone with the age public key can encrypt files without Revaulter.
- **Decryption requires approval**: the age private key is wrapped by Revaulter, so decrypting always requires a passkey holder to approve.
- **The private key never lives on disk in plaintext** (after initial setup): it is stored only in Revaulter's encrypted envelope and briefly materialized in memory or a temporary file during decryption.
- **age handles the heavy lifting**: age is designed for encrypting large files efficiently; Revaulter protects only the small private key.
