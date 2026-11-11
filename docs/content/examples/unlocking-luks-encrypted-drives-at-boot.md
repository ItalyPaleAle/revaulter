---
title: "Unlocking LUKS-encrypted drives at boot"
weight: 32
---

You can use Revaulter to protect the encryption key of a LUKS volume. Instead of storing the key on disk or typing a passphrase at the console, a script calls `revaulter-cli` during boot, and an admin approves the unlock from their phone.

## Setup

1. Generate a random key and encrypt the LUKS volume with it:

    ```bash
    head -c 32 /dev/urandom > /tmp/disk-key.bin
    cryptsetup luksFormat /dev/sdX --key-file /tmp/disk-key.bin
    ```

2. Wrap the key with Revaulter, and save the result:

    ```bash
    revaulter-cli encrypt \
      --server https://revaulter.example.com \
      --request-key AbCdEf0123456789GhIj \
      --key-label boot-disk \
      --algorithm A256GCM \
      --input /tmp/disk-key.bin \
      > /etc/revaulter/boot-disk.json
    ```

3. Approve the request in the Revaulter web UI. The CLI writes a JSON envelope with the ciphertext, nonce, and tag to `/etc/revaulter/boot-disk.json`.

4. Securely delete the plaintext key:

    ```bash
    shred -u /tmp/disk-key.bin
    ```

## Boot script

Create a script that runs early in the boot process, for example with the systemd unit below, and save it as `/usr/local/bin/revaulter-unlock.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail

REVAULTER_SERVER="https://revaulter.example.com"
REQUEST_KEY="AbCdEf0123456789GhIj"
WRAPPED_KEY="/etc/revaulter/boot-disk.json"

# Ask Revaulter to decrypt the key, which an admin must approve in their browser, then unlock the LUKS volume with it
revaulter-cli decrypt \
  --server "$REVAULTER_SERVER" \
  --request-key "$REQUEST_KEY" \
  --json "$WRAPPED_KEY" \
  --format raw \
  --note "boot unlock" \
  --timeout 10m \
  | cryptsetup open /dev/sdX encrypted-data --key-file=-
```

When the server boots, it pauses at this script, and Revaulter sends a notification. The admin opens Revaulter on their phone, authenticates with their passkey, and approves the unlock. The disk key is decrypted in the admin's browser, returned to the CLI, and piped directly into `cryptsetup`, so it never touches the disk.

## systemd unit (optional)

```ini
[Unit]
Description=Unlock encrypted volume via Revaulter
DefaultDependencies=no
Before=local-fs.target
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/revaulter-unlock.sh
RemainAfterExit=yes

[Install]
WantedBy=local-fs.target
```
