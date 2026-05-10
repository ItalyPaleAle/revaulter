---
title: "Unlocking ZFS-encrypted datasets at boot"
weight: 33
---

You can use Revaulter to protect the raw key for a ZFS encrypted dataset. The server stores only a wrapped JSON envelope on disk, and when the machine boots, a systemd unit asks a passkey holder to approve the unwrap and pipes the plaintext key directly into `zfs load-key`.

This example assumes you already have a running Revaulter server, the CLI installed on the ZFS host, and a ZFS pool named `tank`.

## CLI setup

First, set the Revaulter server URL and the request key copied from the web UI:

```bash
# Address of your Revaulter server
REVAULTER_SERVER="https://revaulter.example.com"

# Your request key, copied from the web UI
REVAULTER_REQUEST_KEY="AbCdEf0123456789GhIj"
```

Pin the server's anchor keys in a local trust store so the boot script can run non-interactively:

```bash
# Ensure the directory exists
mkdir -p /etc/revaulter/cli
chmod 0700 /etc/revaulter/cli

revaulter-cli trust \
  --server "$REVAULTER_SERVER" \
  --trust-store /etc/revaulter/cli/trust.json \
  --request-key "$REVAULTER_REQUEST_KEY"
```

## Wrap the dataset key

Pick the dataset name and the pool it belongs to:

```bash
# Name of the ZFS dataset to create
DATASET_NAME="tank/data"

# Name of the existing zpool which contains the dataset
ZPOOL_NAME="tank"

# Path where the wrapped key for the dataset is stored
JSON_KEY_FILE="/etc/revaulter/keys/$DATASET_NAME.json"

# Key label: this is arbitrary and lets you keep distinct sub-keys for different purposes
# Here we name it "zfs-<server hostname>"
REVAULTER_KEY_LABEL="zfs-$(hostname)"

# Additional authenticated data, helps with key binding (optional, but recommended)
REVAULTER_AAD="$(hostname):$DATASET_NAME"
```

Create the key directory, generate a random 32-byte ZFS key, and wrap it with Revaulter:

```bash
# Ensure the directory exists
mkdir -p "/etc/revaulter/keys/$(dirname "$DATASET_NAME")"
chmod 0700 "/etc/revaulter/keys/$(dirname "$DATASET_NAME")"

# Generate a random 32-byte key and wrap it with Revaulter
# The key is encoded as 64 hex chars, for ZFS keyformat=hex
openssl rand -hex 32 \
  | revaulter-cli encrypt \
      --server "$REVAULTER_SERVER" \
      --request-key "$REVAULTER_REQUEST_KEY" \
      --trust-store /etc/revaulter/cli/trust.json \
      --algorithm aes-256-gcm \
      --key-label "$REVAULTER_KEY_LABEL" \
      --input - \
      --aad "$(echo -n "$REVAULTER_AAD" | base64 -w0)" \
      --note "ZFS dataset $DATASET_NAME" \
      --format json \
  > "$JSON_KEY_FILE"
```

Approve the request in the Revaulter web UI. The resulting JSON envelope is safe to keep on an unencrypted partition because it cannot be unwrapped without making another request to Revaulter.

## Unlock helper

Create a helper script that waits for Revaulter to be reachable and prints the unwrapped ZFS key on stdout:

```bash
# Ensure the directory exists
mkdir -p "/etc/revaulter/unlock/$(dirname "$DATASET_NAME")"
chmod 0700 "/etc/revaulter/unlock/$(dirname "$DATASET_NAME")"

cat <<EOT > "/etc/revaulter/unlock/$DATASET_NAME.sh"
#!/usr/bin/env bash
set -euo pipefail

# Wait for the Revaulter server to be reachable
while ! curl -s "$REVAULTER_SERVER/healthz" > /dev/null; do
    >&2 echo "Waiting for the Revaulter server"
    sleep 3
done

# Sleep for a small random interval to avoid hitting rate-limiting when several units start at once
sleep \$[ ( \$RANDOM % 3 )  + 1 ]s

# Submit the decryption request and write the plaintext key to stdout
cat "/etc/revaulter/keys/$DATASET_NAME.json" \\
  | revaulter-cli decrypt \\
     --server "$REVAULTER_SERVER" \\
     --json - \\
     --request-key "$REVAULTER_REQUEST_KEY" \\
     --trust-store /etc/revaulter/cli/trust.json \\
     --note "ZFS dataset $DATASET_NAME" \\
     --format raw
EOT

chmod 0500 "/etc/revaulter/unlock/$DATASET_NAME.sh"
```

## Create the encrypted dataset

ZFS reads the key from stdin when `keylocation=prompt`, so pipe the helper output into `zfs create`:

```bash
zfs create \
  -o encryption=aes-256-gcm \
  -o keyformat=hex \
  -o keylocation=prompt \
  "$DATASET_NAME" \
  <<< "$(/etc/revaulter/unlock/$DATASET_NAME.sh)"
```

This triggers a Revaulter approval request because creating the dataset needs the plaintext key.

## systemd unit

Create a systemd unit that waits for networking and ZFS, unlocks the dataset if needed, and mounts it:

```bash
# Get the systemd-safe escaped name for the dataset
UNIT_NAME=$(systemd-escape "$DATASET_NAME")

# Write the unit file
cat <<EOT > "/etc/systemd/system/mount-$UNIT_NAME.service"
[Unit]
Description=Mount ZFS $DATASET_NAME
Requires=zfs.target network-online.target NetworkManager-wait-online.service
After=zfs.target network-online.target NetworkManager-wait-online.service
StartLimitIntervalSec=0

[Service]
Type=oneshot
RemainAfterExit=true
ExecStart=/bin/sh -c 'while ! zpool list | grep $ZPOOL_NAME; do sleep 1; done; (zfs get keystatus $DATASET_NAME | grep " available" && echo "Already unlocked" || /etc/revaulter/unlock/$DATASET_NAME.sh | zfs load-key $DATASET_NAME) && (zfs get mounted $DATASET_NAME | grep yes && echo "Already mounted: $DATASET_NAME" || zfs mount $DATASET_NAME)'
ExecStop=/bin/sh -c '(zfs get mounted $DATASET_NAME | grep yes && zfs umount $DATASET_NAME || echo "Already unmounted: $DATASET_NAME") && (zfs get keystatus $DATASET_NAME | grep " available" && zfs unload-key $DATASET_NAME || echo "Key already unloaded")'
Restart=on-failure
RestartSec=2s

[Install]
WantedBy=multi-user.target
EOT

chmod 0644 "/etc/systemd/system/mount-$UNIT_NAME.service"
```

Enable and start the unit:

```bash
systemctl daemon-reload
systemctl enable --now "mount-$UNIT_NAME.service"
```

When the host boots, the unit waits until the pool is imported, asks Revaulter to decrypt the wrapped key, and pauses until a passkey holder approves the request. The plaintext key is sent directly to `zfs load-key` and never needs to be stored on disk.

Services that depend on the encrypted dataset can declare `Requires=mount-tank-data.service` and `After=mount-tank-data.service` so they start only after the dataset is unlocked and mounted.
