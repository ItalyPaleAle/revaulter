---
title: "Backing up with restic"
weight: 34
---

[restic](https://restic.net) uses a single password to derive its repository encryption key. Storing that password unattended on the backup host largely defeats the point of having backups: anyone who pops the host gets the repository. Wrapping the password with Revaulter means the backup script gets the password only after a passkey holder approves.

## Setup

1. Pick a strong password and put it in a temporary file:

    ```bash
    openssl rand -base64 32 > /tmp/restic-pw
    ```

2. Initialize the repository with that password:

    ```bash
    RESTIC_PASSWORD_FILE=/tmp/restic-pw restic \
      --repo s3:s3.example.com/my-bucket \
      init
    ```

3. Wrap the password with Revaulter and save the envelope:

    ```bash
    revaulter-cli encrypt \
      --server https://revaulter.example.com \
      --request-key AbCdEf0123456789GhIj \
      --key-label restic-pw \
      --algorithm A256GCM \
      --input /tmp/restic-pw \
      > /etc/restic/pw-wrapped.json
    ```

4. Approve the request in the web UI, then shred the plaintext file:

    ```bash
    shred -u /tmp/restic-pw
    ```

## Running a backup

restic supports `--password-command`: a script that prints the repository password on stdout. Plug Revaulter into it:

```bash
#!/usr/bin/env bash
# /usr/local/bin/restic-password.sh
set -euo pipefail

revaulter-cli decrypt \
  --server https://revaulter.example.com \
  --request-key AbCdEf0123456789GhIj \
  --key-label restic-pw \
  --algorithm A256GCM \
  --json /etc/restic/pw-wrapped.json \
  --format raw \
  --note "restic backup" \
  --timeout 10m
```

Mark the script executable and run a backup:

```bash
chmod 0755 /usr/local/bin/restic-password.sh

restic \
  --password-command /usr/local/bin/restic-password.sh \
  --repo s3:s3.example.com/my-bucket \
  backup /var/data
```

restic invokes the script, the script blocks waiting for approval, the maintainer approves on their phone, and restic gets the password and runs the backup.

## Why this pattern works

- **The host can't restore on its own**: a compromised backup host cannot decrypt the repository even if the wrapped blob and the request key both leak.
- **One file to deploy**: the wrapped JSON is the only secret on the host, and it's useless without Revaulter.
- **Live audit trail**: every restore (or recurring backup) requires interactive approval, so unusual activity is visible in real time.
