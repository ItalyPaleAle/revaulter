---
title: "Encrypting local files with revaulter-edit"
weight: 12
---

`revaulter-edit` is a small utility for keeping local text files encrypted: notes, `.env` files, recovery codes, TLS keys, anything you want on disk but not in cleartext. Opening a file asks Revaulter to unwrap its encryption key, which you approve in the browser with your passkey, exactly like any other Revaulter operation.

## Installing

`revaulter-edit` ships in the same [release archives](https://github.com/ItalyPaleAle/revaulter/releases) as `revaulter-cli`, for Linux, macOS, and Windows.

There is also a container image, `ghcr.io/italypaleale/revaulter-edit:2`: see [using Docker](#using-docker) below.

## How it works

Each file is encrypted locally with its own random 256-bit key and saved in [JWE](https://datatracker.ietf.org/doc/html/rfc7516) format.

That key is never stored in cleartext on-disk. It is wrapped by Revaulter (using the same `encrypt` operation the CLI exposes) and the wrapped key (along with the other required info to unwrap it: the key label and algorithm), is stored in the JWE protected header. Opening the file submits a `decrypt` request to Revaulter and once you approve it in the browser, the file's contents are decrypted locally.

The contents of the file never leave your machine, so `revaulter-edit` can be used to encrypt larger files too.

> Each encrypted file is encoded as JWE and includes this info in the protected header:
>
> ```json
> {
>   "alg": "dir",
>   "enc": "A256GCM",
>   "revaulter": {
>     "v": 1,
>     "server": "https://revaulter.example.com",
>     "keyLabel": "notes",
>     "algorithm": "A256GCM",
>     "wrappedKey": "<base64url>",
>     "wrappedKeyNonce": "<base64url>",
>     "wrappedKeyTag": "<base64url>"
>   }
> }
> ```

## Commands

`revaulter-edit` has three sub-commands, and they all take the path of a local file.

`edit` is the default: running `revaulter-edit FILE` is the same as `revaulter-edit edit FILE`.

### `edit`

Decrypts the file and opens it in your editor. Every time the editor saves, the contents are encrypted again and written back.

```bash
revaulter-edit [edit] [flags] FILE
```

If the file does not exist, a new random key is generated and wrapped with Revaulter, and the file is created the first time the editor saves.

The decrypted contents only ever live in a temporary file that only your user can read, which is overwritten and deleted when the editor exits.

The editor is taken from `--editor` then the environmental variables `$VISUAL` and `$EDITOR`.

Editors that open the file in an existing window and return right away, such as `code` (Visual Studio Code) and `subl` (Sublime Text), are launched with the `--wait` flag automatically, so the session lasts for as long as the file is open. Pass `--no-auto-wait` to omit it.

### `cat`

Decrypts the file and writes its contents to stdout (logs go to stderr):

```bash
revaulter-edit cat [flags] FILE
```

### `write`

Reads the new contents of the file from stdin, encrypts them, and writes them back:

```bash
revaulter-edit write [flags] FILE
```

This is the counterpart of `cat`, for encrypting a file without opening an editor. It encrypts a file that already exists in cleartext:

```bash
revaulter-edit write secrets.txt.enc < secrets.txt
```

It updates one from a script:

```bash
echo "my-secret-pw" | revaulter-edit write password.enc
```

And it edits one with an editor `revaulter-edit` cannot launch itself, for example from inside a container:

```bash
revaulter-edit cat secrets.txt > /tmp/secrets
"$EDITOR" /tmp/secrets
revaulter-edit write secrets.txt < /tmp/secrets
```

If the file already exists, its own key is unwrapped and reused, so only the contents change. If it does not, a new random key is generated and wrapped, exactly as `edit` does.

Note that reading and writing are two separate operations, so the round trip above needs two approvals.

Replacing the contents of a file with nothing is refused unless `--allow-empty` is passed, so a pipe that produced no output does not quietly empty the file.

## Flags

Both sub-commands accept the same flags.

| Flag | Short | Required | Description |
| ------ | ------- | ---------- | ------------- |
| `--server` | `-s` | Yes | Address of the Revaulter server (e.g. `https://revaulter.example.com`). Can also be passed as env var `REVAULTER_SERVER` |
| `--request-key` | `-k` | Yes | Per-user request key (shown in the web UI after registration). Can also be passed as env var `REVAULTER_REQUEST_KEY` |
| `--key-label` | `-l` | For new files | Logical key label used to wrap the file's encryption key. Can also be passed as env var `REVAULTER_KEY_LABEL`. Files that already exist carry their own label, which always wins |
| `--algorithm` | `-a` | No | Algorithm used to wrap the file's encryption key: `A256GCM` (default) or `C20P` |
| `--editor` | | No | Editor to launch. Can also be passed as env var `VISUAL` or `EDITOR` |
| `--no-auto-wait` | | No | Do not add the `--wait` flag to editors that need it, such as `code` and `subl` |
| `--allow-empty` | | No | For `write` only: allow replacing the contents of the file with nothing |
| `--timeout` | `-t` | No | Timeout for the approval request, as a Go duration (e.g. `5m`) |
| `--note` | `-n` | No | Message displayed alongside the request. Defaults to the name of the file |
| `--insecure` | | No | Skip TLS certificate validation |
| `--no-h2c` | | No | Do not attempt connecting with HTTP/2 Cleartext when not using TLS |
| `--trust-store` | | No | Path to the anchor trust store, shared with `revaulter-cli` |
| `--no-trust-store` | | No | Skip anchor pinning and hybrid bundle verification |
| `--verbose` | `-V` | No | Show debug-level logs |

Anchor pinning works exactly as it does for `revaulter-cli`, and uses the same trust store. A server pinned with `revaulter-cli trust` is already trusted by `revaulter-edit`.

## Examples

Set the connection details once, then keep the commands short:

```bash
export REVAULTER_SERVER="https://revaulter.example.com"
export REVAULTER_REQUEST_KEY="AbCdEf0123456789GhIj"
export REVAULTER_KEY_LABEL="notes"
```

Create a new encrypted file, or edit an existing one:

```bash
revaulter-edit ~/notes/recovery-codes.txt
```

Read a file without opening an editor:

```bash
revaulter-edit cat ~/notes/recovery-codes.txt
```

Load an encrypted `.env` file into the environment of a single command:

```bash
set -a
eval "$(revaulter-edit cat ~/projects/app/.env.enc)"
set +a
```

Edit with VS Code, which is launched with `--wait` automatically:

```bash
revaulter-edit --editor code ~/notes/recovery-codes.txt
```

## Using Docker

The container image carries no editor, so it is built around `cat` and `write`: those cover reading a file, encrypting one, and updating one from a script.

To edit inside the container, supply an editor with `--editor` or `EDITOR`. It has to be statically linked, since the image has no shared libraries and no terminfo database. A `busybox-static` from the host works:

```bash
-v /bin/busybox:/bin/busybox:ro --editor "/bin/busybox vi"
```

Two volumes matter:

- The directory holding the files to work on, so the container can read and write them.
- A volume for the trust store, at `/data`. Anchor pins live there, and without it every run is a first contact: each command would prompt to pin the anchor again, and would fail outright when there is no terminal to prompt on.

Pin the server's anchor once, into a volume that later runs reuse:

```bash
docker run --rm -it \
  -v revaulter-trust:/data \
  ghcr.io/italypaleale/revaulter-cli:2 trust \
  --server https://revaulter.example.com \
  --request-key "$REQUEST_KEY"
```

Then read and write files, which need no terminal and so work in scripts:

```bash
docker run --rm \
  -v revaulter-trust:/data -v "$PWD:/work" \
  -e REVAULTER_SERVER -e REVAULTER_REQUEST_KEY \
  ghcr.io/italypaleale/revaulter-edit:2 cat /work/secrets.txt

docker run --rm -i \
  -v revaulter-trust:/data -v "$PWD:/work" \
  -e REVAULTER_SERVER -e REVAULTER_REQUEST_KEY -e REVAULTER_KEY_LABEL \
  ghcr.io/italypaleale/revaulter-edit:2 write /work/secrets.txt < secrets.txt
```

Editing a file on the host, with the contents never written there in cleartext by anything but your own editor, is the same two commands:

```bash
docker run --rm -v revaulter-trust:/data -v "$PWD:/work" \
  -e REVAULTER_SERVER -e REVAULTER_REQUEST_KEY \
  ghcr.io/italypaleale/revaulter-edit:2 cat /work/secrets.txt > /tmp/secrets
"$EDITOR" /tmp/secrets
docker run --rm -i -v revaulter-trust:/data -v "$PWD:/work" \
  -e REVAULTER_SERVER -e REVAULTER_REQUEST_KEY \
  ghcr.io/italypaleale/revaulter-edit:2 write /work/secrets.txt < /tmp/secrets
```

The container runs as a non-root user (UID 65532), so the mounted files and the trust store volume must be readable, and writable, by that user.

## Notes and limitations

- Each save re-encrypts the whole file with a fresh nonce, but reuses the same content encryption key. Only opening the file requires approval, so a long editing session costs a single approval.
- `cat` fails if the file does not exist: only `edit` and `write` create files.
- The file records the server it was encrypted with. Pointing `--server` at a different server warns and then fails to unwrap the key, since the key label belongs to the original user's keys.
