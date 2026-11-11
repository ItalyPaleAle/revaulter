---
title: "Backups"
weight: 29
---

Revaulter's database is critical state and must be backed up.

The database stores each user's encrypted keys, which are needed to use Revaulter with a passkey.

If you lose the database, users can no longer decrypt data they encrypted with Revaulter, or sign anything with their existing signing keys.

Back up the database regularly, keep backups outside the same host or volume, and test that you can restore them.

Also keep a copy of the **`secretKey` from your configuration**, because a restored database works only with the original value.

> ⚠️ **Warning:** Without a backup and the `secretKey`, there's no way to recover from losing the database.

## Protecting backups

A backup contains the same data as the database, so protect it as carefully as the database itself:

- It includes every user's request key. Anyone with a request key can submit encrypt, decrypt, and sign requests as that user, although each request still needs the user's approval in the browser.
- It includes each passkey's wrapped primary key and anchor key. They can't be opened without the user's passkey (and password, if one is set), but they're what an attacker would need for an offline attack.

Backups made with `revaulter backup` aren't encrypted, and their checksum only detects accidental corruption, not deliberate changes.

Store backups encrypted, and limit who can read or write them. A backup tool that encrypts and authenticates its archives, such as restic or Borg, covers both. Don't encrypt Revaulter's backups with Revaulter: if you lose the database, you lose the keys you'd need to decrypt them.

## Built-in `backup` and `restore` subcommands

The `revaulter` server binary has `backup` and `restore` subcommands for a snapshot of the database that doesn't depend on the backend. The snapshot contains only data, plus the schema version it was taken from, so you can restore a backup taken from SQLite into PostgreSQL, or vice versa.

Both subcommands read the same configuration as the server and connect to the database at `databaseDSN`.

```bash
revaulter backup --out /backups/revaulter-$(date +%F).bak

# or stream it directly through another tool, e.g.
revaulter backup | gzip > /backups/revaulter-$(date +%F).bak.gz
```

Restore into an existing database, reading from stdin or from the path in `--in`:

```bash
revaulter restore --in /backups/revaulter-2026-05-01.bak
```

Before inserting rows, `restore` updates the schema to the version recorded in the backup. Any newer schema changes are applied the next time Revaulter starts. Always restore into an empty database: restoring into one that already contains data isn't supported.

> ⚠️ **Warning:** Stop the running Revaulter instance before restoring into its database.

> Backups do not include short-lived state such as pending requests.

## Direct database backups

### SQLite backups

With SQLite, the critical data is the database file itself.

Besides `revaulter backup`, you can use SQLite's `.backup` command, or stop Revaulter briefly before copying the file. Copying the file while Revaulter is running can produce an inconsistent backup.

Store the backup on a different disk, host, or backup service.

Example:

```bash
sqlite3 /data/revaulter.db ".backup /backups/revaulter-$(date +%F).db"
```

### PostgreSQL backups

With PostgreSQL, besides `revaulter backup`, you can use standard tools such as `pg_dump` for logical backups, or physical backups and WAL archiving if you need point-in-time recovery. Make sure your backups cover the Revaulter database, keep copies on another host, and test them by restoring into a new PostgreSQL instance.

A `pg_dump` of the database also includes the `francis` schema and the `v2_request_payloads` table, which hold only short-lived data. To exclude them, pass `--exclude-schema=francis --exclude-table-data=v2_request_payloads`.

After restoring PostgreSQL, start Revaulter with the restored database and the same `secretKey` value that was used originally.
