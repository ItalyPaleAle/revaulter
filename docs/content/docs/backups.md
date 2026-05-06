---
title: "Backups"
weight: 28
---

Revaulter's database is critical state and must be backed up.

Even though request payloads and responses are encrypted with keys derived from passkeys, the database stores the wrapped key material that is required to use Revaulter with each passkey. If you lose the database, users will no longer be able to decrypt messages encrypted with a passkey or sign new digests.

Database loss is irrecoverable.

Back up the database regularly, keep backups outside the same host or volume, and test that you can restore them.

You should also preserve the **same `secretKey` from your configuration** because restores must use the original value.

## Built-in `backup` and `restore` subcommands

The `revaulter` server binary ships with `backup` and `restore` subcommands that produce a backend-agnostic snapshot of the database. The format contains data only and embeds the source schema migration level, so a backup taken from SQLite can be restored into PostgreSQL, or vice versa.

Both subcommands read the same configuration as the server and connect to the database at `databaseDSN`.

```bash
revaulter backup --out /backups/revaulter-$(date +%F).bak

# or stream it directly through another tool, e.g.
revaulter backup | gzip > /backups/revaulter-$(date +%F).bak.gz
```

Restore into an existing database, reading from stdin or from the path given via `-in`:

```bash
revaulter restore --in /backups/revaulter-2026-05-01.bak
```

The `restore` command applies migrations up to the schema level recorded in the backup before inserting rows; any newer migrations bundled with the binary are left for the application to run on its next startup. Restoring into a database that already contains data is not supported — restore into a fresh database.

> Stop the running Revaulter instance before restoring into its database.

## Direct database backups

### SQLite backups

With SQLite, the critical data is the database file itself.

In addition to the built-in `revaulter backup` subcommand above, you can use an application-aware backup such as SQLite's `.backup` command, or stop Revaulter briefly before copying the file. This avoids taking a backup from a live database file in an inconsistent state.

Store the backup on a different disk, host, or backup service.

Example:

```bash
sqlite3 /data/revaulter.db ".backup /backups/revaulter-$(date +%F).db"
```

### PostgreSQL backups

With PostgreSQL, in addition to the built-in `revaulter backup` subcommand above, you can use standard backup tooling such as `pg_dump` for logical backups, or physical backups and WAL archiving if you need point-in-time recovery. Make sure your backup strategy covers the Revaulter database, retains copies off-host, and is tested by restoring into a fresh PostgreSQL instance.

After restoring PostgreSQL, start Revaulter with the restored database and the same `secretKey` value that was used originally.
