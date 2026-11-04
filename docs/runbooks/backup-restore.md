# Backup and restore

Two artefacts cover the host: the orchestrator database and the tenant roots. The Supabase database is dumped only when `SUPABASE_DB_URL` is configured, because the project exposes no SQL endpoint.

## What runs

`dsh-backup.timer` runs `scripts/backup.mjs` daily at 03:30. Each run writes one directory under `/var/backups/copymonster/<timestamp>Z/`:

| File | Contents |
|---|---|
| `server-login.db.gz` | orchestrator SQLite, taken with `.backup` while the server holds it open |
| `users.tar.gz` | every tenant root: homes, profiles, workspaces, session logs |
| `secret-dsh-server-login.env` | orchestrator environment, mode `0600` |
| `secret-.env.systemd` | main app environment, mode `0600` |
| `manifest.json` | SHA-256 of each file, plus what was skipped and why |
| `supabase.dump` | `pg_dump -Fc`, only when `SUPABASE_DB_URL` is set |

Retention keeps the newest 7 runs and, beyond those, the first run of each month for 30 days.

## Restore the orchestrator database

```bash
systemctl stop dsh-orchestrator.service
cp /var/lib/dsh-server-login/server-login.db{,.before-restore}
gunzip -c /var/backups/copymonster/<stamp>Z/server-login.db.gz > /var/lib/dsh-server-login/server-login.db
chown root:root /var/lib/dsh-server-login/server-login.db
chmod 600 /var/lib/dsh-server-login/server-login.db
systemctl start dsh-orchestrator.service
sqlite3 /var/lib/dsh-server-login/server-login.db 'select count(*) from users;'
```

Sessions issued after the backup stop working; users sign in again through the normal SSO flow.

## Restore one tenant root

```bash
systemctl stop dsh-orchestrator.service
mv /var/lib/dsh-server-login/users/<userId> /var/lib/dsh-server-login/users/<userId>.before-restore
tar -xzf /var/backups/copymonster/<stamp>Z/users.tar.gz -C /var/lib/dsh-server-login users/<userId>
chown -R <uid>:<uid> /var/lib/dsh-server-login/users/<userId>
chmod 700 /var/lib/dsh-server-login/users/<userId> /var/lib/dsh-server-login/users/<userId>/home
systemctl start dsh-orchestrator.service
```

The tenant relaunches on the next page load.

## Restore Supabase

```bash
pg_restore --dbname="$SUPABASE_DB_URL" --clean --if-exists --no-owner --no-privileges \
  /var/backups/copymonster/<stamp>Z/supabase.dump
```

Without `SUPABASE_DB_URL`, Supabase is not covered by this backup. Use the dashboard's scheduled backups, or set the connection string and re-run `scripts/backup.mjs`.

## Verify a backup before trusting it

```bash
cd /var/backups/copymonster/<stamp>Z
sha256sum -c <(jq -r '.files | to_entries[] | "\(.value)  \(.key)"' manifest.json)
```

## Restore drill (run quarterly)

1. `gunzip -c server-login.db.gz > /tmp/drill.db && sqlite3 /tmp/drill.db 'select count(*) from users;'`
2. `tar -tzf users.tar.gz | head` and extract one tenant root into `/tmp`.
3. Confirm the extracted home contains `profiles/`, `sessions/` and `.credentials.yaml`.
4. Record the drill date and the counts in the operations log.
