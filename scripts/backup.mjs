#!/usr/bin/env node
/**
 * Backup for the DSH host.
 *
 * One run produces a timestamped directory holding the orchestrator database,
 * every tenant root, and the deployment's secret files, plus a manifest with
 * sizes and SHA-256 digests so a restore can be verified.
 *
 * The Supabase database is dumped only when `SUPABASE_DB_URL` is set: the
 * project exposes no SQL endpoint, so without a connection string the run
 * records `supabase-dump-skipped` instead of pretending the dump exists.
 *
 * Retention keeps the newest `DSH_BACKUP_RETAIN_DAILY` runs and, beyond those,
 * the first run of each month for `DSH_BACKUP_RETAIN_MONTHLY_DAYS` days.
 *
 * Environment:
 *   DSH_BACKUP_DIR              destination (default /var/backups/copymonster)
 *   DSH_SERVER_LOGIN_DATA_ROOT  tenant roots (default /var/lib/dsh-server-login)
 *   SUPABASE_DB_URL             Postgres connection string, optional
 *   DSH_BACKUP_RETAIN_DAILY     daily runs to keep (default 7)
 *   DSH_BACKUP_RETAIN_MONTHLY_DAYS  monthly retention (default 30)
 *   DSH_BACKUP_SECRET_FILES     colon-separated extra files to archive
 * @module dsh-server-login/scripts/backup
 */

import { createHash } from 'node:crypto'
import { execFileSync } from 'node:child_process'
import {
  chmodSync,
  copyFileSync,
  createReadStream,
  existsSync,
  mkdirSync,
  readdirSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs'
import { basename, join } from 'node:path'

const backupDir = process.env.DSH_BACKUP_DIR ?? '/var/backups/copymonster'
const dataRoot = process.env.DSH_SERVER_LOGIN_DATA_ROOT ?? '/var/lib/dsh-server-login'
const supabaseDbUrl = process.env.SUPABASE_DB_URL ?? ''
const retainDaily = Number(process.env.DSH_BACKUP_RETAIN_DAILY ?? 7)
const retainMonthlyDays = Number(process.env.DSH_BACKUP_RETAIN_MONTHLY_DAYS ?? 30)
const secretFiles = (process.env.DSH_BACKUP_SECRET_FILES
  ?? '/etc/dsh-server-login.env:/root/copymonster-launch/.env.systemd')
  .split(':')
  .filter(file => file !== '')

const DAY_MS = 24 * 60 * 60 * 1000
const now = new Date()
const stamp = now.toISOString().replace(/[:.]/g, '-').replace('T', 'T').slice(0, 19) + 'Z'

/** Structured line, so journald and grep both work. */
function report(event, fields = {}) {
  process.stdout.write(`${JSON.stringify({ event, at: now.toISOString(), ...fields })}\n`)
}

/** Run one command, inheriting stderr so a failure is visible in the journal. */
function run(command, args) {
  execFileSync(command, args, { stdio: ['ignore', 'ignore', 'inherit'] })
}

/** SHA-256 of one file, streamed. */
function digest(file) {
  return new Promise((resolve, reject) => {
    const hash = createHash('sha256')
    const stream = createReadStream(file)
    stream.on('error', reject)
    stream.on('data', chunk => hash.update(chunk))
    stream.on('end', () => resolve(hash.digest('hex')))
  })
}

mkdirSync(backupDir, { recursive: true, mode: 0o700 })
const target = join(backupDir, stamp)
mkdirSync(target, { recursive: true, mode: 0o700 })

const manifest = { createdAt: now.toISOString(), host: process.env.HOSTNAME ?? 'unknown', files: {}, skipped: [] }

// 1. Orchestrator SQLite: `.backup` is safe while the server holds the file open.
const dbPath = join(dataRoot, 'server-login.db')
if (existsSync(dbPath)) {
  const snapshot = join(target, 'server-login.db')
  run('sqlite3', [dbPath, `.backup '${snapshot}'`])
  run('gzip', ['-f', snapshot])
  manifest.files['server-login.db.gz'] = join(target, 'server-login.db.gz')
} else {
  manifest.skipped.push('server-login.db')
  report('backup-skip', { item: 'server-login.db', reason: 'absent' })
}

// 2. Tenant roots: homes, profiles, workspaces and session logs.
const usersDir = join(dataRoot, 'users')
if (existsSync(usersDir)) {
  const archive = join(target, 'users.tar.gz')
  run('tar', ['-czf', archive, '-C', dataRoot, 'users'])
  manifest.files['users.tar.gz'] = archive
} else {
  manifest.skipped.push('users')
  report('backup-skip', { item: 'users', reason: 'absent' })
}

// 3. Secret files: copied, never archived into the tenant tree.
for (const file of secretFiles) {
  if (!existsSync(file)) {
    manifest.skipped.push(file)
    continue
  }
  const destination = join(target, `secret-${basename(file)}`)
  copyFileSync(file, destination)
  chmodSync(destination, 0o600)
  manifest.files[`secret-${basename(file)}`] = destination
}

// 4. Supabase, only with a real connection string.
if (supabaseDbUrl !== '') {
  const dump = join(target, 'supabase.dump')
  try {
    run('pg_dump', ['--no-owner', '--no-privileges', '-Fc', '-f', dump, supabaseDbUrl])
    manifest.files['supabase.dump'] = dump
  } catch {
    manifest.skipped.push('supabase.dump')
    report('backup-failed', { item: 'supabase.dump' })
  }
} else {
  manifest.skipped.push('supabase.dump')
  report('supabase-dump-skipped', { reason: 'SUPABASE_DB_URL is not set' })
}

// 5. Manifest with digests, so a restore can prove the archive is intact.
const digests = {}
for (const [name, file] of Object.entries(manifest.files)) digests[name] = await digest(file)
const finalManifest = { ...manifest, files: digests }
const manifestPath = join(target, 'manifest.json')
writeFileSync(manifestPath, `${JSON.stringify(finalManifest, null, 2)}\n`, { mode: 0o600 })
report('backup-created', { target, files: Object.keys(digests), skipped: manifest.skipped })

// 6. Retention: newest N runs, then the first run of each month.
const runs = readdirSync(backupDir, { withFileTypes: true })
  .filter(entry => entry.isDirectory())
  .map(entry => entry.name)
  .sort()
  .reverse()

const keep = new Set(runs.slice(0, retainDaily))
const seenMonths = new Set()
for (const run of runs.slice(retainDaily)) {
  const month = run.slice(0, 7)
  const age = now.getTime() - statSync(join(backupDir, run)).mtimeMs
  if (age > retainMonthlyDays * DAY_MS) continue
  if (seenMonths.has(month)) continue
  seenMonths.add(month)
  keep.add(run)
}

for (const run of runs) {
  if (keep.has(run)) continue
  rmSync(join(backupDir, run), { recursive: true, force: true })
  report('backup-pruned', { run })
}

report('backup-done', { kept: keep.size, pruned: runs.length - keep.size })
