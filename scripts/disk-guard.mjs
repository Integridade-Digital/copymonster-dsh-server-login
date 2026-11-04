#!/usr/bin/env node
/**
 * Disk guard for the DSH host.
 *
 * Runs from a systemd timer. It reports the root filesystem usage, prunes
 * session logs older than the retention window, and reports per-tenant disk
 * usage so a plan's `storage_gb` can be reviewed.
 *
 * An idle user root is reported, never deleted: a tenant that has not written
 * for the whole retention window is still a live account, and removing its
 * home is an operator decision, not a timer's.
 *
 * Exit codes: 0 healthy, 1 at or above the critical threshold, 2 at or above
 * the warning threshold. systemd records the failure so the alert is visible
 * in `systemctl --failed`.
 *
 * Environment:
 *   DSH_GUARD_DATA_ROOT        tenant data root (default /var/lib/dsh-server-login)
 *   DSH_GUARD_WARN_PCT         warning threshold (default 80)
 *   DSH_GUARD_CRITICAL_PCT     critical threshold (default 90)
 *   DSH_GUARD_LOG_MAX_AGE_DAYS session-log retention (default 30)
 *   DSH_GUARD_ORPHAN_MAX_AGE_DAYS orphan-root retention (default 30)
 *   DSH_GUARD_DRY_RUN          "1" reports without deleting
 *   DSH_GUARD_PLAN_STORAGE_GB  JSON map of plan slug to storage ceiling in GB
 * @module dsh-server-login/scripts/disk-guard
 */

import { readdirSync, rmSync, statfsSync, statSync } from 'node:fs'
import { join } from 'node:path'
import { DatabaseSync } from 'node:sqlite'

const dataRoot = process.env.DSH_GUARD_DATA_ROOT ?? '/var/lib/dsh-server-login'
const warnPct = Number(process.env.DSH_GUARD_WARN_PCT ?? 80)
const criticalPct = Number(process.env.DSH_GUARD_CRITICAL_PCT ?? 90)
const logMaxAgeDays = Number(process.env.DSH_GUARD_LOG_MAX_AGE_DAYS ?? 30)
const orphanMaxAgeDays = Number(process.env.DSH_GUARD_ORPHAN_MAX_AGE_DAYS ?? 30)
const dryRun = process.env.DSH_GUARD_DRY_RUN === '1'
const planStorageGb = parsePlanStorage(process.env.DSH_GUARD_PLAN_STORAGE_GB)

const DAY_MS = 24 * 60 * 60 * 1000
const now = Date.now()

/** Structured line, so `journalctl -o json` and grep both work. */
function report(event, fields) {
  process.stdout.write(`${JSON.stringify({ event, at: new Date(now).toISOString(), ...fields })}\n`)
}

/** Root filesystem usage as a percentage. */
function rootUsagePct() {
  const stat = statfsSync('/')
  const total = stat.blocks * stat.bsize
  const free = stat.bavail * stat.bsize
  if (total === 0) return 0
  return Math.round(((total - free) / total) * 100)
}

/**
 * Parse the plan-to-storage map.
 * @param raw - JSON object keyed by plan slug.
 * @returns the map, empty when unset or invalid.
 */
function parsePlanStorage(raw) {
  if (raw === undefined || raw.trim() === '') return {}
  try {
    const parsed = JSON.parse(raw)
    if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) return {}
    const map = {}
    for (const [slug, value] of Object.entries(parsed)) {
      const gigabytes = Number(value)
      if (Number.isFinite(gigabytes) && gigabytes > 0) map[slug] = gigabytes
    }
    return map
  } catch {
    return {}
  }
}

/**
 * Read each user's plan slug from the orchestrator database.
 *
 * The guard only reports; it never writes to the database.
 * @param dbPath - path to the orchestrator SQLite file.
 * @returns a map of user id to plan slug.
 */
function readPlans(dbPath) {
  const plans = new Map()
  let db
  try {
    db = new DatabaseSync(dbPath, { readOnly: true })
    for (const row of db.prepare('SELECT id, plan_slug FROM users').all()) {
      if (typeof row.plan_slug === 'string') plans.set(row.id, row.plan_slug)
    }
  } catch {
    // A missing or locked database only costs the storage comparison.
  } finally {
    try { db?.close() } catch {}
  }
  return plans
}

/**
 * Remove files under `dir` older than the retention window.
 * @param dir - directory to prune.
 * @returns number of bytes removed.
 */
function pruneOldFiles(dir) {
  let removed = 0
  let entries
  try {
    entries = readdirSync(dir, { withFileTypes: true })
  } catch {
    return 0
  }
  for (const entry of entries) {
    const full = join(dir, entry.name)
    try {
      if (entry.isDirectory()) {
        removed += pruneOldFiles(full)
        continue
      }
      const stat = statSync(full)
      if (now - stat.mtimeMs <= logMaxAgeDays * DAY_MS) continue
      if (!dryRun) rmSync(full, { force: true })
      removed += stat.size
    } catch {}
  }
  return removed
}

/** Directory size in bytes, without following symlinks. */
function dirSize(dir) {
  let total = 0
  let entries
  try {
    entries = readdirSync(dir, { withFileTypes: true })
  } catch {
    return 0
  }
  for (const entry of entries) {
    const full = join(dir, entry.name)
    try {
      if (entry.isSymbolicLink()) continue
      if (entry.isDirectory()) total += dirSize(full)
      else total += statSync(full).size
    } catch {}
  }
  return total
}

const usage = rootUsagePct()
report('disk-usage', { percent: usage, warnPct, criticalPct, dryRun })

const plans = readPlans(join(dataRoot, 'server-login.db'))
let prunedBytes = 0
let tenantBytes = 0
let orphans = 0
let overStorage = 0

let userDirs = []
try {
  userDirs = readdirSync(join(dataRoot, 'users'), { withFileTypes: true })
    .filter(entry => entry.isDirectory())
    .map(entry => entry.name)
} catch {
  report('data-root-missing', { dataRoot })
}

for (const userId of userDirs) {
  const root = join(dataRoot, 'users', userId)
  const bytes = dirSize(root)
  tenantBytes += bytes
  const megabytes = Math.round(bytes / (1024 * 1024))
  report('tenant-usage', { userId, megabytes })

  // Storage ceiling is reported, not enforced: a tenant over its plan needs an
  // operator decision (upgrade, cleanup, or a hard block), not a silent delete.
  const plan = plans.get(userId)
  const ceilingGb = plan === undefined ? undefined : planStorageGb[plan]
  if (ceilingGb !== undefined) {
    const usedGb = bytes / 1024 ** 3
    if (usedGb > ceilingGb) {
      overStorage += 1
      report('tenant-over-storage', {
        userId,
        plan,
        usedGb: Number(usedGb.toFixed(2)),
        limitGb: ceilingGb,
      })
    }
  }

  prunedBytes += pruneOldFiles(join(root, 'home', 'logs'))

  // An orphan root is one whose directory has not been touched for the whole
  // retention window; a live tenant writes to it far more often.
  try {
    const age = now - statSync(root).mtimeMs
    if (age > orphanMaxAgeDays * DAY_MS) {
      orphans += 1
      report('tenant-orphan-candidate', { userId, idleDays: Math.round(age / DAY_MS) })
    }
  } catch {}
}

report('cleanup', {
  prunedMegabytes: Math.round(prunedBytes / (1024 * 1024)),
  tenantMegabytes: Math.round(tenantBytes / (1024 * 1024)),
  orphanCandidates: orphans,
  tenantsOverStorage: overStorage,
  dryRun,
})

if (usage >= criticalPct) {
  report('disk-critical', { percent: usage, freeGigabytes: Math.round((statfsSync('/').bavail * statfsSync('/').bsize) / 1024 ** 3) })
  process.exit(1)
}
if (usage >= warnPct) {
  report('disk-warning', { percent: usage })
  process.exit(2)
}
process.exit(0)
