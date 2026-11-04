#!/usr/bin/env node
/**
 * Health probe for the DSH host.
 *
 * Runs from a short timer. It checks the three services, the two HTTP
 * surfaces, disk and memory, counts recent 5xx responses in the journal, and
 * posts one alert when anything fails. A failed check exits 1 so the unit
 * shows up in `systemctl --failed`; `DSH_ALERT_WEBHOOK` adds an out-of-band
 * notification (Telegram, Slack, or any endpoint that accepts JSON).
 *
 * Environment:
 *   DSH_MONITOR_APP_URL         main app health URL (default http://127.0.0.1:3080/api/healthz)
 *   DSH_MONITOR_APP_HOST        Host header for the probe (default app.copymonster.co)
 *   DSH_MONITOR_ORCHESTRATOR_URL  orchestrator URL (default http://127.0.0.1:3081/)
 *   DSH_MONITOR_SERVICES        space-separated units to require active
 *   DSH_MONITOR_DISK_PCT        disk threshold (default 85)
 *   DSH_MONITOR_MEMORY_PCT      memory threshold (default 90)
 *   DSH_MONITOR_5XX_LIMIT       tolerated 5xx in the window (default 20)
 *   DSH_MONITOR_WINDOW_MINUTES  journal window (default 5)
 *   DSH_ALERT_WEBHOOK           optional JSON webhook for the alert
 * @module dsh-server-login/scripts/monitor
 */

import { execFileSync } from 'node:child_process'
import { statfsSync } from 'node:fs'
import { freemem, totalmem } from 'node:os'

const appUrl = process.env.DSH_MONITOR_APP_URL ?? 'http://127.0.0.1:3080/api/healthz'
const appHost = process.env.DSH_MONITOR_APP_HOST ?? 'app.copymonster.co'
const orchestratorUrl = process.env.DSH_MONITOR_ORCHESTRATOR_URL ?? 'http://127.0.0.1:3081/'
const services = (process.env.DSH_MONITOR_SERVICES
  ?? 'copymonster.service dsh-orchestrator.service cloudflared.service')
  .split(/\s+/)
  .filter(name => name !== '')
const diskPct = Number(process.env.DSH_MONITOR_DISK_PCT ?? 85)
const memoryPct = Number(process.env.DSH_MONITOR_MEMORY_PCT ?? 90)
const fiveXxLimit = Number(process.env.DSH_MONITOR_5XX_LIMIT ?? 20)
const windowMinutes = Number(process.env.DSH_MONITOR_WINDOW_MINUTES ?? 5)
const webhook = process.env.DSH_ALERT_WEBHOOK ?? ''

const failures = []

/** Structured line, so journald and grep both work. */
function report(event, fields = {}) {
  process.stdout.write(`${JSON.stringify({ event, at: new Date().toISOString(), ...fields })}\n`)
}

/** Record one failed check. */
function fail(check, detail) {
  failures.push({ check, detail })
  report('check-failed', { check, detail })
}

/** Run a command and return its stdout, or undefined when it exits non-zero. */
function tryRun(command, args) {
  try {
    return execFileSync(command, args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim()
  } catch {
    return undefined
  }
}

// 1. Services.
for (const service of services) {
  const state = tryRun('systemctl', ['is-active', service])
  if (state === 'active') report('service-ok', { service })
  else fail('service', `${service} is ${state ?? 'unknown'}`)
}

// 2. HTTP surfaces.
async function probe(name, url, headers = {}) {
  try {
    const response = await fetch(url, { headers, signal: AbortSignal.timeout(10_000) })
    if (response.ok) report('http-ok', { name, status: response.status })
    else fail('http', `${name} answered ${response.status}`)
  } catch (error) {
    fail('http', `${name} unreachable: ${error instanceof Error ? error.message : String(error)}`)
  }
}

await probe('app', appUrl, { host: appHost })
await probe('orchestrator', orchestratorUrl)

// 3. Disk.
const stat = statfsSync('/')
const diskUsedPct = Math.round(((stat.blocks - stat.bavail) / stat.blocks) * 100)
report('disk', { percent: diskUsedPct, threshold: diskPct })
if (diskUsedPct >= diskPct) fail('disk', `${diskUsedPct}% used (threshold ${diskPct}%)`)

// 4. Memory.
const memoryUsedPct = Math.round(((totalmem() - freemem()) / totalmem()) * 100)
report('memory', { percent: memoryUsedPct, threshold: memoryPct })
if (memoryUsedPct >= memoryPct) fail('memory', `${memoryUsedPct}% used (threshold ${memoryPct}%)`)

// 5. Recent 5xx volume, as a coarse error-rate signal.
const since = `${windowMinutes} min ago`
const journal = tryRun('journalctl', [
  '--since', since,
  '--no-pager', '-o', 'cat',
  '-u', 'copymonster.service', '-u', 'dsh-orchestrator.service',
])
const fiveXx = journal === undefined ? 0 : (journal.match(/"statusCode":5\d\d/g) ?? []).length
report('http-5xx', { count: fiveXx, windowMinutes, limit: fiveXxLimit })
if (fiveXx > fiveXxLimit) fail('http-5xx', `${fiveXx} responses in ${windowMinutes} min (limit ${fiveXxLimit})`)

// 6. Alert.
if (failures.length === 0) {
  report('monitor-ok')
  process.exit(0)
}

const summary = failures.map(entry => `${entry.check}: ${entry.detail}`).join('; ')
report('monitor-failed', { failures: failures.length, summary })

if (webhook !== '') {
  try {
    await fetch(webhook, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ text: `CopyMonster alert: ${summary}` }),
      signal: AbortSignal.timeout(10_000),
    })
  } catch (error) {
    report('alert-webhook-failed', { detail: error instanceof Error ? error.message : String(error) })
  }
}

process.exit(1)
