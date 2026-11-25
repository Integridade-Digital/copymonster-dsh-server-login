import { test } from 'node:test'
import assert from 'node:assert/strict'
import { EventEmitter } from 'node:events'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { LocalSpawner } from '../lib/supervisor/orchestrator.js'

function makeSpawner(root) {
  const config = { dataRoot: root, identityPublicKey: '' }
  const db = { findUserById: async () => undefined }
  return new LocalSpawner(config, async () => null, async () => 10001, db)
}

function seedTenant(spawner, userId) {
  // The private maps are the only state `stop` and `teardown` read locally;
  // seeding them exercises the shutdown path without spawning a real process.
  spawner['mains'].set(userId, { id: `${userId}-main`, status: 'running' })
}

test('M-5: teardown stops many tenants concurrently, not one after another', async (t) => {
  const root = mkdtempSync(join(tmpdir(), 'spawner-teardown-'))
  t.after(() => rmSync(root, { recursive: true, force: true }))

  const spawner = makeSpawner(root)
  const tenants = Array.from({ length: 12 }, (_, i) => `tenant-${i}`)
  for (const id of tenants) seedTenant(spawner, id)

  const startedAt = performance.now()
  await spawner.teardown()
  const elapsed = performance.now() - startedAt

  // Serial stops with any per-tenant wait would add up; a concurrent teardown
  // finishes in well under a second for idle tenants.
  assert.ok(elapsed < 500, `teardown took ${elapsed.toFixed(0)}ms`)
  assert.equal(spawner['mains'].size, 0)
})

test('M-5: teardown destroys proxied WebSocket upstreams so the server can drain', async (t) => {
  const root = mkdtempSync(join(tmpdir(), 'spawner-teardown-'))
  t.after(() => rmSync(root, { recursive: true, force: true }))

  const spawner = makeSpawner(root)
  seedTenant(spawner, 'tenant-a')

  const destroyed = new Set()
  const upstream = new EventEmitter()
  upstream.destroy = () => destroyed.add('upstream')
  const browser = new EventEmitter()
  browser.destroy = () => destroyed.add('browser')
  spawner.registerWebSocket('tenant-a', upstream)
  spawner.registerWebSocket('tenant-a', browser)

  await spawner.teardown()

  assert.deepEqual([...destroyed].sort(), ['browser', 'upstream'])
  assert.equal(spawner['activeWsSockets'].size, 0)
})

test('M-5: teardown is idempotent across repeated shutdown calls', async (t) => {
  const root = mkdtempSync(join(tmpdir(), 'spawner-teardown-'))
  t.after(() => rmSync(root, { recursive: true, force: true }))

  const spawner = makeSpawner(root)
  seedTenant(spawner, 'tenant-a')
  seedTenant(spawner, 'tenant-b')

  await spawner.teardown()
  await spawner.teardown()

  assert.equal(spawner['mains'].size, 0)
  assert.equal(spawner['activeWsSockets'].size, 0)
})
