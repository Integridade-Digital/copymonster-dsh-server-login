// M-11: a short or missing gateway secret must fail the spawn, not fall back
// to the constant that used to live in the source tree.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { LocalSpawner } from '../lib/supervisor/orchestrator.js'

function spawnerWith(root, secret) {
  const config = { dataRoot: root, identityPublicKey: '', gatewayInternalSecret: secret, llmGatewayHost: '127.0.0.1', llmGatewayPort: 4010 }
  const db = { findUserById: async () => ({ id: 'tenant-1', username: 'slug', role: 'active', uid: 10001 }) }
  return new LocalSpawner(config, async () => null, async () => 10001, db)
}

for (const [label, secret] of [['absent', undefined], ['short', 'too-short-secret']]) {
  test(`M-11: a ${label} gateway secret refuses to mint a tenant token`, async (t) => {
    const root = mkdtempSync(join(tmpdir(), 'spawner-secret-'))
    t.after(() => rmSync(root, { recursive: true, force: true }))
    const spawner = spawnerWith(root, secret)
    await assert.rejects(() => spawner['baseEnv']('tenant-1'), /gatewayInternalSecret/)
  })
}

test('M-11: a strong secret still mints the token', async (t) => {
  const root = mkdtempSync(join(tmpdir(), 'spawner-secret-'))
  t.after(() => rmSync(root, { recursive: true, force: true }))
  const spawner = spawnerWith(root, 'a'.repeat(48))
  const env = await spawner['baseEnv']('tenant-1')
  assert.ok(env.COPYMONSTER_INTERNAL_SESSION_TOKEN)
})
