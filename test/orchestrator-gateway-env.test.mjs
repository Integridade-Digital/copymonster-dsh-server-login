import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { LocalSpawner } from '../lib/supervisor/orchestrator.js'
import { verifyTenantToken } from '../lib/gateway/token-validator.js'

test('orchestrator baseEnv: common tenant receives gateway URL and session token, no master keys', async (t) => {
  const root = mkdtempSync(join(tmpdir(), 'spawner-env-test-'))
  t.after(() => {
    rmSync(root, { recursive: true, force: true })
  })

  const GATEWAY_SECRET = 'orchestrator-secret-key-32-chars-long'
  const config = {
    dataRoot: root,
    identityPublicKey: '',
    llmGatewayHost: '127.0.0.1',
    llmGatewayPort: 4010,
    gatewayInternalSecret: GATEWAY_SECRET,
  }

  const mockDb = {
    findUserById: async (id) => {
      if (id === 'tenant-1') {
        return { id: 'tenant-1', username: 'client-slug', role: 'active', uid: 10001 }
      }
      return undefined
    },
  }

  // Set platform keys in process.env
  const oldOrKey = process.env.OPENROUTER_API_KEY
  const oldDsKey = process.env.DEEPSEEK_API_KEY
  process.env.OPENROUTER_API_KEY = 'sk-or-platform-secret-never-leak'
  process.env.DEEPSEEK_API_KEY = 'sk-ds-platform-secret-never-leak'

  try {
    const spawner = new LocalSpawner(
      config,
      async () => 'sk-ds-user-key',
      async () => 10001,
      mockDb,
    )

    const env = await spawner['baseEnv']('tenant-1')

    // 1. Gateway URL and internal session token MUST be present
    assert.equal(env.COPYMONSTER_LLM_GATEWAY_URL, 'http://127.0.0.1:4010/internal/v1/llm')
    assert.ok(typeof env.COPYMONSTER_INTERNAL_SESSION_TOKEN === 'string')

    // 2. Token must be validly signed
    const tokenCheck = verifyTenantToken(env.COPYMONSTER_INTERNAL_SESSION_TOKEN, GATEWAY_SECRET)
    assert.equal(tokenCheck.valid, true)
    if (tokenCheck.valid) {
      assert.equal(tokenCheck.payload.sub, 'tenant-1')
      assert.equal(tokenCheck.payload.slug, 'client-slug')
    }

    // 3. Master keys MUST NOT be leaked to common tenant
    assert.equal(env.OPENROUTER_API_KEY, undefined)
    assert.equal(env.DEEPSEEK_API_KEY, undefined)
  } finally {
    if (oldOrKey !== undefined) process.env.OPENROUTER_API_KEY = oldOrKey
    else delete process.env.OPENROUTER_API_KEY
    if (oldDsKey !== undefined) process.env.DEEPSEEK_API_KEY = oldDsKey
    else delete process.env.DEEPSEEK_API_KEY
  }
})

test('orchestrator baseEnv: admin tenant retains platform keys', async (t) => {
  const root = mkdtempSync(join(tmpdir(), 'spawner-env-admin-test-'))
  t.after(() => {
    rmSync(root, { recursive: true, force: true })
  })

  const GATEWAY_SECRET = 'orchestrator-secret-key-32-chars-long'
  const config = {
    dataRoot: root,
    identityPublicKey: '',
    llmGatewayHost: '127.0.0.1',
    llmGatewayPort: 4010,
    gatewayInternalSecret: GATEWAY_SECRET,
  }

  const mockDb = {
    findUserById: async (id) => {
      if (id === 'admin-1') {
        return { id: 'admin-1', username: 'funel', role: 'admin', uid: 10000 }
      }
      return undefined
    },
  }

  const oldDsKey = process.env.DEEPSEEK_API_KEY
  process.env.DEEPSEEK_API_KEY = 'sk-ds-admin-key'

  try {
    const spawner = new LocalSpawner(
      config,
      async () => 'sk-ds-admin-key',
      async () => 10000,
      mockDb,
    )

    const env = await spawner['baseEnv']('admin-1')

    // Admin receives gateway info AND platform keys
    assert.equal(env.COPYMONSTER_LLM_GATEWAY_URL, 'http://127.0.0.1:4010/internal/v1/llm')
    assert.ok(typeof env.COPYMONSTER_INTERNAL_SESSION_TOKEN === 'string')
    assert.equal(env.DEEPSEEK_API_KEY, 'sk-ds-admin-key')
  } finally {
    if (oldDsKey !== undefined) process.env.DEEPSEEK_API_KEY = oldDsKey
    else delete process.env.DEEPSEEK_API_KEY
  }
})
