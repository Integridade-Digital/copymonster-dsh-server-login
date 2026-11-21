import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, utimesSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { MasterCredentialsResolver, redactApiKey } from '../lib/supervisor/master-credentials.js'

test('master credentials: redactApiKey redacts safely', () => {
  assert.equal(redactApiKey(null), '[NOT_SET]')
  assert.equal(redactApiKey(''), '[NOT_SET]')
  assert.equal(redactApiKey('short'), '[REDACTED]')
  assert.equal(redactApiKey('sk-openrouter-secret-key-12345'), 'sk-open...2345')
})

test('master credentials: reads admin .credentials.yaml and resolves providers', async (t) => {
  const root = mkdtempSync(join(tmpdir(), 'master-cred-test-'))
  t.after(() => {
    rmSync(root, { recursive: true, force: true })
  })

  const adminId = 'admin-user-uuid'
  const adminHome = join(root, 'users', adminId, 'home')
  mkdirSync(adminHome, { recursive: true })

  const yamlContent = `
version: 1
refs:
  OPENROUTER_API_KEY: "sk-or-admin-vault-key"
  DEEPSEEK_API_KEY: "sk-ds-admin-vault-key"
`
  writeFileSync(join(adminHome, '.credentials.yaml'), yamlContent, 'utf8')

  const mockDb = {
    findUserByUsername: async (name) => {
      if (name === 'funel') return { id: adminId, role: 'admin' }
      return undefined
    },
    listPublicUsers: async () => [{ id: adminId, role: 'admin' }],
  }

  const resolver = new MasterCredentialsResolver({
    db: mockDb,
    dataRoot: root,
  })

  const openrouterKey = await resolver.resolveKeyForProvider('openrouter')
  assert.equal(openrouterKey, 'sk-or-admin-vault-key')

  const deepseekKey = await resolver.resolveKeyForProvider('deepseek')
  assert.equal(deepseekKey, 'sk-ds-admin-vault-key')

  const deepseekOfficialKey = await resolver.resolveKeyForProvider('deepseek-official')
  assert.equal(deepseekOfficialKey, 'sk-ds-admin-vault-key')

  const unknown = await resolver.resolveKeyForProvider('nonexistent')
  assert.equal(unknown, undefined)
})

test('master credentials: falls back to environment variables', async () => {
  const oldEnv = process.env.OPENROUTER_API_KEY
  process.env.OPENROUTER_API_KEY = 'sk-or-env-fallback'

  try {
    const mockDb = {
      findUserByUsername: async () => undefined,
      listPublicUsers: async () => [],
    }

    const resolver = new MasterCredentialsResolver({
      db: mockDb,
      dataRoot: '/tmp/nonexistent-dir',
    })

    const key = await resolver.resolveKeyForProvider('openrouter')
    assert.equal(key, 'sk-or-env-fallback')
  } finally {
    if (oldEnv !== undefined) {
      process.env.OPENROUTER_API_KEY = oldEnv
    } else {
      delete process.env.OPENROUTER_API_KEY
    }
  }
})

test('master credentials: cache invalidation on file mtime update', async (t) => {
  const root = mkdtempSync(join(tmpdir(), 'master-cred-cache-test-'))
  t.after(() => {
    rmSync(root, { recursive: true, force: true })
  })

  const adminId = 'admin-user-uuid'
  const adminHome = join(root, 'users', adminId, 'home')
  mkdirSync(adminHome, { recursive: true })
  const credPath = join(adminHome, '.credentials.yaml')

  writeFileSync(credPath, 'version: 1\nrefs:\n  OPENROUTER_API_KEY: "initial-key"\n', 'utf8')

  const mockDb = {
    findUserByUsername: async () => ({ id: adminId, role: 'admin' }),
    listPublicUsers: async () => [{ id: adminId, role: 'admin' }],
  }

  const resolver = new MasterCredentialsResolver({
    db: mockDb,
    dataRoot: root,
  })

  const key1 = await resolver.resolveKeyForProvider('openrouter')
  assert.equal(key1, 'initial-key')

  // Update file on disk
  writeFileSync(credPath, 'version: 1\nrefs:\n  OPENROUTER_API_KEY: "updated-key"\n', 'utf8')
  // Bump mtime to simulate passage of time
  const future = new Date(Date.now() + 5000)
  utimesSync(credPath, future, future)

  const key2 = await resolver.resolveKeyForProvider('openrouter')
  assert.equal(key2, 'updated-key')
})
