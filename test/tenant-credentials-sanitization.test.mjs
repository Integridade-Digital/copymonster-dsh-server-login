import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { load as loadYaml } from 'js-yaml'
import { sanitizeTenantCredentials, LocalUserFs } from '../lib/fs/local-user-fs.js'

test('sanitizeTenantCredentials removes platform and sensitive keys from tenant .credentials.yaml', (t) => {
  const home = mkdtempSync(join(tmpdir(), 'tenant-sanitization-test-'))
  t.after(() => rmSync(home, { recursive: true, force: true }))

  const credPath = join(home, '.credentials.yaml')
  const initialYaml = `
version: 1
refs:
  OPENROUTER_API_KEY: "sk-or-v1-leaked-key-12345"
  DEEPSEEK_API_KEY: "dsk-leaked-key-9999"
  OPENAI_API_KEY: "sk-proj-leaked-openai-key"
  ANTHROPIC_API_KEY: "sk-ant-leaked-claude-key"
  SAFE_CUSTOM_VAR: "my-harmless-custom-value"
records:
  grant1: { tool: "test-tool" }
`
  writeFileSync(credPath, initialYaml, 'utf8')

  sanitizeTenantCredentials(home)

  const sanitized = loadYaml(readFileSync(credPath, 'utf8'))
  assert.equal(sanitized.version, 1)
  assert.equal(sanitized.refs.OPENROUTER_API_KEY, undefined)
  assert.equal(sanitized.refs.DEEPSEEK_API_KEY, undefined)
  assert.equal(sanitized.refs.OPENAI_API_KEY, undefined)
  assert.equal(sanitized.refs.ANTHROPIC_API_KEY, undefined)
  assert.equal(sanitized.refs.SAFE_CUSTOM_VAR, "my-harmless-custom-value")
  assert.deepEqual(sanitized.records, { grant1: { tool: "test-tool" } })
})

test('LocalUserFs.initUserRoot does not seed global credentials to regular tenants', async (t) => {
  const dataRoot = mkdtempSync(join(tmpdir(), 'dsh-prov-san-test-'))
  t.after(() => rmSync(dataRoot, { recursive: true, force: true }))

  const userFs = new LocalUserFs((id) => join(dataRoot, 'users', id))
  const tenantId = 'regular-tenant-uuid'
  await userFs.initUserRoot(tenantId, undefined, 'https://tenant.app.copymonster.co', { isAdmin: false })

  const tenantCredPath = join(dataRoot, 'users', tenantId, 'home', '.credentials.yaml')
  assert.equal(existsSync(tenantCredPath), false, '.credentials.yaml must not be created or seeded for regular tenants')
})

test('LocalUserFs.initUserRoot sanitizes pre-existing legacy .credentials.yaml for regular tenants', async (t) => {
  const dataRoot = mkdtempSync(join(tmpdir(), 'dsh-prov-san-legacy-'))
  t.after(() => rmSync(dataRoot, { recursive: true, force: true }))

  const tenantId = 'legacy-tenant-uuid'
  const tenantHome = join(dataRoot, 'users', tenantId, 'home')
  mkdirSync(tenantHome, { recursive: true })

  const tenantCredPath = join(tenantHome, '.credentials.yaml')
  writeFileSync(tenantCredPath, `
version: 1
refs:
  OPENROUTER_API_KEY: "sk-or-v1-legacy-master-key"
  SAFE_USER_REF: "safe-val"
`, 'utf8')

  const userFs = new LocalUserFs((id) => join(dataRoot, 'users', id))
  await userFs.initUserRoot(tenantId, undefined, 'https://legacy.app.copymonster.co', { isAdmin: false })

  const content = loadYaml(readFileSync(tenantCredPath, 'utf8'))
  assert.equal(content.refs.OPENROUTER_API_KEY, undefined)
  assert.equal(content.refs.SAFE_USER_REF, 'safe-val')
})

test('LocalUserFs.initUserRoot preserves .credentials.yaml for admin users', async (t) => {
  const dataRoot = mkdtempSync(join(tmpdir(), 'dsh-prov-admin-test-'))
  t.after(() => rmSync(dataRoot, { recursive: true, force: true }))

  const adminId = 'admin-user-uuid'
  const adminHome = join(dataRoot, 'users', adminId, 'home')
  mkdirSync(adminHome, { recursive: true })

  const adminCredPath = join(adminHome, '.credentials.yaml')
  writeFileSync(adminCredPath, `
version: 1
refs:
  OPENROUTER_API_KEY: "sk-or-v1-admin-configured-key"
`, 'utf8')

  const userFs = new LocalUserFs((id) => join(dataRoot, 'users', id))
  await userFs.initUserRoot(adminId, undefined, 'https://funel.copymonster.co', { isAdmin: true })

  const content = loadYaml(readFileSync(adminCredPath, 'utf8'))
  assert.equal(content.refs.OPENROUTER_API_KEY, 'sk-or-v1-admin-configured-key', 'admin credentials must be preserved')
})
