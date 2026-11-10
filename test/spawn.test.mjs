import test from 'node:test'
import assert from 'node:assert/strict'
import { existsSync, mkdirSync, rmSync } from 'node:fs'
import { resolveBinary, scrubEnv } from '../lib/supervisor/spawn.js'

test('resolveBinary falls back to basename when configured absolute path is missing', () => {
  if (!existsSync('/bin/setpriv')) return
  assert.equal(resolveBinary('/usr/bin/setpriv', '/usr/bin:/bin'), '/bin/setpriv')
})

test('resolveBinary resolves absolute binaries unchanged when they exist', () => {
  if (!existsSync('/bin/sh')) return
  assert.equal(resolveBinary('/bin/sh', '/usr/bin:/bin'), '/bin/sh')
})

test('resolveBinary resolves names from standard system directories', () => {
  if (!existsSync('/bin/sh')) return
  assert.equal(resolveBinary('sh', ''), '/bin/sh')
})

test('ensuring cwd directory exists prevents ENOENT on spawn', () => {
  const testDir = '/tmp/test-spawner-cwd-' + Date.now()
  mkdirSync(testDir, { recursive: true })
  assert.equal(existsSync(testDir), true)
  rmSync(testDir, { recursive: true, force: true })
})

test('scrubEnv keeps only the allowlist and never forwards Stripe or service-role secrets', () => {
  const scrubbed = scrubEnv({
    PATH: '/usr/bin:/bin',
    HOME: '/root',
    SUPABASE_URL: 'https://example.supabase.co',
    SUPABASE_ANON_KEY: 'anon',
    STRIPE_SECRET_KEY: 'sk_live_should_not_leak',
    STRIPE_WEBHOOK_SECRET: 'whsec_should_not_leak',
    SUPABASE_SERVICE_ROLE_KEY: 'service_role_should_not_leak',
    SESSION_SECRET: 'session_should_not_leak',
    AWS_SECRET_ACCESS_KEY: 'aws_should_not_leak',
  })

  assert.equal(scrubbed.SUPABASE_URL, 'https://example.supabase.co')
  assert.equal(scrubbed.SUPABASE_ANON_KEY, 'anon')
  assert.equal(scrubbed.HOME, '/root')
  for (const key of Object.keys(scrubbed)) {
    assert.ok(!key.startsWith('STRIPE_'), key)
    assert.ok(!/SERVICE_ROLE|SESSION_SECRET|SECRET_ACCESS_KEY/.test(key), key)
  }
  assert.ok(scrubbed.PATH.includes('/usr/bin'))
})
