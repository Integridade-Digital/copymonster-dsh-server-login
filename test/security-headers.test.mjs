// Every response this process serves carries the baseline security headers,
// including the launching page whose inline reload script the CSP allows
// (SEC-018).
import assert from 'node:assert/strict'
import test from 'node:test'
import { buildServer, ORCHESTRATOR_CSP } from '../lib/web/server.js'
import { resolveConfig } from '../lib/config.js'

async function withServer(run) {
  const previousEnv = { ...process.env }
  process.env.SESSION_SECRET = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
  process.env.DSH_SERVER_LOGIN_DATA_ROOT = '/tmp/dsh-test-headers'
  process.env.DSH_SERVER_LOGIN_ENCRYPTION_SECRET = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
  process.env.DSH_SERVER_LOGIN_BASE_DOMAIN = 'copymonster.co'
  process.env.DSH_SERVER_LOGIN_MAIN_APP_URL = 'https://app.copymonster.co'
  process.env.DSH_SERVER_LOGIN_SUPABASE_URL = 'https://test.supabase.co'
  process.env.DSH_SERVER_LOGIN_SUPABASE_ANON_KEY = 'test-anon-key'

  const config = resolveConfig(process.env)
  const app = await buildServer(config)
  try {
    await run(app)
  } finally {
    await app.close()
    process.env = previousEnv
  }
}

test('security headers are present on a JSON response', async () => {
  await withServer(async (app) => {
    const res = await app.inject({ method: 'GET', url: '/api/auth/me' })
    assert.equal(res.headers['x-content-type-options'], 'nosniff')
    assert.equal(res.headers['x-frame-options'], 'DENY')
    assert.equal(res.headers['referrer-policy'], 'strict-origin-when-cross-origin')
    assert.equal(res.headers['strict-transport-security'], 'max-age=31536000; includeSubDomains')
    assert.equal(res.headers['content-security-policy'], ORCHESTRATOR_CSP)
  })
})

test('the policy forbids framing and inline-script escapes', async () => {
  assert.match(ORCHESTRATOR_CSP, /frame-ancestors 'none'/)
  assert.match(ORCHESTRATOR_CSP, /default-src 'self'/)
  // The launching page reloads via an inline script; without 'unsafe-inline'
  // the page would never advance.
  assert.match(ORCHESTRATOR_CSP, /script-src 'self' 'unsafe-inline'/)
})

test('headers also cover a 404 from the orchestrator', async () => {
  await withServer(async (app) => {
    const res = await app.inject({ method: 'GET', url: '/nope' })
    assert.equal(res.headers['x-content-type-options'], 'nosniff')
    assert.equal(res.headers['x-frame-options'], 'DENY')
  })
})
