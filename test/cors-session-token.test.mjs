import assert from 'node:assert/strict'
import test from 'node:test'
import { buildServer } from '../lib/web/server.js'
import { resolveConfig } from '../lib/config.js'

test('session-token responds with CORS headers on OPTIONS preflight and bypasses subdomain proxy', async () => {
  const previousEnv = { ...process.env }
  process.env.SESSION_SECRET = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
  process.env.DSH_SERVER_LOGIN_DATA_ROOT = '/tmp/dsh-test-data'
  process.env.DSH_SERVER_LOGIN_ENCRYPTION_SECRET = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
  process.env.DSH_SERVER_LOGIN_BASE_DOMAIN = 'copymonster.co'
  process.env.DSH_SERVER_LOGIN_MAIN_APP_URL = 'https://app.copymonster.co'
  process.env.DSH_SERVER_LOGIN_SUPABASE_URL = 'https://test.supabase.co'
  process.env.DSH_SERVER_LOGIN_SUPABASE_ANON_KEY = 'test-anon-key'

  const config = resolveConfig(process.env)
  const app = await buildServer(config)

  try {
    // 1. Loopback OPTIONS preflight
    const loopbackOptions = await app.inject({
      method: 'OPTIONS',
      url: '/api/auth/session-token',
      headers: {
        host: '127.0.0.1:3081',
        origin: 'https://app.copymonster.co',
        'access-control-request-method': 'POST',
        'access-control-request-headers': 'content-type',
      },
    })
    assert.equal(loopbackOptions.statusCode, 204)
    assert.equal(loopbackOptions.headers['access-control-allow-origin'], 'https://app.copymonster.co')
    assert.equal(loopbackOptions.headers['access-control-allow-credentials'], 'true')
    assert.ok(loopbackOptions.headers['access-control-allow-methods'].includes('POST'))
    assert.ok(loopbackOptions.headers['access-control-allow-methods'].includes('OPTIONS'))
    assert.equal(loopbackOptions.body, '')

    // 2. Tenant subdomain OPTIONS preflight
    const subdomainOptions = await app.inject({
      method: 'OPTIONS',
      url: '/api/auth/session-token',
      headers: {
        host: 'digital.copymonster.co',
        origin: 'https://app.copymonster.co',
        'access-control-request-method': 'POST',
        'access-control-request-headers': 'content-type',
      },
    })
    assert.equal(subdomainOptions.statusCode, 204)
    assert.equal(subdomainOptions.headers['access-control-allow-origin'], 'https://app.copymonster.co')
    assert.equal(subdomainOptions.headers['access-control-allow-credentials'], 'true')

    // 3. POST on tenant subdomain includes CORS headers
    const subdomainPost = await app.inject({
      method: 'POST',
      url: '/api/auth/session-token',
      headers: {
        host: 'digital.copymonster.co',
        origin: 'https://app.copymonster.co',
        'content-type': 'application/json',
      },
      payload: JSON.stringify({ supabaseJwt: 'invalid-jwt-token' }),
    })
    assert.equal(subdomainPost.headers['access-control-allow-origin'], 'https://app.copymonster.co')
    assert.equal(subdomainPost.headers['access-control-allow-credentials'], 'true')
  } finally {
    await app.close()
    for (const key of Object.keys(process.env)) {
      if (!(key in previousEnv)) delete process.env[key]
      else process.env[key] = previousEnv[key]
    }
  }
})
