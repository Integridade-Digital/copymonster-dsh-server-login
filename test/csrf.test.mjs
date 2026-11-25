// M-2: SameSite=None session cookies span tenant subdomains, so mutating
// requests must prove a platform origin.
import assert from 'node:assert/strict'
import test from 'node:test'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { buildServer } from '../lib/web/server.js'
import { resolveConfig } from '../lib/config.js'
import { buildCsrfOriginPolicy, isAllowedMutation, isMutatingMethod } from '../lib/web/middleware/csrf.js'

const LOGIN_BODY = JSON.stringify({ username: 'nobody', password: 'nobody-pass-123' })

async function withServer(run) {
  const previousEnv = { ...process.env }
  const dataRoot = mkdtempSync(join(tmpdir(), 'dsh-csrf-test-'))
  process.env.NODE_ENV = 'test'
  process.env.SESSION_SECRET = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
  process.env.DSH_SERVER_LOGIN_DATA_ROOT = dataRoot
  process.env.DSH_SERVER_LOGIN_ENCRYPTION_SECRET = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
  process.env.DSH_SERVER_LOGIN_BASE_DOMAIN = 'copymonster.co'
  process.env.DSH_SERVER_LOGIN_COOKIE_DOMAIN = '.copymonster.co'
  process.env.DSH_SERVER_LOGIN_MAIN_APP_URL = 'https://app.copymonster.co'
  process.env.DSH_SERVER_LOGIN_SUPABASE_URL = 'not-a-url'
  process.env.DSH_SERVER_LOGIN_SUPABASE_ANON_KEY = 'test-anon-key'
  process.env.DSH_SERVER_LOGIN_SUPABASE_SERVICE_ROLE_KEY = 'test-service-role-key'

  const app = await buildServer(resolveConfig(process.env))
  try {
    await run(app)
  } finally {
    await app.close()
    rmSync(dataRoot, { recursive: true, force: true })
    process.env = previousEnv
  }
}

function login(app, headers) {
  return app.inject({
    method: 'POST',
    url: '/api/auth/login',
    headers: { 'content-type': 'application/json', ...headers },
    payload: LOGIN_BODY,
  })
}

test('CSRF: mutating methods are rejected from a foreign origin', async () => {
  await withServer(async (app) => {
    const res = await login(app, { host: '127.0.0.1:3081', origin: 'https://evil.example' })
    assert.equal(res.statusCode, 403)
    assert.deepEqual(res.json(), { error: 'csrf_origin_rejected' })
  })
})

test('CSRF: login accepts the main app, a tenant subdomain, and a platform referer', async () => {
  await withServer(async (app) => {
    const mainApp = await login(app, {
      host: '127.0.0.1:3081',
      origin: 'https://app.copymonster.co',
    })
    assert.equal(mainApp.statusCode, 401)

    const tenant = await login(app, {
      host: '127.0.0.1:3081',
      origin: 'https://digital.copymonster.co',
    })
    assert.equal(tenant.statusCode, 401)

    const referer = await login(app, {
      host: '127.0.0.1:3081',
      referer: 'https://app.copymonster.co/login',
    })
    assert.equal(referer.statusCode, 401)
  })
})

test('CSRF: a same-host custom domain is its own trusted origin', async () => {
  await withServer(async (app) => {
    const res = await login(app, {
      host: 'forms.example.org',
      origin: 'https://forms.example.org',
    })
    assert.equal(res.statusCode, 401)
  })
})

test('CSRF: lookalike and malformed origins are rejected', async () => {
  await withServer(async (app) => {
    const lookalike = await login(app, {
      host: '127.0.0.1:3081',
      origin: 'https://copymonster.co.evil.example',
    })
    assert.equal(lookalike.statusCode, 403)

    const opaque = await login(app, { host: '127.0.0.1:3081', origin: 'null' })
    assert.equal(opaque.statusCode, 403)
  })
})

test('CSRF: a tenant origin cannot carry a session cookie to another tenant', async () => {
  await withServer(async (app) => {
    const res = await app.inject({
      method: 'POST',
      url: '/api/auth/logout',
      headers: {
        host: 'victim.copymonster.co',
        origin: 'https://attacker.copymonster.co',
        cookie: 'sid=abc.def',
      },
    })
    assert.equal(res.statusCode, 403)
    assert.deepEqual(res.json(), { error: 'csrf_origin_rejected' })
  })
})

test('CSRF: the main app may still mutate a tenant with the shared cookie', async () => {
  await withServer(async (app) => {
    const res = await app.inject({
      method: 'POST',
      url: '/api/auth/logout',
      headers: {
        host: '127.0.0.1:3081',
        origin: 'https://app.copymonster.co',
        cookie: 'sid=abc.def',
      },
    })
    assert.equal(res.statusCode, 200)
  })
})

test('CSRF: a cookie-bearing request with no source is trusted only from loopback', async () => {
  await withServer(async (app) => {
    const external = await app.inject({
      method: 'POST',
      url: '/api/auth/logout',
      remoteAddress: '203.0.113.5',
      headers: { host: '127.0.0.1:3081', cookie: 'sid=abc.def' },
    })
    assert.equal(external.statusCode, 403)

    const loopback = await app.inject({
      method: 'POST',
      url: '/api/auth/logout',
      headers: { host: '127.0.0.1:3081', cookie: 'sid=abc.def' },
    })
    assert.equal(loopback.statusCode, 200)
  })
})

test('CSRF: safe methods and unauthenticated callers are not blocked', async () => {
  await withServer(async (app) => {
    const read = await app.inject({
      method: 'GET',
      url: '/api/auth/me',
      headers: { host: '127.0.0.1:3081', origin: 'https://evil.example' },
    })
    assert.equal(read.statusCode, 401)

    const preflight = await app.inject({
      method: 'OPTIONS',
      url: '/api/auth/session-token',
      headers: {
        host: '127.0.0.1:3081',
        origin: 'https://evil.example',
        'access-control-request-method': 'POST',
      },
    })
    assert.equal(preflight.statusCode, 204)

    const anonymous = await app.inject({
      method: 'POST',
      url: '/api/auth/logout',
      headers: { host: '127.0.0.1:3081' },
    })
    assert.equal(anonymous.statusCode, 200)
  })
})

test('CSRF: the decision is independent of route and only guards mutations', () => {
  assert.equal(isMutatingMethod('POST'), true)
  assert.equal(isMutatingMethod('put'), true)
  assert.equal(isMutatingMethod('DELETE'), true)
  assert.equal(isMutatingMethod('GET'), false)

  const policy = buildCsrfOriginPolicy({
    baseDomain: 'copymonster.co',
    cookieDomain: '.copymonster.co',
    mainAppUrl: 'https://app.copymonster.co',
    secureCookies: true,
  })
  assert.deepEqual(policy.platformHosts, ['copymonster.co'])
  assert.deepEqual(policy.cookieTrustedHosts, ['copymonster.co', 'app.copymonster.co'])
  assert.equal(policy.allowLoopback, false)

  const base = {
    method: 'POST',
    hosts: ['digital.copymonster.co'],
    remoteAddress: '203.0.113.5',
    hasSessionCookie: false,
  }
  assert.equal(isAllowedMutation({ ...base, origin: 'https://app.copymonster.co' }, policy), true)
  assert.equal(isAllowedMutation({ ...base, origin: 'https://evil.example' }, policy), false)
  assert.equal(
    isAllowedMutation({ ...base, hasSessionCookie: true, origin: 'https://copymonster.co' }, policy),
    true,
  )
  assert.equal(
    isAllowedMutation({ ...base, hasSessionCookie: true, origin: 'https://attacker.copymonster.co' }, policy),
    false,
  )
  assert.equal(
    isAllowedMutation({ ...base, origin: 'http://127.0.0.1:3080', hosts: ['127.0.0.1:3080'] }, policy),
    true,
  )
})
