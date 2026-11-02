import assert from 'node:assert/strict'
import test from 'node:test'
import { buildUpstreamHeaders } from '../lib/supervisor/proxy.js'
import { apply } from '../lib/runtime.js'

test('proxy replaces client forwarding headers with canonical tenant host', () => {
  const headers = buildUpstreamHeaders({
    host: 'digital.copymonster.co',
    'x-forwarded-host': 'attacker.example',
    'x-forwarded-proto': 'http',
    cookie: 'sid=valid',
  }, 43127, 'digital.copymonster.co')
  assert.equal(headers.host, '127.0.0.1:43127')
  assert.equal(headers['x-forwarded-host'], 'digital.copymonster.co')
  assert.equal(headers['x-forwarded-proto'], 'https')
  assert.equal(headers.cookie, 'sid=valid')
})

test('tenant runtime /enter redirects through the DSH launch-token exchange', () => {
  const previousRole = process.env.DSH_SERVER_LOGIN_ROLE
  const previousDomain = process.env.DSH_SERVER_LOGIN_BASE_DOMAIN
  process.env.DSH_SERVER_LOGIN_ROLE = 'main'
  process.env.DSH_SERVER_LOGIN_BASE_DOMAIN = 'copymonster.co'
  let route
  const ctx = {
    inject(services, callback) {
      assert.deepEqual(services, ['webServer', 'connection'])
      callback({
        webServer: { register(value) { route = value; return () => {} } },
        connection: { authenticatedUrl: url => `${url}?token=one-time-launch` },
        effect(effect) { effect() },
      })
    },
  }
  try {
    apply(ctx)
    assert.equal(route.path, '/enter')
    const result = { status: undefined, headers: undefined, body: undefined }
    route.handler({ method: 'GET', headers: {
      'x-forwarded-host': 'digital.copymonster.co',
      'x-forwarded-proto': 'https',
    } }, {
      writeHead(status, headers) { result.status = status; result.headers = headers },
      end(body) { result.body = body },
    })
    assert.equal(result.status, 303)
    assert.equal(result.headers.location, 'https://digital.copymonster.co/?token=one-time-launch')
    assert.equal(result.headers['cache-control'], 'no-store')
  } finally {
    if (previousRole === undefined) delete process.env.DSH_SERVER_LOGIN_ROLE
    else process.env.DSH_SERVER_LOGIN_ROLE = previousRole
    if (previousDomain === undefined) delete process.env.DSH_SERVER_LOGIN_BASE_DOMAIN
    else process.env.DSH_SERVER_LOGIN_BASE_DOMAIN = previousDomain
  }
})

test('tenant runtime refuses invalid forwarded hosts and schemes', () => {
  const previousRole = process.env.DSH_SERVER_LOGIN_ROLE
  const previousDomain = process.env.DSH_SERVER_LOGIN_BASE_DOMAIN
  process.env.DSH_SERVER_LOGIN_ROLE = 'main'
  process.env.DSH_SERVER_LOGIN_BASE_DOMAIN = 'copymonster.co'
  let route
  try {
    apply({ inject(_services, callback) {
      callback({
        webServer: { register(value) { route = value; return () => {} } },
        connection: { authenticatedUrl: url => url },
        effect(effect) { effect() },
      })
    } })
    for (const headers of [
      { 'x-forwarded-host': 'attacker.example', 'x-forwarded-proto': 'https' },
      { 'x-forwarded-host': 'digital.copymonster.co', 'x-forwarded-proto': 'http' },
    ]) {
      let status
      route.handler({ method: 'GET', headers }, { writeHead(code) { status = code }, end() {} })
      assert.equal(status, 400)
    }
  } finally {
    if (previousRole === undefined) delete process.env.DSH_SERVER_LOGIN_ROLE
    else process.env.DSH_SERVER_LOGIN_ROLE = previousRole
    if (previousDomain === undefined) delete process.env.DSH_SERVER_LOGIN_BASE_DOMAIN
    else process.env.DSH_SERVER_LOGIN_BASE_DOMAIN = previousDomain
  }
})
