// Signed session cookies + requireAuth. Covers the SSO handoff contract with
// the main app: a correctly signed cookie for a live DB session authenticates,
// while a forged, stale, or mismatched cookie is rejected before any handler.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import Fastify from 'fastify'
import { signSessionCookie, verifySessionCookie } from '../lib/web/session-cookie.js'
import { requireAuth } from '../lib/web/middleware/authn.js'

const SECRET = 'test-session-secret-32-characters!!'
const TTL = 3600

function nowSeconds() {
  return Math.floor(Date.now() / 1000)
}

function claims(overrides = {}) {
  return {
    u: 'user-1',
    s: '11111111-1111-1111-1111-111111111111',
    n: 'alice',
    jti: 'jti-1',
    iat: nowSeconds(),
    ...overrides,
  }
}

function makeUser(overrides = {}) {
  return {
    id: 'user-1',
    username: 'alice',
    pass_hash: 'x',
    role: 'active',
    home_dir: '/home/alice',
    api_key_ref: null,
    created_at: 1,
    approved_by: null,
    uid: 100001,
    supabase_sub: '11111111-1111-1111-1111-111111111111',
    ...overrides,
  }
}

function makeApp(row) {
  const app = Fastify()
  app.decorate('db', {
    findSessionWithUser: async () => (row === undefined ? undefined : row),
  })
  app.decorate('config', { sessionSecret: SECRET, sessionTtlSeconds: TTL })
  app.decorateRequest('user', null)
  app.get('/probe', { preHandler: requireAuth }, async (request) => ({ user: request.user }))
  return app
}

function probe(app, token) {
  return app.inject({
    method: 'GET',
    url: '/probe',
    headers: token === undefined ? {} : { cookie: `sid=${token}` },
  })
}

test('session cookie: round-trip returns the signed claims', () => {
  const value = claims()
  const token = signSessionCookie(value, SECRET)
  assert.deepEqual(verifySessionCookie(token, SECRET, nowSeconds(), TTL), value)
})

test('session cookie: a different secret is rejected', () => {
  const token = signSessionCookie(claims(), SECRET)
  assert.equal(verifySessionCookie(token, 'another-secret-32-characters!!!!!', nowSeconds(), TTL), null)
})

test('session cookie: a tampered payload is rejected', () => {
  const token = signSessionCookie(claims(), SECRET)
  const signature = token.slice(token.indexOf('.') + 1)
  const forged = `${Buffer.from(JSON.stringify(claims({ u: 'user-2' }))).toString('base64url')}.${signature}`
  assert.equal(verifySessionCookie(forged, SECRET, nowSeconds(), TTL), null)
})

test('session cookie: an expired cookie is rejected', () => {
  const token = signSessionCookie(claims({ iat: nowSeconds() - TTL - 1 }), SECRET)
  assert.equal(verifySessionCookie(token, SECRET, nowSeconds(), TTL), null)
})

test('session cookie: malformed values are rejected', () => {
  for (const value of ['', 'nope', '.', 'abc.', '.abc', 'a.b.c']) {
    assert.equal(verifySessionCookie(value, SECRET, nowSeconds(), TTL), null, value)
  }
})

test('auth: a valid signed cookie for a live session reaches the handler', async () => {
  const app = makeApp({ expiresAt: Date.now() + 60_000, user: makeUser() })
  const res = await probe(app, signSessionCookie(claims(), SECRET))
  assert.equal(res.statusCode, 200)
  assert.equal(res.json().user.username, 'alice')
  await app.close()
})

test('auth: a forged cookie is rejected with 401', async () => {
  const app = makeApp({ expiresAt: Date.now() + 60_000, user: makeUser() })
  const res = await probe(app, signSessionCookie(claims(), 'attacker-secret-32-characters!!!!!'))
  assert.equal(res.statusCode, 401)
  await app.close()
})

test('auth: a missing cookie is rejected with 401', async () => {
  const app = makeApp({ expiresAt: Date.now() + 60_000, user: makeUser() })
  const res = await probe(app, undefined)
  assert.equal(res.statusCode, 401)
  await app.close()
})

test('auth: an expired cookie is rejected with 401', async () => {
  const app = makeApp({ expiresAt: Date.now() + 60_000, user: makeUser() })
  const res = await probe(app, signSessionCookie(claims({ iat: nowSeconds() - TTL - 1 }), SECRET))
  assert.equal(res.statusCode, 401)
  await app.close()
})

test('auth: a signed cookie without a DB session is rejected with 401', async () => {
  const app = makeApp(undefined)
  const res = await probe(app, signSessionCookie(claims(), SECRET))
  assert.equal(res.statusCode, 401)
  await app.close()
})

test('auth: a revoked (expired) DB session is rejected with 401', async () => {
  const app = makeApp({ expiresAt: Date.now() - 1, user: makeUser() })
  const res = await probe(app, signSessionCookie(claims(), SECRET))
  assert.equal(res.statusCode, 401)
  await app.close()
})

test('auth: a cookie naming a different user id is rejected with 401', async () => {
  const app = makeApp({ expiresAt: Date.now() + 60_000, user: makeUser({ id: 'user-2' }) })
  const res = await probe(app, signSessionCookie(claims(), SECRET))
  assert.equal(res.statusCode, 401)
  await app.close()
})

test('auth: a cookie naming a different username is rejected with 401', async () => {
  const app = makeApp({ expiresAt: Date.now() + 60_000, user: makeUser({ username: 'bob' }) })
  const res = await probe(app, signSessionCookie(claims(), SECRET))
  assert.equal(res.statusCode, 401)
  await app.close()
})

test('auth: a cookie naming another Supabase subject is rejected with 401', async () => {
  const app = makeApp({
    expiresAt: Date.now() + 60_000,
    user: makeUser({ supabase_sub: '22222222-2222-2222-2222-222222222222' }),
  })
  const res = await probe(app, signSessionCookie(claims(), SECRET))
  assert.equal(res.statusCode, 401)
  await app.close()
})

test('auth: a disabled user is rejected with 401', async () => {
  const app = makeApp({ expiresAt: Date.now() + 60_000, user: makeUser({ role: 'disabled' }) })
  const res = await probe(app, signSessionCookie(claims(), SECRET))
  assert.equal(res.statusCode, 401)
  await app.close()
})
