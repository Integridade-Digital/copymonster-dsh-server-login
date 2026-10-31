// SSO integration: the orchestrator exchanges the Supabase access token with
// the main app's `/api/auth/session-token`, binds the canonical profile to a
// local user, and issues a signed `sid` cookie that requireAuth accepts.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import Fastify from 'fastify'
import { authRoutes } from '../lib/web/routes/auth.js'

const SECRET = 'test-session-secret-32-characters!!'
const TTL = 3600
const SUB = '11111111-1111-1111-1111-111111111111'

function makeDb() {
  const users = []
  const usersBySub = new Map()
  const sessions = new Map()
  let nextUid = 100001

  return {
    users,
    sessions,
    async findUserBySupabaseSub(sub) {
      return usersBySub.get(sub)
    },
    async findUserByUsername(username) {
      return users.find((u) => u.username === username)
    },
    async findUserBySlug(slug) {
      return users.find((u) => u.username.toLowerCase() === slug.toLowerCase())
    },
    async findUserById(id) {
      return users.find((u) => u.id === id)
    },
    async setUserSupabaseSub(userId, sub) {
      const user = users.find((u) => u.id === userId)
      if (user === undefined) throw new Error('no user')
      user.supabase_sub = sub
      usersBySub.set(sub, user)
    },
    async createUser({ id, username, passHash, role, homeDir }) {
      const user = {
        id,
        username,
        pass_hash: passHash,
        role,
        home_dir: homeDir,
        api_key_ref: null,
        created_at: Date.now(),
        approved_by: null,
        uid: nextUid++,
        supabase_sub: null,
      }
      users.push(user)
      return user
    },
    async createSession({ tokenHash, userId, expiresAt }) {
      sessions.set(tokenHash, { userId, expiresAt })
    },
    async findSessionWithUser(tokenHash) {
      const session = sessions.get(tokenHash)
      if (session === undefined) return undefined
      const user = users.find((u) => u.id === session.userId)
      if (user === undefined) return undefined
      return { expiresAt: session.expiresAt, user }
    },
    async deleteSession(tokenHash) {
      sessions.delete(tokenHash)
    },
    async audit() {},
  }
}

function makeApp(db, overrides = {}) {
  const app = Fastify()
  const config = {
    sessionSecret: SECRET,
    sessionTtlSeconds: TTL,
    secureCookies: false,
    cookieDomain: '',
    dataRoot: '/tmp/dsh-sso-test',
    baseDomain: 'app.test',
    mainAppUrl: 'http://main.test',
    ...overrides,
  }
  app.decorate('db', db)
  app.decorate('config', config)
  app.decorate('userFs', { initUserRoot: async () => {} })
  app.decorate('supervisor', { restartMain: async () => {} })
  app.decorateRequest('user', null)
  app.register(authRoutes)
  return app
}

function sso(app, body) {
  return app.inject({
    method: 'POST',
    url: '/api/auth/session-token',
    payload: body,
  })
}

function cookieFrom(res) {
  const header = res.headers['set-cookie']
  const value = Array.isArray(header) ? header[0] : header
  if (typeof value !== 'string') throw new Error('no set-cookie')
  return value.split(';')[0]
}

function stubMainApp(t, result) {
  const calls = []
  const original = globalThis.fetch
  globalThis.fetch = async (url, init) => {
    calls.push({ url: String(url), authorization: init?.headers?.authorization })
    if (result instanceof Error) throw result
    return new Response(JSON.stringify(result.body), {
      status: result.status,
      headers: { 'content-type': 'application/json' },
    })
  }
  t.after(() => {
    globalThis.fetch = original
  })
  return calls
}

test('sso: valid token creates the user and issues an accepted cookie', async (t) => {
  const db = makeDb()
  const app = makeApp(db)
  t.after(() => app.close())
  const calls = stubMainApp(t, { status: 200, body: { supabase_sub: SUB, username: 'alice' } })

  const res = await sso(app, { supabaseJwt: 'valid.jwt.token' })
  assert.equal(res.statusCode, 200)
  assert.equal(res.json().user.username, 'alice')
  assert.equal(res.json().redirectUrl, 'https://alice.app.test/')
  assert.equal(calls[0].url, 'http://main.test/api/auth/session-token')
  assert.equal(calls[0].authorization, 'Bearer valid.jwt.token')
  assert.equal(db.users.length, 1)
  assert.equal(db.users[0].id, SUB)
  assert.equal(db.users[0].supabase_sub, SUB)

  const me = await app.inject({ method: 'GET', url: '/api/auth/me', headers: { cookie: cookieFrom(res) } })
  assert.equal(me.statusCode, 200)
  assert.equal(me.json().user.username, 'alice')
})

test('sso: the body username cannot select another identity', async (t) => {
  const db = makeDb()
  const app = makeApp(db)
  t.after(() => app.close())
  stubMainApp(t, { status: 200, body: { supabase_sub: SUB, username: 'alice' } })

  const res = await sso(app, { supabaseJwt: 'valid.jwt.token', username: 'admin' })
  assert.equal(res.statusCode, 200)
  assert.equal(res.json().user.username, 'alice')
  assert.equal(db.users[0].username, 'alice')
})

test('sso: an existing username bound to another subject is rejected', async (t) => {
  const db = makeDb()
  const app = makeApp(db)
  t.after(() => app.close())
  await db.createUser({ id: 'other-id', username: 'alice', passHash: 'x', role: 'active', homeDir: '/tmp/a' })
  await db.setUserSupabaseSub('other-id', '22222222-2222-2222-2222-222222222222')
  stubMainApp(t, { status: 200, body: { supabase_sub: SUB, username: 'alice' } })

  const res = await sso(app, { supabaseJwt: 'valid.jwt.token' })
  assert.equal(res.statusCode, 403)
  assert.equal(res.json().error, 'username-taken-by-another-user')
})

test('sso: an existing unlinked username is adopted and linked', async (t) => {
  const db = makeDb()
  const app = makeApp(db)
  t.after(() => app.close())
  await db.createUser({ id: 'local-id', username: 'alice', passHash: 'x', role: 'active', homeDir: '/tmp/a' })
  stubMainApp(t, { status: 200, body: { supabase_sub: SUB, username: 'alice' } })

  const res = await sso(app, { supabaseJwt: 'valid.jwt.token' })
  assert.equal(res.statusCode, 200)
  assert.equal(db.users.length, 1)
  assert.equal(db.users[0].id, 'local-id')
  assert.equal(db.users[0].supabase_sub, SUB)
})

test('sso: an existing mixed-case username is adopted case-insensitively', async (t) => {
  const db = makeDb()
  const app = makeApp(db)
  t.after(() => app.close())
  await db.createUser({ id: 'local-id', username: 'Alice', passHash: 'x', role: 'active', homeDir: '/tmp/a' })
  stubMainApp(t, { status: 200, body: { supabase_sub: SUB, username: 'alice' } })

  const res = await sso(app, { supabaseJwt: 'valid.jwt.token' })
  assert.equal(res.statusCode, 200)
  assert.equal(db.users.length, 1)
  assert.equal(db.users[0].id, 'local-id')
  assert.equal(db.users[0].supabase_sub, SUB)
})

test('sso: a token the main app rejects returns 401', async (t) => {
  const db = makeDb()
  const app = makeApp(db)
  t.after(() => app.close())
  stubMainApp(t, { status: 401, body: { error: 'invalid_token' } })

  const res = await sso(app, { supabaseJwt: 'bad.jwt.token' })
  assert.equal(res.statusCode, 401)
  assert.equal(res.json().error, 'invalid_supabase_jwt')
})

test('sso: a forbidden main-app exchange is forwarded as 403', async (t) => {
  const db = makeDb()
  const app = makeApp(db)
  t.after(() => app.close())
  stubMainApp(t, { status: 403, body: { success: false, error: 'tenant-not-assigned' } })

  const res = await sso(app, { supabaseJwt: 'valid.jwt.token' })
  assert.equal(res.statusCode, 403)
  assert.equal(res.json().error, 'tenant-not-assigned')
})

test('sso: an unreachable main app returns 502', async (t) => {
  const db = makeDb()
  const app = makeApp(db)
  t.after(() => app.close())
  stubMainApp(t, new Error('ECONNREFUSED'))

  const res = await sso(app, { supabaseJwt: 'valid.jwt.token' })
  assert.equal(res.statusCode, 502)
  assert.equal(res.json().error, 'sso_unavailable')
  assert.equal(db.users.length, 0)
})

test('sso: a forged session cookie is rejected by /api/auth/me', async (t) => {
  const db = makeDb()
  const app = makeApp(db)
  t.after(() => app.close())
  stubMainApp(t, { status: 200, body: { supabase_sub: SUB, username: 'alice' } })

  const res = await sso(app, { supabaseJwt: 'valid.jwt.token' })
  const sid = cookieFrom(res).replace(/^sid=/, '')
  const payload = sid.slice(0, sid.indexOf('.'))
  const forged = `${payload}.${'A'.repeat(43)}`
  const me = await app.inject({ method: 'GET', url: '/api/auth/me', headers: { cookie: `sid=${forged}` } })
  assert.equal(me.statusCode, 401)
})
