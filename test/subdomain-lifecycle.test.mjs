// Tenant provisioning and spawn lifecycle (SEC-001 of the subdomain plan):
// a uid conflict must fail loudly, a failed spawn must not leave the tenant
// looking "starting", and a first visit must reach the login page (Fase 5).
import { test } from 'node:test'
import assert from 'node:assert/strict'
import Fastify from 'fastify'
import { dshRoutes } from '../lib/web/routes/dsh.js'
import { authRoutes } from '../lib/web/routes/auth.js'
import { registerDshProxy, parseSubdomain } from '../lib/supervisor/proxy.js'
import { hashSessionToken, newSessionToken } from '../lib/web/auth.js'
import { signSessionCookie } from '../lib/web/session-cookie.js'

const SECRET = 'subdomain-plan-session-secret-32-chars'
const BASE_DOMAIN = 'app.test'

function tenantUser(overrides = {}) {
  return {
    id: 'tenant-user-1',
    username: 'alice',
    role: 'active',
    home_dir: '/tmp/alice',
    api_key_ref: null,
    created_at: Date.now(),
    approved_by: null,
    uid: 100010,
    supabase_sub: 'sub-1',
    ...overrides,
  }
}

function sessionCookie(user) {
  const jti = newSessionToken()
  // `t`/`r` are what the proxy signs into the identity handshake; without them
  // the session counts as pre-handshake and forces a sign-in.
  const cookie = 'sid=' + signSessionCookie(
    {
      u: user.id,
      s: user.supabase_sub,
      n: user.username,
      jti,
      iat: Math.floor(Date.now() / 1000),
      t: 'tenant-1',
      r: 'owner',
    },
    SECRET,
  )
  return { cookie, jti, tokenHash: hashSessionToken(jti) }
}

/** Minimal server carrying the proxy and the routes it depends on. */
function makeApp({ user, lifecycle, launchError } = {}) {
  const app = Fastify({ trustProxy: false })
  const tenant = user ?? tenantUser()
  const sessions = new Map()
  const users = new Map([[tenant.id, tenant]])

  app.decorate('db', {
    findUserBySlug: async (slug) => [...users.values()].find((u) => u.username.toLowerCase() === slug.toLowerCase()),
    findUserById: async (id) => users.get(id),
    findUserByUsername: async (name) => [...users.values()].find((u) => u.username === name),
    findUserBySupabaseSub: async (sub) => [...users.values()].find((u) => u.supabase_sub === sub),
    findSessionWithUser: async (tokenHash) => {
      const row = sessions.get(tokenHash)
      if (row === undefined) return undefined
      return { expiresAt: row.expiresAt, user: users.get(row.userId) ?? tenant }
    },
    createSession: async ({ tokenHash, userId, expiresAt }) => { sessions.set(tokenHash, { userId, expiresAt }) },
    createUser: async ({ id, username, passHash, role, homeDir }) => {
      const created = { ...tenantUser(), id, username, pass_hash: passHash, role, home_dir: homeDir, supabase_sub: null }
      users.set(id, created)
      return created
    },
    setUserSupabaseSub: async (id, sub) => {
      const found = users.get(id)
      if (found !== undefined) found.supabase_sub = sub
    },
    setUserPlanLimits: async () => {},
    audit: async () => {},
  })
  app.decorate('config', {
    baseDomain: BASE_DOMAIN,
    dataRoot: '/tmp/dsh-subdomain-plan',
    deployMode: 'local',
    enablePatch: false,
    baseUid: 100000,
    mainAppUrl: 'https://app.copymonster.co',
    sessionSecret: SECRET,
    sessionTtlSeconds: 3600,
    secureCookies: false,
    cookieDomain: '',
    maxUploadBytes: 1024,
    logLevel: 'error',
  })
  app.decorate('userFs', {
    initUserRoot: async () => {},
    resolvePath: () => '/tmp/dsh-subdomain-plan/users/alice/ws',
    writeHandoff: async () => {},
  })
  app.decorate('supervisor', {
    status: async () => ({ main: undefined, watchdog: undefined }),
    endpointFor: async () => undefined,
    lifecycle: async () => lifecycle ?? { state: 'stopped' },
    async launch() {
      if (launchError !== undefined) throw launchError
      return { id: 'inst-1', userId: tenant.id, role: 'main', folder: '/x', port: 4242, status: 'starting' }
    },
    restartMain: async () => undefined,
    spawnWatchdog: async () => undefined,
    stop: async () => {},
    ensureFileService: async () => {},
  })
  app.decorate('identity', { sign: () => 'identity' })
  app.decorateRequest('user', null)

  return { app, tenant, sessions }
}

function host(slug = 'alice') {
  return { host: `${slug}.${BASE_DOMAIN}`, accept: 'text/html' }
}

test('Fase 5: parseSubdomain resolves only one-level tenant hosts', () => {
  assert.equal(parseSubdomain('alice.app.test', BASE_DOMAIN), 'alice')
  assert.equal(parseSubdomain('alice.app.test:443', BASE_DOMAIN), 'alice')
  assert.equal(parseSubdomain('app.test', BASE_DOMAIN), null)
  assert.equal(parseSubdomain('evil.test', BASE_DOMAIN), null)
})

test('Fase 5 / Teste D: a first visit before SSO redirects to login instead of 404 JSON', async () => {
  const { app } = makeApp()
  await registerDshProxy(app)
  const res = await app.inject({ method: 'GET', url: '/', headers: host() })
  assert.equal(res.statusCode, 302)
  assert.equal(res.headers.location, 'https://app.copymonster.co')
  await app.close()
})

test('Fase 5 / Teste D: a JSON client still receives 401, not a redirect', async () => {
  const { app } = makeApp()
  await registerDshProxy(app)
  const res = await app.inject({ method: 'GET', url: '/api/data', headers: { host: `alice.${BASE_DOMAIN}`, accept: 'application/json' } })
  assert.equal(res.statusCode, 401)
  await app.close()
})

test('Fase 5 / Teste D: a failed tenant reports 503 with a retry page, never the launching page', async () => {
  const { app, tenant, sessions } = makeApp({ lifecycle: { state: 'failed', lastError: 'ProvisioningConflict:uid' } })
  const { cookie, tokenHash } = sessionCookie(tenant)
  sessions.set(tokenHash, { expiresAt: Date.now() + 60_000 })
  await registerDshProxy(app)
  const res = await app.inject({ method: 'GET', url: '/', headers: { ...host(), cookie } })
  assert.equal(res.statusCode, 503)
  assert.match(res.body, /Tentar novamente/)
  assert.match(res.body, /ProvisioningConflict:uid/)
  await app.close()
})

test('Fase 5 / Teste D: a starting tenant keeps the launching page', async () => {
  const { app, tenant, sessions } = makeApp({ lifecycle: { state: 'starting' } })
  const { cookie, tokenHash } = sessionCookie(tenant)
  sessions.set(tokenHash, { expiresAt: Date.now() + 60_000 })
  await registerDshProxy(app)
  const res = await app.inject({ method: 'GET', url: '/', headers: { ...host(), cookie } })
  assert.equal(res.statusCode, 200)
  assert.match(res.body, /Iniciando|Carregando|loading/i)
  await app.close()
})

test('Fase 5 / status: reports state and lastError for a refused launch', async () => {
  const { app, tenant, sessions } = makeApp({ lifecycle: { state: 'failed', lastError: 'ProvisioningError' } })
  const { cookie, tokenHash } = sessionCookie(tenant)
  sessions.set(tokenHash, { expiresAt: Date.now() + 60_000 })
  await app.register(dshRoutes)
  const res = await app.inject({
    method: 'GET',
    url: '/api/dsh/status',
    headers: { host: `${BASE_DOMAIN}`, cookie },
  })
  assert.equal(res.statusCode, 200)
  const body = res.json()
  assert.equal(body.state, 'failed')
  assert.equal(body.lastError, 'ProvisioningError')
  await app.close()
})

test('Fase 5 / slug: the exchange refuses a username longer than 30 characters', async () => {
  const { app } = makeApp()
  const original = globalThis.fetch
  globalThis.fetch = async () => new Response(JSON.stringify({
    supabase_sub: '11111111-1111-1111-1111-111111111111',
    username: 'a'.repeat(31),
  }), { status: 200, headers: { 'content-type': 'application/json' } })
  try {
    await app.register(authRoutes)
    const res = await app.inject({
      method: 'POST',
      url: '/api/auth/session-token',
      headers: { authorization: 'Bearer valid.jwt.token' },
      payload: {},
    })
    assert.equal(res.statusCode, 502)
    assert.equal(res.json().error, 'sso_unavailable')
  } finally {
    globalThis.fetch = original
    await app.close()
  }
})

test('Fase 5 / Teste C: the exchange provisions the Linux account before answering', async () => {
  const { app } = makeApp()
  let provisioned = 0
  app.supervisor.ensureFileService = async () => { provisioned += 1 }
  const original = globalThis.fetch
  globalThis.fetch = async () => new Response(JSON.stringify({
    supabase_sub: '22222222-2222-2222-2222-222222222222',
    username: 'bobby',
  }), { status: 200, headers: { 'content-type': 'application/json' } })
  try {
    await app.register(authRoutes)
    const res = await app.inject({
      method: 'POST',
      url: '/api/auth/session-token',
      headers: { authorization: 'Bearer valid.jwt.token' },
      payload: {},
    })
    assert.equal(res.statusCode, 200)
    assert.equal(provisioned, 1)
  } finally {
    globalThis.fetch = original
    await app.close()
  }
})

test('Fase 5 / Teste C: a provisioning conflict fails the exchange with 503', async () => {
  const { app } = makeApp()
  app.supervisor.ensureFileService = async () => {
    const error = new Error('provisioning conflict')
    error.name = 'ProvisioningConflict'
    throw error
  }
  const original = globalThis.fetch
  globalThis.fetch = async () => new Response(JSON.stringify({
    supabase_sub: '33333333-3333-3333-3333-333333333333',
    username: 'caroline',
  }), { status: 200, headers: { 'content-type': 'application/json' } })
  try {
    await app.register(authRoutes)
    const res = await app.inject({
      method: 'POST',
      url: '/api/auth/session-token',
      headers: { authorization: 'Bearer valid.jwt.token' },
      payload: {},
    })
    assert.equal(res.statusCode, 503)
    assert.equal(res.json().error, 'workspace_provisioning_failed')
    assert.equal(res.headers['set-cookie'], undefined)
  } finally {
    globalThis.fetch = original
    await app.close()
  }
})
