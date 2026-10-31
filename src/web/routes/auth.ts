/**
 * Auth routes: self-registration (→ pending), login, logout, and the current
 * identity. Registration always yields a `pending` user; an admin approves it.
 * @module dsh-server-login/web/routes/auth
 */

import type { FastifyInstance, FastifyPluginAsync, FastifyReply, FastifyRequest } from 'fastify'
import { randomUUID } from 'node:crypto'
import { requireAuth } from '../middleware/authn.js'
import { homeRoot, userRoot } from '../../fs/workspace.js'
import { deriveKey, encrypt } from '../../crypto.js'
import { toPublicUser, type User } from '../../db/types.js'
import {
  clearSessionCookie,
  hashPassword,
  hashSessionToken,
  newSessionToken,
  parseCookie,
  sessionCookie,
  verifyPassword,
} from '../auth.js'
import { signSessionCookie, verifySessionCookie } from '../session-cookie.js'

const registerSchema = {
  body: {
    type: 'object',
    required: ['username', 'password'],
    additionalProperties: false,
    properties: {
      username: { type: 'string', minLength: 3, maxLength: 32, pattern: '^[a-zA-Z0-9_-]+$' },
      password: { type: 'string', minLength: 8, maxLength: 128 },
    },
  },
} as const

const loginSchema = {
  body: {
    type: 'object',
    required: ['username', 'password'],
    additionalProperties: false,
    properties: {
      username: { type: 'string', maxLength: 64 },
      password: { type: 'string', maxLength: 128 },
    },
  },
} as const

interface Credentials {
  username: string
  password: string
}

const sessionTokenSchema = {
  body: {
    type: 'object',
    required: ['supabaseJwt'],
    additionalProperties: false,
    properties: {
      supabaseJwt: { type: 'string', minLength: 10, maxLength: 4096 },
      username: { type: 'string', minLength: 3, maxLength: 32, pattern: '^[a-zA-Z0-9_-]+$' },
    },
  },
} as const

interface MainAppSession {
  sub: string
  username: string
}

type ExchangeResult =
  | { ok: true; session: MainAppSession }
  | { ok: false; reason: 'invalid' | 'forbidden' | 'unavailable'; detail?: string }

/** Read the main app's error code without trusting arbitrary response text. */
async function exchangeError(response: Response): Promise<string | undefined> {
  try {
    const body: unknown = await response.json()
    if (body === null || typeof body !== 'object') return undefined
    const error = (body as Record<string, unknown>).error
    return typeof error === 'string' && /^[a-z0-9-]{1,64}$/.test(error) ? error : undefined
  } catch {
    return undefined
  }
}

/**
 * Ask the main app to validate the Supabase access token and return the
 * canonical profile. The main app is the only component that talks to
 * Supabase Auth, so this control plane never parses a JWT itself.
 */
async function exchangeSupabaseSession(
  mainAppUrl: string,
  supabaseJwt: string,
): Promise<ExchangeResult> {
  let response: Response
  try {
    response = await fetch(`${mainAppUrl.replace(/\/+$/, '')}/api/auth/session-token`, {
      method: 'POST',
      headers: { authorization: `Bearer ${supabaseJwt}` },
      signal: AbortSignal.timeout(10_000),
    })
  } catch {
    return { ok: false, reason: 'unavailable' }
  }
  if (response.status === 401) return { ok: false, reason: 'invalid' }
  if (response.status === 403) {
    return { ok: false, reason: 'forbidden', detail: await exchangeError(response) }
  }
  if (!response.ok) return { ok: false, reason: 'unavailable' }

  let body: unknown
  try {
    body = await response.json()
  } catch {
    return { ok: false, reason: 'unavailable' }
  }
  if (body === null || typeof body !== 'object') return { ok: false, reason: 'unavailable' }
  const record = body as Record<string, unknown>
  const sub = record.supabase_sub
  const username = record.username
  if (typeof sub !== 'string' || !/^[A-Za-z0-9_-]{8,64}$/.test(sub)) {
    return { ok: false, reason: 'unavailable' }
  }
  if (typeof username !== 'string' || !/^[a-z0-9-]{1,32}$/.test(username)) {
    return { ok: false, reason: 'unavailable' }
  }
  return { ok: true, session: { sub, username } }
}

/** Persist a session row and set its signed cookie. */
async function issueSession(
  app: FastifyInstance,
  request: FastifyRequest,
  reply: FastifyReply,
  user: User,
): Promise<void> {
  const now = Date.now()
  const jti = newSessionToken()
  await app.db.createSession({
    tokenHash: hashSessionToken(jti),
    userId: user.id,
    expiresAt: now + app.config.sessionTtlSeconds * 1000,
    ip: request.ip,
    userAgent: request.headers['user-agent'],
  })
  const token = signSessionCookie(
    { u: user.id, s: user.supabase_sub, n: user.username, jti, iat: Math.floor(now / 1000) },
    app.config.sessionSecret,
  )
  reply.header(
    'set-cookie',
    sessionCookie(token, app.config.sessionTtlSeconds, app.config.secureCookies, app.config.cookieDomain),
  )
}

export const authRoutes: FastifyPluginAsync = async (app) => {
  app.post(
    '/api/auth/session-token',
    { schema: sessionTokenSchema, config: { rateLimit: { max: 20, timeWindow: '1 minute' } } },
    async (request, reply) => {
      const { supabaseJwt } = request.body as { supabaseJwt: string }
      const exchanged = await exchangeSupabaseSession(app.config.mainAppUrl, supabaseJwt)
      if (!exchanged.ok) {
        if (exchanged.reason === 'invalid') {
          return reply.code(401).send({ error: 'invalid_supabase_jwt' })
        }
        if (exchanged.reason === 'forbidden') {
          return reply.code(403).send({ error: exchanged.detail ?? 'sso_forbidden' })
        }
        return reply.code(502).send({ error: 'sso_unavailable' })
      }
      const { sub, username } = exchanged.session

      let user = await app.db.findUserBySupabaseSub(sub)
      if (user === undefined) {
        const byName = await app.db.findUserBySlug(username)
        if (byName !== undefined) {
          if (byName.supabase_sub !== null) {
            return reply.code(403).send({ error: 'username-taken-by-another-user' })
          }
          if (byName.role === 'disabled') return reply.code(403).send({ error: 'disabled' })
          if (byName.role === 'pending') return reply.code(403).send({ error: 'pending_review' })
          await app.db.setUserSupabaseSub(byName.id, sub)
          byName.supabase_sub = sub
          user = byName
          await app.db.audit(byName.id, 'sso_link', null)
        } else {
          if ((await app.db.findUserById(sub)) !== undefined) {
            return reply.code(403).send({ error: 'username-taken-by-another-user' })
          }
          const homeDir = homeRoot(userRoot(app.config.dataRoot, sub))
          user = await app.db.createUser({
            id: sub,
            username,
            passHash: 'supabase_sso_managed',
            role: 'active',
            homeDir,
          })
          await app.db.setUserSupabaseSub(sub, sub)
          user.supabase_sub = sub
          await app.userFs.initUserRoot(sub, user.uid ?? undefined)
          await app.db.audit(sub, 'sso_provision', JSON.stringify({ username }))
        }
      }

      if (user.role === 'disabled') return reply.code(403).send({ error: 'disabled' })
      if (user.role === 'pending') return reply.code(403).send({ error: 'pending_review' })

      await issueSession(app, request, reply, user)
      await app.db.audit(user.id, 'sso_login', null)

      const subUrl =
        app.config.baseDomain !== ''
          ? `https://${user.username.toLowerCase()}.${app.config.baseDomain}/`
          : `/u/${user.id}/dsh/`
      return { ok: true, user: toPublicUser(user), redirectUrl: subUrl }
    },
  )

  app.post(
    '/api/auth/register',
    { schema: registerSchema, config: { rateLimit: { max: 5, timeWindow: '1 minute' } } },
    async (request, reply) => {
      const { username, password } = request.body as Credentials
      if ((await app.db.findUserByUsername(username)) !== undefined) {
        return reply.code(409).send({ error: 'username_taken' })
      }
      const id = randomUUID()
      const homeDir = homeRoot(userRoot(app.config.dataRoot, id))
      const passHash = await hashPassword(password)
      // Create the user first so `initUserRoot` resolves the DB-assigned uid
      // (baseUid + row_id) instead of the hash fallback — the per-user Pods and
      // the DSH Pod must run as the *same* uid or the DSH cannot write its dirs.
      const user = await app.db.createUser({ id, username, passHash, role: 'pending', homeDir })
      await app.userFs.initUserRoot(id, user.uid ?? undefined)
      await app.db.audit(id, 'register', JSON.stringify({ username }))
      return reply.code(201).send({ user: { id, username, role: 'pending' } })
    },
  )

  app.post(
    '/api/auth/login',
    { schema: loginSchema, config: { rateLimit: { max: 10, timeWindow: '1 minute' } } },
    async (request, reply) => {
      const { username, password } = request.body as Credentials
      const user = await app.db.findUserByUsername(username)
      if (user === undefined || !(await verifyPassword(password, user.pass_hash))) {
        return reply.code(401).send({ error: 'invalid_credentials' })
      }
      if (user.role === 'pending') return reply.code(403).send({ error: 'pending_review' })
      if (user.role === 'disabled') return reply.code(403).send({ error: 'disabled' })

      await issueSession(app, request, reply, user)
      await app.db.audit(user.id, 'login', null)
      return { user: toPublicUser(user) }
    },
  )

  app.post('/api/auth/logout', async (request, reply) => {
    const token = parseCookie(request.headers.cookie, 'sid')
    if (token !== undefined) {
      const claims = verifySessionCookie(
        token,
        app.config.sessionSecret,
        Math.floor(Date.now() / 1000),
        app.config.sessionTtlSeconds,
      )
      if (claims !== null) await app.db.deleteSession(hashSessionToken(claims.jti))
    }
    reply.header('set-cookie', clearSessionCookie(app.config.secureCookies, app.config.cookieDomain))
    return { ok: true }
  })

  app.get('/api/auth/me', { preHandler: requireAuth }, async (request) => ({ user: request.user }))

  const keyAddSchema = {
    body: {
      type: 'object',
      required: ['name', 'apiKey'],
      additionalProperties: false,
      properties: {
        name: { type: 'string', minLength: 1, maxLength: 32 },
        apiKey: { type: 'string', minLength: 1, maxLength: 256 },
      },
    },
  } as const

  app.get('/api/me/keys', { preHandler: requireAuth }, async (request) => ({
    keys: await app.db.listCredentialKeys(request.user!.id),
  }))

  app.post('/api/me/keys', { preHandler: requireAuth, schema: keyAddSchema }, async (request, reply) => {
    const { name, apiKey } = request.body as { name: string; apiKey: string }
    const cleanName = name.trim()
    if (!/^[A-Za-z0-9\-_ .]{1,32}$/.test(cleanName)) {
      return reply.code(400).send({ error: 'invalid_name' })
    }
    // Header-safe charset only: reject spaces, quotes, non-ASCII, etc.
    if (!/^[A-Za-z0-9\-_.]{1,256}$/.test(apiKey)) {
      return reply.code(400).send({ error: 'invalid_api_key' })
    }
    const key = await app.db.setCredentialKey(
      request.user!.id,
      cleanName,
      encrypt(apiKey, deriveKey(app.config.encryptionSecret)),
    )
    await app.db.audit(request.user!.id, 'set_api_key', JSON.stringify({ name: cleanName }))
    // 换 key 后重建 DSH Pod：DEEPSEEK_API_KEY 是启动时从 Secret 快照进 env 的，
    // 不重建不会生效（docs/k8s.md §4.3 改 key 联动）。
    await app.supervisor.restartMain(request.user!.id)
    return { key }
  })

  app.post('/api/me/keys/:id/select', { preHandler: requireAuth }, async (request, reply) => {
    const { id } = request.params as { id: string }
    if (!(await app.db.selectCredentialKey(request.user!.id, id))) return reply.code(404).send({ error: 'not_found' })
    await app.supervisor.restartMain(request.user!.id)
    return { ok: true }
  })

  app.delete('/api/me/keys/:id', { preHandler: requireAuth }, async (request, reply) => {
    const { id } = request.params as { id: string }
    if (!(await app.db.deleteCredentialKey(request.user!.id, id))) return reply.code(404).send({ error: 'not_found' })
    return { ok: true }
  })
}
