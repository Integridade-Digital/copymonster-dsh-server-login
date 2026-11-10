/**
 * Auth routes: self-registration (→ active), login, logout, password reset,
 * and the current identity. Registration creates an active user directly.
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
import { publicOriginForUser } from '../../supervisor/proxy.js'

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
  // The tenant subdomain calls this route cross-origin, so the browser sends an
  // OPTIONS preflight with `access-control-request-headers` but no credentials.
  // Those extra headers must not be rejected here; the handler still requires a
  // bearer token of its own.
  headers: {
    type: 'object',
    required: ['authorization'],
    properties: {
      authorization: { type: 'string', pattern: '^Bearer .+$' },
    },
  },
} as const

interface MainAppSession {
  sub: string
  username: string
  /** Plan slug the main app reported; absent when it could not read it. */
  planSlug?: string
  /** Tenant id the caller acts within, signed into the session for the tenant handshake. */
  tenantId?: string
  /** Role inside the tenant. */
  role?: 'owner' | 'admin' | 'member'
  /** Platform-operator flag. */
  isAdmin?: boolean
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
  const planSlug = record.plan_slug
  const validPlan = typeof planSlug === 'string' && /^[a-z0-9-]{1,32}$/.test(planSlug)
  const tenantId = record.tenant_id
  const validTenant = typeof tenantId === 'string'
    && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(tenantId)
  const role = record.role
  const validRole = role === 'owner' || role === 'admin' || role === 'member'
  return {
    ok: true,
    session: {
      sub,
      username,
      ...(validPlan ? { planSlug } : {}),
      ...(validTenant ? { tenantId } : {}),
      ...(validRole ? { role } : {}),
      isAdmin: record.is_admin === true,
    },
  }
}

/** Persist a session row and set its signed cookie. */
async function issueSession(
  app: FastifyInstance,
  request: FastifyRequest,
  reply: FastifyReply,
  user: User,
  identity: Pick<MainAppSession, 'tenantId' | 'role' | 'isAdmin'>,
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
  const token = signSessionCookie({
    u: user.id,
    s: user.supabase_sub,
    n: user.username,
    jti,
    iat: Math.floor(now / 1000),
    ...(identity.tenantId === undefined ? {} : { t: identity.tenantId }),
    ...(identity.role === undefined ? {} : { r: identity.role }),
    ...(identity.isAdmin === undefined ? {} : { a: identity.isAdmin }),
  }, app.config.sessionSecret)
  reply.header(
    'set-cookie',
    sessionCookie(token, app.config.sessionTtlSeconds, app.config.secureCookies, app.config.cookieDomain),
  )
}

export const authRoutes: FastifyPluginAsync = async (app) => {
  // The browser login page runs on the main app origin and calls this route on
  // the tenant subdomain. Both are same-site (one registrable domain), so the
  // session cookie travels, but the browser still requires CORS for the fetch.
  app.addHook('onRequest', async (request, reply) => {
    if ((request.raw.url ?? '').split('?')[0] !== '/api/auth/session-token') return
    const origin = request.headers.origin
    const allowedOrigins = [
      app.config.mainAppUrl,
      `https://app.${app.config.baseDomain}`,
      'https://app.copymonster.co',
    ].filter(Boolean)
    if (!origin || !allowedOrigins.includes(origin)) return
    reply.header('access-control-allow-origin', origin)
    reply.header('access-control-allow-credentials', 'true')
    reply.header('access-control-allow-headers', 'content-type, authorization')
    reply.header('access-control-allow-methods', 'POST, OPTIONS')
    reply.header('vary', 'origin')
  })

  app.options('/api/auth/session-token', async (_request, reply) => {
    return reply.code(204).send()
  })

  app.post(
    '/api/auth/session-token',
    { schema: sessionTokenSchema, config: { rateLimit: { max: 20, timeWindow: '1 minute' } } },
    async (request, reply) => {
      const authHeader = request.headers.authorization
      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return reply.code(401).send({ error: 'missing-or-invalid-bearer' })
      }
      const supabaseJwt = authHeader.slice(7)
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
          // A local password-only account with this slug is not proof that the
          // Supabase caller owns it. Linking it on the SSO exchange would hand
          // the workspace to whoever registers that slug in the main app, so the
          // exchange stops here and the owner must link explicitly.
          await app.db.audit(byName.id, 'sso_link_refused', JSON.stringify({ username, reason: 'account_link_required' }))
          return reply.code(409).send({ error: 'account_link_required' })
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
          await app.userFs.initUserRoot(sub, user.uid ?? undefined, publicOriginForUser(app.config.baseDomain, user.username))
          await app.db.audit(sub, 'sso_provision', JSON.stringify({ username }))
        }
      }

      if (user.role === 'disabled') return reply.code(403).send({ error: 'disabled' })
      if (user.role === 'pending') return reply.code(403).send({ error: 'pending_review' })

      // The plan travels with the exchange, so the spawner can size the tenant's
      // resource scope without the orchestrator ever querying Supabase.
      if (exchanged.session.planSlug !== undefined) {
        const limits = app.config.planLimits[exchanged.session.planSlug]
        await app.db.setUserPlanLimits(user.id, {
          planSlug: exchanged.session.planSlug,
          memoryMax: limits?.memoryMax ?? null,
          cpuQuota: limits?.cpuQuota ?? null,
          tasksMax: limits?.tasksMax ?? null,
        })
      }

      await issueSession(app, request, reply, user, exchanged.session)
      await app.db.audit(user.id, 'sso_login', null)

      const subUrl =
        app.config.baseDomain !== ''
          ? `https://${user.username.toLowerCase()}.${app.config.baseDomain}/`
          : `/u/${user.id}/dsh/`
      return { ok: true, user: toPublicUser(user), redirectUrl: subUrl }
    },
  )

  // Canonical user registration is hosted on the primary application.
  app.get('/register', async (_request, reply) => {
    return reply.redirect('https://app.copymonster.co/register', 302)
  })

  app.get('/register.html', async (_request, reply) => {
    return reply.redirect('https://app.copymonster.co/register', 302)
  })

  app.all('/api/auth/register', async (_request, reply) => {
    return reply.redirect('https://app.copymonster.co/register', 302)
  })

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

      // Password login carries no Supabase tenant identity; a tenant subdomain
      // requires the SSO exchange, which signs one.
      await issueSession(app, request, reply, user, {})
      await app.db.audit(user.id, 'login', null)
      const subUrl =
        app.config.baseDomain !== ''
          ? `https://${user.username.toLowerCase()}.${app.config.baseDomain}/`
          : `/u/${user.id}/dsh/`
      return { user: toPublicUser(user), redirectUrl: subUrl }
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

  const forgotSchema = {
    body: {
      type: 'object',
      required: ['email'],
      additionalProperties: false,
      properties: {
        email: { type: 'string', format: 'email', maxLength: 254 },
      },
    },
  } as const

  app.post(
    '/api/auth/forgot',
    { schema: forgotSchema, config: { rateLimit: { max: 3, timeWindow: '1 minute' } } },
    async (request, reply) => {
      const { email } = request.body as { email: string }
      const supabaseUrl = process.env.DSH_SERVER_LOGIN_SUPABASE_URL
      const supabaseAnonKey = process.env.DSH_SERVER_LOGIN_SUPABASE_ANON_KEY
      if (!supabaseUrl || !supabaseAnonKey) {
        return reply.code(500).send({ error: 'not_configured' })
      }
      const res = await fetch(`${supabaseUrl}/auth/v1/recover`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          apikey: supabaseAnonKey,
        },
        body: JSON.stringify({ email }),
      })
      if (!res.ok) {
        return reply.code(400).send({ error: 'request_failed' })
      }
      return { ok: true }
    },
  )

  const resetSchema = {
    body: {
      type: 'object',
      required: ['token', 'password'],
      additionalProperties: false,
      properties: {
        token: { type: 'string', minLength: 10, maxLength: 4096 },
        password: { type: 'string', minLength: 8, maxLength: 128 },
      },
    },
  } as const

  app.post(
    '/api/auth/reset',
    { schema: resetSchema, config: { rateLimit: { max: 5, timeWindow: '1 minute' } } },
    async (request, reply) => {
      const { token, password } = request.body as { token: string; password: string }
      const supabaseUrl = process.env.DSH_SERVER_LOGIN_SUPABASE_URL
      const supabaseAnonKey = process.env.DSH_SERVER_LOGIN_SUPABASE_ANON_KEY
      if (!supabaseUrl || !supabaseAnonKey) {
        return reply.code(500).send({ error: 'not_configured' })
      }
      const res = await fetch(`${supabaseUrl}/auth/v1/verify`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          apikey: supabaseAnonKey,
        },
        body: JSON.stringify({ token, type: 'recovery', password }),
      })
      if (!res.ok) {
        return reply.code(400).send({ error: 'invalid_token' })
      }
      return { ok: true }
    },
  )

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
