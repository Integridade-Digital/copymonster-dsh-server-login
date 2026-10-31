/**
 * Auth routes: self-registration (→ pending), login, logout, and the current
 * identity. Registration always yields a `pending` user; an admin approves it.
 * @module dsh-server-login/web/routes/auth
 */

import type { FastifyPluginAsync } from 'fastify'
import { createHmac, randomUUID, timingSafeEqual } from 'node:crypto'
import { requireAuth } from '../middleware/authn.js'
import { homeRoot, userRoot } from '../../fs/workspace.js'
import { deriveKey, encrypt } from '../../crypto.js'
import { toPublicUser } from '../../db/types.js'
import {
  clearSessionCookie,
  hashPassword,
  hashSessionToken,
  newSessionToken,
  parseCookie,
  sessionCookie,
  verifyPassword,
} from '../auth.js'

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
    required: ['supabaseJwt', 'username'],
    additionalProperties: false,
    properties: {
      supabaseJwt: { type: 'string', minLength: 10, maxLength: 4096 },
      username: { type: 'string', minLength: 3, maxLength: 32, pattern: '^[a-zA-Z0-9_-]+$' },
    },
  },
} as const

function parseAndValidateSupabaseJwt(token: string, secret?: string): { sub: string; email?: string } | null {
  const parts = token.split('.')
  if (parts.length !== 3) return null
  const [headerB64, payloadB64, signatureB64] = parts
  if (!headerB64 || !payloadB64 || !signatureB64) return null

  if (secret && secret.trim() !== '') {
    const expectedSig = createHmac('sha256', secret)
      .update(`${headerB64}.${payloadB64}`)
      .digest('base64url')
    const sigBuf = Buffer.from(signatureB64)
    const expBuf = Buffer.from(expectedSig)
    if (sigBuf.length !== expBuf.length || !timingSafeEqual(sigBuf, expBuf)) {
      return null
    }
  }

  try {
    const payloadStr = Buffer.from(payloadB64, 'base64url').toString('utf8')
    const payload = JSON.parse(payloadStr)
    if (!payload || typeof payload !== 'object') return null
    if (typeof payload.sub !== 'string') return null
    if (typeof payload.exp === 'number' && payload.exp * 1000 < Date.now()) {
      return null
    }
    return { sub: payload.sub, email: payload.email }
  } catch {
    return null
  }
}

export const authRoutes: FastifyPluginAsync = async (app) => {
  app.post(
    '/api/auth/session-token',
    { schema: sessionTokenSchema, config: { rateLimit: { max: 20, timeWindow: '1 minute' } } },
    async (request, reply) => {
      const { supabaseJwt, username } = request.body as { supabaseJwt: string; username: string }
      const supabaseSecret = process.env.SUPABASE_JWT_SECRET ?? ''
      const jwtClaims = parseAndValidateSupabaseJwt(supabaseJwt, supabaseSecret)
      if (jwtClaims === null) {
        return reply.code(401).send({ error: 'invalid_supabase_jwt' })
      }

      let user = await app.db.findUserByUsername(username)
      if (user === undefined) {
        const id = jwtClaims.sub || randomUUID()
        const homeDir = homeRoot(userRoot(app.config.dataRoot, id))
        user = await app.db.createUser({
          id,
          username,
          passHash: 'supabase_sso_managed',
          role: 'active',
          homeDir,
        })
        await app.userFs.initUserRoot(id, user.uid ?? undefined)
        await app.db.audit(id, 'sso_provision', JSON.stringify({ username, email: jwtClaims.email }))
      }

      if (user.role === 'disabled') {
        return reply.code(403).send({ error: 'disabled' })
      }

      const token = newSessionToken()
      await app.db.createSession({
        tokenHash: hashSessionToken(token),
        userId: user.id,
        expiresAt: Date.now() + app.config.sessionTtlSeconds * 1000,
        ip: request.ip,
        userAgent: request.headers['user-agent'],
      })
      await app.db.audit(user.id, 'sso_login', null)

      reply.header(
        'set-cookie',
        sessionCookie(token, app.config.sessionTtlSeconds, app.config.secureCookies, app.config.cookieDomain),
      )

      const subUrl = app.config.baseDomain !== '' ? `https://${username.toLowerCase()}.${app.config.baseDomain}/` : `/u/${user.id}/dsh/`
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

      const token = newSessionToken()
      await app.db.createSession({
        tokenHash: hashSessionToken(token),
        userId: user.id,
        expiresAt: Date.now() + app.config.sessionTtlSeconds * 1000,
        ip: request.ip,
        userAgent: request.headers['user-agent'],
      })
      await app.db.audit(user.id, 'login', null)
      reply.header(
        'set-cookie',
        sessionCookie(token, app.config.sessionTtlSeconds, app.config.secureCookies, app.config.cookieDomain),
      )
      return { user: toPublicUser(user) }
    },
  )

  app.post('/api/auth/logout', async (request, reply) => {
    const token = parseCookie(request.headers.cookie, 'sid')
    if (token !== undefined) await app.db.deleteSession(hashSessionToken(token))
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
