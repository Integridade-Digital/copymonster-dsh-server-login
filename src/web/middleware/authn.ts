/**
 * Authentication / authorization guards.
 *
 * `resolveSessionUser` verifies the signed `sid` cookie and maps its `jti` to
 * the persisted session; `requireAuth` projects that user onto `request.user`,
 * and `requireAdmin` additionally enforces the admin role. Both guards reject
 * with 401/403 and never continue the handler.
 * @module dsh-server-login/web/middleware/authn
 */

import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify'
import type { User } from '../../db/types.js'
import { toPublicUser } from '../../db/types.js'
import { hashSessionToken, parseCookie } from '../auth.js'
import { verifySessionCookie } from '../session-cookie.js'

/**
 * Resolve a `Cookie` header into the authenticated user.
 *
 * The HMAC proves the cookie was issued here; the `sessions` row proves it was
 * not revoked or expired; the id/username/subject checks prove the DB session
 * still belongs to the identity the cookie names.
 * @param app - server carrying the DB adapter and session configuration.
 * @param cookieHeader - raw `Cookie` request header.
 * @returns the user, or undefined when the cookie is absent or invalid.
 */
export async function resolveSessionUser(
  app: Pick<FastifyInstance, 'db' | 'config'>,
  cookieHeader: string | undefined,
): Promise<User | undefined> {
  const token = parseCookie(cookieHeader, 'sid')
  if (token === undefined) return undefined
  const claims = verifySessionCookie(
    token,
    app.config.sessionSecret,
    Math.floor(Date.now() / 1000),
    app.config.sessionTtlSeconds,
  )
  if (claims === null) return undefined

  const row = await app.db.findSessionWithUser(hashSessionToken(claims.jti))
  if (row === undefined || row.expiresAt <= Date.now()) return undefined
  const user = row.user
  if (user.role === 'disabled') return undefined
  if (user.id !== claims.u || user.username !== claims.n) return undefined
  if (claims.s !== null && user.supabase_sub !== claims.s) return undefined
  return user
}

/** Resolve the session cookie into `request.user`, or reject 401. */
export async function requireAuth(request: FastifyRequest, reply: FastifyReply): Promise<void> {
  const user = await resolveSessionUser(request.server, request.headers.cookie)
  if (user === undefined) {
    reply.code(401).send({ error: 'unauthorized' })
    return
  }
  request.user = toPublicUser(user)
}

/** Require an authenticated admin; rejects non-admins with 403. */
export async function requireAdmin(request: FastifyRequest, reply: FastifyReply): Promise<void> {
  await requireAuth(request, reply)
  if (request.user === null) return // requireAuth already sent the response
  if (request.user.role !== 'admin') {
    reply.code(403).send({ error: 'forbidden' })
    return
  }
}
