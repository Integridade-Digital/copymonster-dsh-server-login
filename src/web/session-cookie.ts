/**
 * Signed session cookies shared with the main app.
 *
 * A cookie is `base64url(payload) + "." + base64url(HMAC-SHA256(payload))`.
 * The payload binds the local user id, the linked Supabase subject, the
 * canonical username, and the session jti; verification rejects tampering and
 * expiry before any database lookup. `jti` is the raw DB session token, so a
 * signed cookie authenticates only while its `sessions` row exists (logout
 * revokes it).
 * @module dsh-server-login/web/session-cookie
 */

import { createHmac, timingSafeEqual } from 'node:crypto'

/** Claims carried by a signed session cookie. */
export interface SessionClaims {
  /** Local user id. */
  u: string
  /** Linked Supabase Auth subject, or null for password-only users. */
  s: string | null
  /** Canonical username (the subdomain slug source). */
  n: string
  /** Raw session token whose hash is the `sessions.token_hash`. */
  jti: string
  /** Issue time, epoch seconds. */
  iat: number
}

function mac(payload: string, secret: string): string {
  return createHmac('sha256', secret).update(payload).digest('base64url')
}

function isClaims(value: unknown): value is SessionClaims {
  if (value === null || typeof value !== 'object') return false
  const claims = value as Record<string, unknown>
  return (
    typeof claims.u === 'string' &&
    (claims.s === null || typeof claims.s === 'string') &&
    typeof claims.n === 'string' &&
    typeof claims.jti === 'string' &&
    typeof claims.iat === 'number' &&
    Number.isFinite(claims.iat)
  )
}

/**
 * Sign session claims with `secret`.
 * @param claims - values to bind into the cookie.
 * @param secret - HMAC key shared with the main app.
 * @returns the cookie value to store under `sid`.
 */
export function signSessionCookie(claims: SessionClaims, secret: string): string {
  const payload = Buffer.from(JSON.stringify(claims)).toString('base64url')
  return `${payload}.${mac(payload, secret)}`
}

/**
 * Verify a signed session cookie and return its claims.
 * @param token - the raw `sid` cookie value.
 * @param secret - HMAC key shared with the main app.
 * @param now - current time, epoch seconds.
 * @param maxAgeSeconds - maximum accepted age of the cookie.
 * @returns the claims, or null when the cookie is malformed, tampered, or stale.
 */
export function verifySessionCookie(
  token: string,
  secret: string,
  now: number,
  maxAgeSeconds: number,
): SessionClaims | null {
  const dot = token.indexOf('.')
  if (dot <= 0 || dot === token.length - 1) return null
  const payload = token.slice(0, dot)
  const provided = Buffer.from(token.slice(dot + 1), 'base64url')
  const expected = Buffer.from(mac(payload, secret), 'base64url')
  if (provided.length !== expected.length || !timingSafeEqual(provided, expected)) return null

  let decoded: unknown
  try {
    decoded = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'))
  } catch {
    return null
  }
  if (!isClaims(decoded)) return null
  const age = now - decoded.iat
  if (age < 0 || age > maxAgeSeconds) return null
  return decoded
}
