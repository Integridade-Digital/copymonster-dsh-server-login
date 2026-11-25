/**
 * HMAC-SHA256 session token generator and validator for internal tenant requests
 * to the central LLM loopback gateway.
 * @module dsh-server-login/gateway/token-validator
 */

import { createHmac, timingSafeEqual } from 'node:crypto'

export interface TenantTokenPayload {
  /** Tenant user ID (UUID) */
  sub: string
  /** Tenant slug / username */
  slug: string
  /** Issued at timestamp (seconds) */
  iat: number
  /** Expiration timestamp (seconds) */
  exp: number
  /** Strictly scoped to LLM inference */
  scope: 'llm:infer'
}

export interface CreateTenantTokenOptions {
  userId: string
  slug: string
  secret: string
  /** Lifetime in seconds (default: 86400 = 24 hours) */
  ttlSeconds?: number
}

export type VerifyTokenResult =
  | { valid: true; payload: TenantTokenPayload }
  | { valid: false; error: string }

/**
 * Mint a signed internal session token for a tenant process.
 *
 * The orchestrator re-mints the token on every spawn, so a short lifetime
 * bounds the window a leaked token stays useful without forcing mid-stream
 * reauthentication; 12 h clears any realistic single generation.
 * @param options - tenant identity, signing secret, and optional TTL override.
 * @returns the signed compact JWS.
 */
export function createTenantToken(options: CreateTenantTokenOptions): string {
  const { userId, slug, secret, ttlSeconds = 12 * 60 * 60 } = options
  if (!secret || secret.length < 16) {
    throw new Error('createTenantToken: secret must be at least 16 characters')
  }
  if (!userId || !slug) {
    throw new Error('createTenantToken: userId and slug are required')
  }

  const now = Math.floor(Date.now() / 1000)
  const header = { alg: 'HS256', typ: 'JWT' }
  const payload: TenantTokenPayload = {
    sub: userId,
    slug,
    iat: now,
    exp: now + ttlSeconds,
    scope: 'llm:infer',
  }

  const headerB64 = Buffer.from(JSON.stringify(header)).toString('base64url')
  const payloadB64 = Buffer.from(JSON.stringify(payload)).toString('base64url')
  const signingInput = `${headerB64}.${payloadB64}`
  const signature = createHmac('sha256', secret).update(signingInput).digest('base64url')

  return `${signingInput}.${signature}`
}

/**
 * Verify and decode an internal session token.
 * Validates HMAC signature with constant-time comparison, expiration, and scope.
 */
export function verifyTenantToken(token: string | undefined | null, secret: string): VerifyTokenResult {
  if (!secret || secret.length < 16) {
    return { valid: false, error: 'Gateway internal secret is invalid or missing' }
  }
  if (!token || typeof token !== 'string') {
    return { valid: false, error: 'Missing token' }
  }

  const trimmed = token.startsWith('Bearer ') ? token.slice(7).trim() : token.trim()
  const parts = trimmed.split('.')
  if (parts.length !== 3) {
    return { valid: false, error: 'Malformed token: expected 3 dot-separated parts' }
  }

  const [headerB64, payloadB64, sigB64] = parts
  if (!headerB64 || !payloadB64 || !sigB64) {
    return { valid: false, error: 'Malformed token parts' }
  }

  const signingInput = `${headerB64}.${payloadB64}`
  const expectedSig = createHmac('sha256', secret).update(signingInput).digest('base64url')

  const sigBuf = Buffer.from(sigB64)
  const expectedBuf = Buffer.from(expectedSig)

  if (sigBuf.length !== expectedBuf.length || !timingSafeEqual(sigBuf, expectedBuf)) {
    return { valid: false, error: 'Invalid token signature' }
  }

  let payload: unknown
  try {
    payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf8'))
  } catch {
    return { valid: false, error: 'Invalid token payload JSON' }
  }

  if (
    typeof payload !== 'object' ||
    payload === null ||
    typeof (payload as any).sub !== 'string' ||
    typeof (payload as any).slug !== 'string' ||
    typeof (payload as any).exp !== 'number' ||
    (payload as any).scope !== 'llm:infer'
  ) {
    return { valid: false, error: 'Invalid token payload claims' }
  }

  const tokenPayload = payload as TenantTokenPayload
  const now = Math.floor(Date.now() / 1000)

  if (tokenPayload.exp < now) {
    return { valid: false, error: 'Token has expired' }
  }

  return { valid: true, payload: tokenPayload }
}
