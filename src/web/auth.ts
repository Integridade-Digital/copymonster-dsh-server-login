/**
 * Password hashing, session-token helpers, and cookie assembly.
 *
 * Uses `node:crypto` scrypt so the scaffold has zero native dependency beyond
 * SQLite; production may swap in argon2id without changing call sites.
 * @module dsh-server-login/web/auth
 */

import { createHash, randomBytes, scrypt, timingSafeEqual } from 'node:crypto'
import { promisify } from 'node:util'

const scryptAsync = promisify(scrypt) as (
  password: string,
  salt: Buffer,
  keylen: number,
  options: { N: number; r: number; p: number; maxmem: number },
) => Promise<Buffer>

const KEY_LENGTH = 64

/**
 * scrypt cost for newly hashed passwords (N=2^17, r=8, p=1 ≈ 128 MiB, ~0.5 s).
 * Node's default (N=2^14) is cheap enough for a GPU farm to grind offline, so
 * new hashes record a higher cost. Stored hashes carry their own parameters
 * and keep verifying at the cost they were created with.
 */
const PASSWORD_KDF = { N: 2 ** 17, r: 8, p: 1, maxmem: 256 * 1024 * 1024 } as const

/** Cost recorded for legacy `scrypt$salt$hash` values (Node's default). */
const LEGACY_KDF = { N: 2 ** 14, r: 8, p: 1, maxmem: 64 * 1024 * 1024 } as const

/** Fixed salt for the login enumeration guard; not a real credential. */
const DUMMY_SALT = Buffer.alloc(16, 0x5a)

/** Hash a password into a `scrypt$N$r$p$<salt>$<hash>` string. */
export async function hashPassword(password: string): Promise<string> {
  const salt = randomBytes(16)
  const derived = await scryptAsync(password, salt, KEY_LENGTH, PASSWORD_KDF)
  return `scrypt$${PASSWORD_KDF.N}$${PASSWORD_KDF.r}$${PASSWORD_KDF.p}$${salt.toString('hex')}$${derived.toString('hex')}`
}

/** Constant-time password verification against a stored `scrypt$...` string. */
export async function verifyPassword(password: string, stored: string): Promise<boolean> {
  const parts = stored.split('$')
  // Legacy format: `scrypt$<salt>$<hash>`.
  if (parts.length === 3) {
    const [, saltHex, hashHex] = parts
    if (saltHex === undefined || hashHex === undefined) return false
    return compareDerived(password, saltHex, hashHex, LEGACY_KDF)
  }
  // Current format: `scrypt$N$r$p$<salt>$<hash>`.
  if (parts.length === 6) {
    const [, n, r, p, saltHex, hashHex] = parts
    const N = Number(n)
    const rr = Number(r)
    const pp = Number(p)
    if (!Number.isInteger(N) || !Number.isInteger(rr) || !Number.isInteger(pp)) return false
    if (N < 2 ** 10 || N > PASSWORD_KDF.N || saltHex === undefined || hashHex === undefined) return false
    const cost = { N, r: rr, p: pp, maxmem: 256 * 1024 * 1024 }
    return compareDerived(password, saltHex, hashHex, cost)
  }
  return false
}

/** Derive and compare one stored hash under a given scrypt cost. */
async function compareDerived(
  password: string,
  saltHex: string,
  hashHex: string,
  cost: { N: number; r: number; p: number; maxmem: number },
): Promise<boolean> {
  const expected = Buffer.from(hashHex, 'hex')
  const derived = await scryptAsync(password, Buffer.from(saltHex, 'hex'), KEY_LENGTH, cost)
  return derived.length === expected.length && timingSafeEqual(derived, expected)
}

/**
 * Perform one scrypt hash whose result is discarded.
 *
 * The login route calls this when the username does not exist, so a failed
 * lookup costs the same as a wrong password. Without it, response timing
 * reveals which usernames exist.
 * @param password - submitted password; only its cost matters here.
 */
export async function burnPasswordHashCost(password: string): Promise<void> {
  await scryptAsync(password, DUMMY_SALT, KEY_LENGTH, PASSWORD_KDF)
}

/** Generate a fresh opaque session token. */
export function newSessionToken(): string {
  return randomBytes(32).toString('base64url')
}

/** Hash a session token for storage; the DB never holds the raw token. */
export function hashSessionToken(token: string): string {
  return createHash('sha256').update(token).digest('hex')
}

/** Extract a named cookie value from a `Cookie` header. */
export function parseCookie(header: string | undefined, name: string): string | undefined {
  if (!header) return undefined
  for (const part of header.split(';')) {
    const idx = part.indexOf('=')
    if (idx === -1) continue
    if (part.slice(0, idx).trim() === name) return part.slice(idx + 1).trim()
  }
  return undefined
}

/** Build a `Set-Cookie` value for the session token.
 *
 * `SameSite=None` (with `Secure`) when behind HTTPS so the cookie survives the
 * cross-subdomain hop `dsh.<domain>` → `<user>.dsh.<domain>`; `SameSite=Lax`
 * otherwise. The subdomain auth check still validates cookie ↔ slug, so the
 * looser SameSite does not widen who a session can reach.
 */
export function sessionCookie(token: string, maxAgeSeconds: number, secure: boolean, domain?: string): string {
  const flags = ['sid=' + token, 'HttpOnly', secure ? 'SameSite=None' : 'SameSite=Lax', 'Path=/', `Max-Age=${maxAgeSeconds}`]
  if (secure) flags.push('Secure')
  if (domain !== undefined && domain !== '') flags.push(`Domain=${domain}`)
  return flags.join('; ')
}

/** Build a `Set-Cookie` value that expires the session cookie. */
export function clearSessionCookie(secure: boolean, domain?: string): string {
  const flags = ['sid=', 'HttpOnly', secure ? 'SameSite=None' : 'SameSite=Lax', 'Path=/', 'Max-Age=0']
  if (secure) flags.push('Secure')
  if (domain !== undefined && domain !== '') flags.push(`Domain=${domain}`)
  return flags.join('; ')
}
