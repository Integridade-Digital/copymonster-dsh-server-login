/**
 * Signed browser identity for per-tenant DSH processes.
 *
 * The proxy authenticates the browser session and signs the caller's tenant
 * identity with an Ed25519 private key held by this control plane. Each tenant
 * receives only the public key, so code inside a tenant can verify the
 * identity but cannot mint one.
 * @module dsh-server-login/identity
 */

import { createPrivateKey, createPublicKey, generateKeyPairSync, sign } from 'node:crypto'
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'

/** Role a caller holds inside its tenant. */
export type TenantRole = 'owner' | 'admin' | 'member' | 'anonymous'

/** Claims the proxy signs for one browser request. */
export interface IdentityClaims {
  /** Supabase `auth.users` identity. */
  sub: string
  /** Tenant the caller acts within. */
  tenant: string
  /** Role held inside the tenant. */
  role: TenantRole
  /** Platform-operator flag. */
  isAdmin: boolean
  /** Issued-at, milliseconds since the epoch. */
  iat: number
  /** Expiry, milliseconds since the epoch. */
  exp: number
}

/** Signer shared by the proxy and the tenant spawner. */
export interface IdentitySigner {
  /** Base64 SPKI DER public key the tenant verifies with. */
  readonly publicKey: string
  /**
   * Sign one identity payload.
   * @param claims - caller identity and lifetime.
   * @returns `<base64url(payload)>.<base64url(signature)>`.
   */
  sign(claims: IdentityClaims): string
}

/** Lifetime of one signed identity; the proxy re-signs every request. */
export const IDENTITY_TTL_MS = 5 * 60 * 1000

/**
 * Load the control plane's signing key, generating it on first use.
 * @param dataRoot - control-plane data directory that owns the key file.
 * @returns signer exposing the public key and the signing operation.
 */
export function createIdentitySigner(dataRoot: string): IdentitySigner {
  const keyPath = join(dataRoot, 'identity.key')
  let privatePem: string
  if (existsSync(keyPath)) {
    privatePem = readFileSync(keyPath, 'utf8')
  } else {
    const { privateKey } = generateKeyPairSync('ed25519')
    privatePem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString()
    mkdirSync(dataRoot, { recursive: true })
    writeFileSync(keyPath, privatePem, { mode: 0o600 })
  }
  const privateKey = createPrivateKey(privatePem)
  const publicKey = createPublicKey(privateKey)
    .export({ type: 'spki', format: 'der' })
    .toString('base64')
  return {
    publicKey,
    sign(claims) {
      const payload = Buffer.from(JSON.stringify(claims)).toString('base64url')
      const signature = sign(null, Buffer.from(payload), privateKey).toString('base64url')
      return `${payload}.${signature}`
    },
  }
}
