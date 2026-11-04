/**
 * Child-process helpers for the supervisor: env scrubbing and free-port lookup.
 *
 * Env scrubbing mirrors the harness `scrubbedParentEnv` / `SENSITIVE_ENV_PATTERN`
 * doctrine (packages/subprocess/subprocess/src/index.ts): build the child env
 * from a clean allowlist so no orchestrator secret leaks into a user DSH, then
 * inject only the resolved per-user values.
 * @module dsh-server-login/supervisor/spawn
 */

import { createServer } from 'node:net'
import { existsSync } from 'node:fs'

const ALLOWED_ENV = new Set([
  'PATH',
  'HOME',
  'USER',
  'TMP',
  'TEMP',
  'TMPDIR',
  'SYSTEMROOT',
  'SystemRoot',
  'PATHEXT',
  'ProgramFiles',
  'ProgramFiles(x86)',
  'LANG',
  'LC_ALL',
  'NODE_PATH',
  'DSH_SERVER_LOGIN_BASE_DOMAIN',
  'SUPABASE_URL',
  'SUPABASE_ANON_KEY',
  // The service-role key is deliberately absent: a tenant DSH runs untrusted
  // code, and every privileged read and write goes through a caller-scoped RPC
  // that derives the tenant from auth.uid().
])

export const DEFAULT_SYSTEM_PATH = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'

/**
 * Ensures standard system binary directories are included in the PATH,
 * preserving any custom prefixes (like node, nvm, pnpm) without duplicates.
 */
export function sanitizePath(existingPath?: string): string {
  const standardDirs = ['/usr/local/sbin', '/usr/local/bin', '/usr/sbin', '/usr/bin', '/sbin', '/bin']
  const parts = existingPath ? existingPath.split(':').filter(Boolean) : []
  for (const dir of standardDirs) {
    if (!parts.includes(dir)) {
      parts.push(dir)
    }
  }
  return parts.join(':')
}

/**
 * Resolves a binary command to an absolute path if it is a simple binary name
 * and exists in standard system directories or PATH.
 */
export function resolveBinary(cmd: string, pathEnv?: string): string {
  if ((cmd.includes('/') || cmd.includes('\\')) && existsSync(cmd)) {
    return cmd
  }
  const baseName = cmd.split(/[/\\]/).pop() ?? cmd
  const knownLocations = ['/usr/bin', '/bin', '/usr/local/bin', '/usr/sbin', '/sbin']
  const searchDirs = [
    ...knownLocations,
    ...(pathEnv ? pathEnv.split(':').filter(Boolean) : []),
  ]
  for (const dir of searchDirs) {
    const full = `${dir}/${baseName}`
    if (existsSync(full)) {
      return full
    }
  }
  return cmd
}

/** Drop credential-shaped and unknown env vars; keep only a safe allowlist with guaranteed PATH. */
export function scrubEnv(env: NodeJS.ProcessEnv): Record<string, string> {
  const out: Record<string, string> = {}
  for (const [key, value] of Object.entries(env)) {
    if (ALLOWED_ENV.has(key) && value !== undefined) out[key] = value
  }
  out.PATH = sanitizePath(out.PATH ?? env.PATH)
  return out
}

/** Reserve an ephemeral loopback port, release it, and return its number. */
export function findFreePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const server = createServer()
    server.on('error', reject)
    server.listen(0, '127.0.0.1', () => {
      const address = server.address()
      const port = typeof address === 'object' && address !== null ? address.port : undefined
      server.close(() => {
        if (port !== undefined) resolve(port)
        else reject(new Error('could not reserve a free port'))
      })
    })
  })
}
