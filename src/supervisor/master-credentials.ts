/**
 * Master credentials resolver for the central LLM loopback gateway.
 * Reads the admin tenant's credentials vault (.credentials.yaml) securely in-memory,
 * with atomic caching (30s TTL + mtime invalidation) and safe fallbacks.
 * @module dsh-server-login/supervisor/master-credentials
 */

import { existsSync, readFileSync, statSync } from 'node:fs'
import { join } from 'node:path'
import { load as loadYaml } from 'js-yaml'
import type { DbAdapter } from '../db/adapter.js'
import { homeRoot, userRoot } from '../fs/workspace.js'
import { platformApiKeys } from './platform-key.js'

const DEFAULT_GLOBAL_CREDENTIALS = '/root/.dsh/.credentials.yaml'
const CACHE_TTL_MS = 30_000

export interface MasterCredentialsOptions {
  db: Pick<DbAdapter, 'findUserByUsername' | 'listPublicUsers'>
  dataRoot: string
  /**
   * Username of the account that owns the master provider credentials.
   * This account is authoritative even when its role is not `admin`, because
   * operators configure provider keys while signed in to it.
   */
  masterUsername: string
  logger?: {
    info(msg: string, ...args: unknown[]): void
    warn(msg: string, ...args: unknown[]): void
    error(msg: string, ...args: unknown[]): void
  }
}

interface CacheEntry {
  keys: Record<string, string>
  timestamp: number
  filePath?: string
  fileMtimeMs?: number
}

/** Sensitive API key patterns that must be redacted unconditionally across all loggers. */
export const SENSITIVE_KEY_PATTERN = /(?:sk-or-v1-[a-zA-Z0-9_\-]+|sk-ant-[a-zA-Z0-9_\-]+|sk-proj-[a-zA-Z0-9_\-]+|dsk-[a-zA-Z0-9_\-]+)/gi

/**
 * Replace any sensitive API keys (sk-or-v1-, sk-ant-, sk-proj-, dsk-) with [REDACTED_KEY].
 */
export function redactSensitiveString(text: string): string {
  if (!text || typeof text !== 'string') return text
  return text.replace(SENSITIVE_KEY_PATTERN, '[REDACTED_KEY]')
}

/** Maximum depth traversed in a log payload; deeper values pass through unchanged. */
const MAX_REDACTION_DEPTH = 10

/** True for object literals and `Object.create(null)` records only. */
function isPlainRecord(val: object): val is Record<string, unknown> {
  const proto = Object.getPrototypeOf(val)
  return proto === Object.prototype || proto === null
}

function redactValue(val: unknown, path: WeakSet<object>, depth: number): unknown {
  if (typeof val === 'string') return redactSensitiveString(val)
  if (val === null || typeof val !== 'object') return val
  if (depth >= MAX_REDACTION_DEPTH) return val
  // Pino's `formatters.log` runs before serializers and sees the raw Fastify
  // request graph, which is cyclic. A shared reference is only circular while
  // it is still on the current path, so entries are removed on the way back.
  if (path.has(val)) return '[Circular]'
  if (Array.isArray(val)) {
    path.add(val)
    try {
      return val.map((item) => redactValue(item, path, depth + 1))
    } finally {
      path.delete(val)
    }
  }
  // Class instances (requests, replies, errors, buffers, streams) are left
  // untouched so the logger's own serializers still read their real properties.
  if (!isPlainRecord(val)) return val
  path.add(val)
  try {
    const out: Record<string, unknown> = {}
    for (const [key, item] of Object.entries(val)) {
      out[key] = redactValue(item, path, depth + 1)
    }
    return out
  } finally {
    path.delete(val)
  }
}

/**
 * Recursively sanitize plain objects and arrays by masking sensitive API keys.
 *
 * Values that are not strings, arrays, or plain records (Fastify requests,
 * errors, buffers, streams) are returned unchanged.
 */
export function redactSensitiveObject<T>(val: T): T {
  return redactValue(val, new WeakSet<object>(), 0) as T
}

/**
 * Safely redact an API key for logs without leaking secret material.
 */
export function redactApiKey(key: string | undefined | null): string {
  if (!key) return '[NOT_SET]'
  const trimmed = key.trim()
  if (trimmed.length <= 10) return '[REDACTED]'
  if (/^(sk-or-v1-|sk-ant-|sk-proj-|dsk-)/i.test(trimmed)) {
    return '[REDACTED_KEY]'
  }
  return `${trimmed.slice(0, 7)}...${trimmed.slice(-4)}`
}

export class MasterCredentialsResolver {
  private readonly db: MasterCredentialsOptions['db']
  private readonly dataRoot: string
  private readonly masterUsername: string
  private readonly logger?: MasterCredentialsOptions['logger']
  private cache: CacheEntry | null = null

  constructor(options: MasterCredentialsOptions) {
    this.db = options.db
    this.dataRoot = options.dataRoot
    this.masterUsername = options.masterUsername
    this.logger = options.logger
  }

  /**
   * Invalidate the current cache forcing a reload on the next call.
   */
  public invalidateCache(): void {
    this.cache = null
  }

  /**
   * Find the master tenant user row.
   * The configured master username wins regardless of role; only when that
   * account does not exist does the resolver fall back to the first `admin`.
   */
  public async findAdminUserId(): Promise<string | undefined> {
    try {
      const master = await this.db.findUserByUsername(this.masterUsername)
      if (master) return master.id
      const users = await this.db.listPublicUsers()
      const admin = users.find((u) => u.role === 'admin')
      return admin?.id
    } catch (err) {
      this.logger?.warn?.(`[MasterCredentials] Error looking up admin user: ${String(err)}`)
      return undefined
    }
  }

  /**
   * Resolve the path to the admin's .credentials.yaml file.
   */
  public async getAdminCredentialsPath(): Promise<string | undefined> {
    const adminId = await this.findAdminUserId()
    if (!adminId) return undefined
    const home = homeRoot(userRoot(this.dataRoot, adminId))
    const credPath = join(home, '.credentials.yaml')
    return existsSync(credPath) ? credPath : undefined
  }

  /**
   * Read all available credentials in memory with caching.
   */
  public async getAllCredentials(): Promise<Record<string, string>> {
    const now = Date.now()

    // 1. Check if cache is still fresh and file unchanged
    if (this.cache && now - this.cache.timestamp < CACHE_TTL_MS) {
      if (this.cache.filePath && existsSync(this.cache.filePath)) {
        try {
          const stat = statSync(this.cache.filePath)
          if (stat.mtimeMs === this.cache.fileMtimeMs) {
            return this.cache.keys
          }
        } catch {
          // Stat failed, fall through to re-read
        }
      } else if (!this.cache.filePath) {
        return this.cache.keys
      }
    }

    const merged: Record<string, string> = {}

    // 2. Base layer: control plane environment variables
    const envKeys = platformApiKeys(process.env)
    for (const [k, v] of Object.entries(envKeys)) {
      if (v) merged[k] = v
    }

    // 3. Fallback layer: global credentials file (/root/.dsh/.credentials.yaml)
    const globalPath = process.env.DSH_SERVER_LOGIN_GLOBAL_CREDENTIALS ?? DEFAULT_GLOBAL_CREDENTIALS
    if (existsSync(globalPath)) {
      try {
        const raw = readFileSync(globalPath, 'utf8')
        const parsed = loadYaml(raw) as any
        if (parsed && typeof parsed === 'object' && parsed.refs && typeof parsed.refs === 'object') {
          for (const [k, v] of Object.entries(parsed.refs)) {
            if (typeof v === 'string' && v.trim()) {
              merged[k] = v.trim()
            }
          }
        }
      } catch (err) {
        this.logger?.warn?.(`[MasterCredentials] Failed reading global credentials file ${globalPath}: ${String(err)}`)
      }
    }

    // 4. Highest priority layer: Admin tenant's .credentials.yaml
    let adminCredPath: string | undefined
    let adminFileMtimeMs: number | undefined

    try {
      adminCredPath = await this.getAdminCredentialsPath()
      if (adminCredPath && existsSync(adminCredPath)) {
        const stat = statSync(adminCredPath)
        adminFileMtimeMs = stat.mtimeMs
        const raw = readFileSync(adminCredPath, 'utf8')
        const parsed = loadYaml(raw) as any
        if (parsed && typeof parsed === 'object' && parsed.refs && typeof parsed.refs === 'object') {
          for (const [k, v] of Object.entries(parsed.refs)) {
            if (typeof v === 'string' && v.trim()) {
              merged[k] = v.trim()
            }
          }
        }
      }
    } catch (err) {
      this.logger?.warn?.(`[MasterCredentials] Failed reading admin credentials from ${adminCredPath}: ${String(err)}`)
    }

    this.cache = {
      keys: merged,
      timestamp: now,
      filePath: adminCredPath,
      fileMtimeMs: adminFileMtimeMs,
    }

    return merged
  }

  /**
   * Resolve an API key for a given provider or reference name.
   * Handles aliases and provider name normalization:
   * - "openrouter" -> OPENROUTER_API_KEY
   * - "deepseek" / "deepseek-official" -> DEEPSEEK_API_KEY
   * - "openai" -> OPENAI_API_KEY
   * - "anthropic" -> ANTHROPIC_API_KEY
   */
  public async resolveKeyForProvider(providerOrRef: string): Promise<string | undefined> {
    const creds = await this.getAllCredentials()
    const trimmed = providerOrRef.trim()

    // 1. Direct match on ref name (e.g. OPENROUTER_API_KEY)
    if (creds[trimmed]) return creds[trimmed]

    // 2. Normalized provider mapping
    const normalized = trimmed.toLowerCase()
    if (normalized === 'openrouter') {
      return creds['OPENROUTER_API_KEY']
    }
    if (normalized === 'deepseek' || normalized === 'deepseek-official' || normalized === 'deepseek-chat') {
      return creds['DEEPSEEK_API_KEY']
    }
    if (normalized === 'openai') {
      return creds['OPENAI_API_KEY']
    }
    if (normalized === 'anthropic') {
      return creds['ANTHROPIC_API_KEY']
    }
    if (normalized === 'cloudflare' || normalized === 'cloudflare-workers-ai' || normalized === 'workers-ai') {
      return creds['CLOUDFLARE_API_KEY'] || creds['CLOUDFLARE_API_TOKEN']
    }

    // 3. Fallback to UPPERCASE_API_KEY convention
    const envStyle = `${normalized.toUpperCase().replace(/[^A-Z0-9]/g, '_')}_API_KEY`
    if (creds[envStyle]) return creds[envStyle]

    return undefined
  }

  /**
   * Resolve Cloudflare Workers AI credentials (Account ID and API Key/Token).
   */
  public async resolveCloudflareCredentials(): Promise<{ accountId?: string; apiKey?: string }> {
    const creds = await this.getAllCredentials()
    const apiKey = creds['CLOUDFLARE_API_KEY'] || creds['CLOUDFLARE_API_TOKEN'] || creds['cloudflare'] || process.env.CLOUDFLARE_API_KEY || process.env.CLOUDFLARE_API_TOKEN
    const accountId = creds['CLOUDFLARE_ACCOUNT_ID'] || creds['CLOUDFLARE_ACCOUNT'] || process.env.CLOUDFLARE_ACCOUNT_ID || process.env.CLOUDFLARE_ACCOUNT
    return {
      accountId: accountId?.trim() || undefined,
      apiKey: apiKey?.trim() || undefined,
    }
  }
}
