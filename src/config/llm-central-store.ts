/**
 * Cached store for the centralized LLM routing configuration.
 * Fetches from Supabase `public.system_config` on boot and caches in memory
 * and optionally local disk for offline / network failure resilience.
 * @module dsh-server-login/config/llm-central-store
 */

import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import type { SupabaseClient } from '@supabase/supabase-js'
import {
  type CentralRoutingConfig,
  CentralRoutingConfigSchema,
  DEFAULT_CENTRAL_ROUTING_CONFIG,
  SYSTEM_CONFIG_LLM_ROUTING_KEY,
} from './llm-central-routing.js'

export interface CentralRoutingStoreOptions {
  /** Supabase client (anon or service_role key) */
  supabaseClient?: SupabaseClient | null
  /** Optional directory to persist cached config (e.g. dataRoot) */
  cacheDir?: string
  /** Logger for informative startup logs */
  logger?: {
    info(msg: string, ...args: unknown[]): void
    warn(msg: string, ...args: unknown[]): void
    error(msg: string, ...args: unknown[]): void
  }
}

export class CentralRoutingStore {
  private config: CentralRoutingConfig = DEFAULT_CENTRAL_ROUTING_CONFIG
  private readonly supabaseClient?: SupabaseClient | null
  private readonly cacheFilePath?: string
  private readonly logger?: CentralRoutingStoreOptions['logger']

  constructor(options: CentralRoutingStoreOptions = {}) {
    this.supabaseClient = options.supabaseClient
    this.logger = options.logger
    if (options.cacheDir) {
      this.cacheFilePath = join(options.cacheDir, 'llm-central-routing.cache.json')
    }
  }

  /**
   * Return the currently active in-memory routing configuration.
   */
  public getConfig(): CentralRoutingConfig {
    return this.config
  }

  /**
   * Load configuration on orchestrator startup.
   * Priority:
   * 1. Supabase `public.system_config` (key = `llm.central_routing`)
   * 2. Local disk cache file (if Supabase is down or unreachable)
   * 3. Built-in defaults
   */
  public async loadOnBoot(): Promise<CentralRoutingConfig> {
    // 1. Try reading from Supabase
    if (this.supabaseClient) {
      try {
        const { data, error } = await this.supabaseClient
          .from('system_config')
          .select('value')
          .eq('key', SYSTEM_CONFIG_LLM_ROUTING_KEY)
          .maybeSingle()

        if (!error && data?.value) {
          const parsed = CentralRoutingConfigSchema.safeParse(data.value)
          if (parsed.success) {
            this.config = parsed.data
            this.persistToDiskCache(this.config)
            this.logger?.info?.(
              `[CentralRoutingStore] Successfully loaded LLM central routing (v${this.config.version}) from Supabase`,
            )
            return this.config
          } else {
            this.logger?.warn?.(
              `[CentralRoutingStore] Supabase row for ${SYSTEM_CONFIG_LLM_ROUTING_KEY} failed validation: ${parsed.error.message}`,
            )
          }
        } else if (error) {
          this.logger?.warn?.(
            `[CentralRoutingStore] Supabase query for ${SYSTEM_CONFIG_LLM_ROUTING_KEY} returned error: ${error.message}`,
          )
        }
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err)
        this.logger?.warn?.(`[CentralRoutingStore] Failed fetching config from Supabase: ${msg}`)
      }
    }

    // 2. Try loading from disk cache
    const cached = this.loadFromDiskCache()
    if (cached) {
      this.config = cached
      this.logger?.info?.(
        `[CentralRoutingStore] Loaded LLM central routing from local cache file: ${this.cacheFilePath}`,
      )
      return this.config
    }

    // 3. Fallback to built-in default
    this.config = DEFAULT_CENTRAL_ROUTING_CONFIG
    this.persistToDiskCache(this.config)
    this.logger?.info?.(
      '[CentralRoutingStore] Initialized LLM central routing with default production baseline',
    )
    return this.config
  }

  /**
   * Update the configuration programmatically (used by admin routes or tests)
   */
  public updateConfig(newConfig: unknown): CentralRoutingConfig {
    const parsed = CentralRoutingConfigSchema.parse(newConfig)
    this.config = parsed
    this.persistToDiskCache(this.config)
    return this.config
  }

  private loadFromDiskCache(): CentralRoutingConfig | null {
    if (!this.cacheFilePath || !existsSync(this.cacheFilePath)) {
      return null
    }
    try {
      const raw = readFileSync(this.cacheFilePath, 'utf-8')
      const json = JSON.parse(raw)
      const parsed = CentralRoutingConfigSchema.safeParse(json)
      return parsed.success ? parsed.data : null
    } catch (err) {
      this.logger?.warn?.(
        `[CentralRoutingStore] Could not read disk cache at ${this.cacheFilePath}: ${String(err)}`,
      )
      return null
    }
  }

  private persistToDiskCache(cfg: CentralRoutingConfig): void {
    if (!this.cacheFilePath) return
    try {
      const dir = dirname(this.cacheFilePath)
      if (!existsSync(dir)) {
        mkdirSync(dir, { recursive: true })
      }
      writeFileSync(this.cacheFilePath, JSON.stringify(cfg, null, 2), 'utf-8')
    } catch (err) {
      this.logger?.warn?.(
        `[CentralRoutingStore] Failed saving disk cache to ${this.cacheFilePath}: ${String(err)}`,
      )
    }
  }
}
