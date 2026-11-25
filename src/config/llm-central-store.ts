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

/** Default interval for the routing reload poll; the admin event makes it a backstop. */
const DEFAULT_POLL_INTERVAL_MS = 30_000

/**
 * Whether two parsed routing configurations are equivalent.
 *
 * Both values come from the same Zod schema, so a structural JSON comparison
 * is enough to tell whether a reload changed anything worth logging.
 */
function sameRouting(a: CentralRoutingConfig | null, b: CentralRoutingConfig): boolean {
  if (a === null) return false
  try {
    return JSON.stringify(a) === JSON.stringify(b)
  } catch {
    return false
  }
}

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
  private config: CentralRoutingConfig | null = null
  private readonly supabaseClient?: SupabaseClient | null
  private readonly cacheFilePath?: string
  private readonly logger?: CentralRoutingStoreOptions['logger']
  private pollTimer?: NodeJS.Timeout
  private reloading?: Promise<CentralRoutingConfig>
  private realtimeChannel?: unknown

  constructor(options: CentralRoutingStoreOptions = {}) {
    this.supabaseClient = options.supabaseClient
    this.logger = options.logger
    if (options.cacheDir) {
      this.cacheFilePath = join(options.cacheDir, 'llm-central-routing.cache.json')
    }
  }

  /**
   * Return the currently active in-memory routing configuration.
   * Throws if configuration has not been loaded yet.
   */
  public getConfig(): CentralRoutingConfig {
    if (!this.config) {
      throw new Error('CentralRoutingStore: routing configuration not loaded. Admin must configure Settings > Models > Provider routing.')
    }
    return this.config
  }

  /**
   * Load configuration on orchestrator startup.
   * Priority:
   * 1. Supabase `public.system_config` (key = `llm.central_routing`)
   * 2. Local disk cache file (if Supabase is down or unreachable)
   * Throws if no configuration is found — the Admin must configure Settings > Models > Provider routing.
   */
  public async loadOnBoot(): Promise<CentralRoutingConfig> {
    return this.reload()
  }

  /**
   * Re-read the routing configuration and swap it in when it changed.
   *
   * A live tenant must adopt an Admin change without a restart: the gateway
   * resolves every turn through {@link getConfig}, so replacing `this.config`
   * shifts the next request onto the new provider. A row that fails validation
   * keeps the current configuration in place instead of blanking the route.
   * @returns the configuration now in effect.
   */
  public async reload(): Promise<CentralRoutingConfig> {
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
            const changed = !sameRouting(this.config, parsed.data)
            this.config = parsed.data
            this.persistToDiskCache(this.config)
            if (changed) {
              this.logger?.info?.(
                `[CentralRoutingStore] Reloaded LLM central routing (v${this.config.version}) from Supabase`,
              )
            }
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

    // Supabase unreachable or empty: keep an already-loaded configuration
    // rather than downgrading to the disk cache, which is older.
    if (this.config) return this.config

    // 2. Try loading from disk cache
    const cached = this.loadFromDiskCache()
    if (cached) {
      this.config = cached
      this.logger?.info?.(
        `[CentralRoutingStore] Loaded LLM central routing from local cache file: ${this.cacheFilePath}`,
      )
      return this.config
    }

    // 3. In test environment, fallback to structural default config if neither Supabase nor disk cache exists
    if (process.env.NODE_ENV === 'test') {
      this.config = DEFAULT_CENTRAL_ROUTING_CONFIG
      return this.config
    }

    // 4. No configuration found in production — fail explicitly
    const msg = 'CentralRoutingStore: no LLM routing configuration found in Supabase (system_config.llm.central_routing) or local cache. Admin must configure Settings > Models > Provider routing.'
    this.logger?.error?.(`[CentralRoutingStore] ${msg}`)
    throw new Error(msg)
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

  /**
   * Reload now, coalescing concurrent callers onto one Supabase read.
   *
   * The admin-changed event and the periodic poll can arrive together; sharing
   * one in-flight promise keeps a burst of notifications to a single query.
   * @returns the configuration in effect after the read.
   */
  public triggerReload(): Promise<CentralRoutingConfig> {
    if (this.reloading === undefined) {
      this.reloading = this.reload().finally(() => {
        this.reloading = undefined
      })
    }
    return this.reloading
  }

  /**
   * Poll Supabase for routing changes so a live gateway adopts an Admin change
   * even when the change event is missed (Realtime disabled, tunnel drop).
   * A failed poll keeps the current configuration.
   * @param intervalMs - delay between reads.
   */
  public startPolling(intervalMs: number = DEFAULT_POLL_INTERVAL_MS): void {
    if (this.pollTimer !== undefined || this.supabaseClient === undefined || this.supabaseClient === null) return
    this.pollTimer = setInterval(() => {
      void this.triggerReload().catch((err: unknown) => {
        this.logger?.warn?.(`[CentralRoutingStore] Periodic reload failed: ${String(err)}`)
      })
    }, intervalMs)
    this.pollTimer.unref()
  }

  /** Stop the periodic reload started by {@link startPolling}. */
  public stopPolling(): void {
    if (this.pollTimer === undefined) return
    clearInterval(this.pollTimer)
    this.pollTimer = undefined
  }

  /**
   * Subscribe to Realtime changes on the routing row so an Admin save reaches
   * a live gateway immediately.
   *
   * Realtime requires `system_config` in the `supabase_realtime` publication;
   * when it is not, the subscription reports an error and the poll remains the
   * delivery path. The orchestrator never depends on this channel for
   * correctness, only for latency.
   */
  public subscribeToChanges(): void {
    const client = this.supabaseClient as
      | (SupabaseClient & { removeChannel?: (channel: unknown) => Promise<unknown> })
      | null
      | undefined
    if (client === null || client === undefined) return
    const channelFactory = (client as { channel?: (name: string) => unknown }).channel
    if (typeof channelFactory !== 'function') return
    try {
      const channel = (channelFactory.call(client, 'llm-routing-changes') as {
        on: (event: string, filter: unknown, cb: () => void) => unknown
        subscribe: (cb?: (status: string, err?: unknown) => void) => unknown
      })
      channel.on(
        'postgres_changes',
        { event: '*', schema: 'public', table: 'system_config', filter: `key=eq.${SYSTEM_CONFIG_LLM_ROUTING_KEY}` },
        () => {
          void this.triggerReload().catch((err: unknown) => {
            this.logger?.warn?.(`[CentralRoutingStore] Realtime reload failed: ${String(err)}`)
          })
        },
      )
      channel.subscribe((status: string, err?: unknown) => {
        if (status === 'SUBSCRIBED') {
          this.logger?.info?.('[CentralRoutingStore] Subscribed to realtime routing changes')
        } else if (status === 'CHANNEL_ERROR' || status === 'TIMED_OUT') {
          this.logger?.warn?.(
            `[CentralRoutingStore] Realtime subscription unavailable (${status}); periodic reload stays active${err === undefined ? '' : `: ${String(err)}`}`,
          )
        }
      })
      this.realtimeChannel = channel
    } catch (err) {
      this.logger?.warn?.(`[CentralRoutingStore] Could not subscribe to realtime routing changes: ${String(err)}`)
    }
  }

  /**
   * Close the Realtime channel, if any.
   *
   * The channel holds an open WebSocket that keeps the Node process alive, so
   * shutdown must remove it for the server to drain.
   * @returns settles once the channel is removed.
   */
  public async unsubscribe(): Promise<void> {
    const client = this.supabaseClient as { removeChannel?: (channel: unknown) => Promise<unknown> } | null | undefined
    const channel = this.realtimeChannel
    this.realtimeChannel = undefined
    if (channel === undefined || client === null || client === undefined) return
    if (typeof client.removeChannel !== 'function') return
    try {
      await client.removeChannel(channel)
    } catch (err) {
      this.logger?.warn?.(`[CentralRoutingStore] Could not remove realtime channel: ${String(err)}`)
    }
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
