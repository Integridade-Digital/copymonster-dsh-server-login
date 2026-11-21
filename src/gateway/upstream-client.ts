/**
 * Upstream LLM dispatcher: forwards inference requests to external providers
 * with SSE streaming and pre-chunk failover.
 * @module dsh-server-login/gateway/upstream-client
 */

import { Readable } from 'node:stream'
import type { CentralRoutingStore } from '../config/llm-central-store.js'
import { MasterCredentialsResolver, redactApiKey } from '../supervisor/master-credentials.js'

export interface ChatMessage {
  role: string
  content: string | unknown
  name?: string
  [key: string]: unknown
}

export interface ChatCompletionRequest {
  model: string
  messages: ChatMessage[]
  stream?: boolean
  temperature?: number
  top_p?: number
  max_tokens?: number
  stop?: string | string[]
  presence_penalty?: number
  frequency_penalty?: number
  [key: string]: unknown
}

export interface UpstreamClientOptions {
  masterCredentials: MasterCredentialsResolver
  centralRoutingStore: CentralRoutingStore
  logger?: {
    info(msg: string, ...args: unknown[]): void
    warn(msg: string, ...args: unknown[]): void
    error(msg: string, ...args: unknown[]): void
  }
}

export type UpstreamResult =
  | { type: 'stream'; status: number; headers: Record<string, string>; stream: Readable }
  | { type: 'json'; status: number; data: unknown }
  | { type: 'error'; status: number; error: { message: string; type?: string; code?: string } }

interface ResolvedRoute {
  provider: string
  model: string
  url: string
  headers: Record<string, string>
}

const FAILOVER_STATUS_CODES = new Set([401, 402, 403, 429, 500, 502, 503, 504])

export class UpstreamLlmClient {
  private readonly masterCredentials: MasterCredentialsResolver
  private readonly centralRoutingStore: CentralRoutingStore
  private readonly logger?: UpstreamClientOptions['logger']

  constructor(options: UpstreamClientOptions) {
    this.masterCredentials = options.masterCredentials
    this.centralRoutingStore = options.centralRoutingStore
    this.logger = options.logger
  }

  /**
   * Determine the target provider and model for a request.
   */
  public resolveTargetRoute(requestedModel: string, providerOverride?: string, modelOverride?: string): { provider: string; model: string } {
    if (providerOverride && modelOverride) {
      return { provider: providerOverride, model: modelOverride }
    }

    const cfg = this.centralRoutingStore.getConfig()
    const primary = cfg.failover?.primary ?? { provider: 'deepseek', model: 'deepseek-chat' }

    const trimmed = (requestedModel || '').trim()

    // Tenant alias or empty: route to central routing primary
    if (!trimmed || trimmed === 'copymonster/copy-monster-default' || trimmed === 'copy-monster-default' || trimmed.startsWith('copymonster/')) {
      return { provider: primary.provider, model: primary.model }
    }

    // Provider-prefixed model names
    if (trimmed.startsWith('openrouter/')) {
      return { provider: 'openrouter', model: trimmed.slice('openrouter/'.length) }
    }
    if (trimmed.startsWith('deepseek/')) {
      return { provider: 'deepseek', model: trimmed.slice('deepseek/'.length) }
    }
    if (trimmed.startsWith('openai/')) {
      return { provider: 'openai', model: trimmed.slice('openai/'.length) }
    }
    if (trimmed.startsWith('anthropic/')) {
      return { provider: 'anthropic', model: trimmed.slice('anthropic/'.length) }
    }

    // Direct model name with known provider primary
    return { provider: primary.provider, model: trimmed }
  }

  /**
   * Build the upstream HTTP endpoint URL and headers for a provider.
   */
  public async buildProviderEndpoint(provider: string, apiKey: string): Promise<{ url: string; headers: Record<string, string> }> {
    const norm = provider.toLowerCase()
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${apiKey}`,
    }

    if (norm === 'openrouter') {
      headers['HTTP-Referer'] = 'https://copymonster.co'
      headers['X-Title'] = 'CopyMonster'
      return {
        url: 'https://openrouter.ai/api/v1/chat/completions',
        headers,
      }
    }

    if (norm === 'deepseek' || norm === 'deepseek-official' || norm === 'deepseek-chat') {
      return {
        url: 'https://api.deepseek.com/chat/completions',
        headers,
      }
    }

    if (norm === 'openai') {
      return {
        url: 'https://api.openai.com/v1/chat/completions',
        headers,
      }
    }

    // Fallback default: OpenRouter standard format
    headers['HTTP-Referer'] = 'https://copymonster.co'
    headers['X-Title'] = 'CopyMonster'
    return {
      url: 'https://openrouter.ai/api/v1/chat/completions',
      headers,
    }
  }

  /**
   * Execute an upstream chat completion request with pre-chunk failover.
   */
  public async dispatch(
    body: ChatCompletionRequest,
    options?: { signal?: AbortSignal; tenantSlug?: string },
  ): Promise<UpstreamResult> {
    const isStream = body.stream === true
    const cfg = this.centralRoutingStore.getConfig()

    // 1. Determine primary route
    const primaryTarget = this.resolveTargetRoute(body.model)
    const primaryKey = await this.masterCredentials.resolveKeyForProvider(primaryTarget.provider)

    const fallbackCandidate = cfg.failover?.chain?.[0]
    const hasFailover = cfg.failover?.enabled !== false && fallbackCandidate !== undefined

    // Helper to attempt a single upstream call
    const tryCall = async (
      provider: string,
      model: string,
      key: string,
    ): Promise<{ res?: Response; error?: Error }> => {
      const { url, headers } = await this.buildProviderEndpoint(provider, key)
      const payload = {
        ...body,
        model,
      }

      this.logger?.info?.(
        `[LLM-GATEWAY] Dispatching to ${provider} (${model}) with key ${redactApiKey(key)} for tenant ${options?.tenantSlug ?? 'unknown'}`,
      )

      try {
        const timeoutSignal = AbortSignal.timeout(60_000)
        const combinedSignal = options?.signal
          ? AbortSignal.any([options.signal, timeoutSignal])
          : timeoutSignal

        const res = await fetch(url, {
          method: 'POST',
          headers,
          body: JSON.stringify(payload),
          signal: combinedSignal,
        })
        return { res }
      } catch (err) {
        return { error: err instanceof Error ? err : new Error(String(err)) }
      }
    }

    // 2. Attempt primary provider if key is available
    let activeRes: Response | undefined
    let activeProvider = primaryTarget.provider
    let activeModel = primaryTarget.model

    if (primaryKey) {
      const primaryAttempt = await tryCall(primaryTarget.provider, primaryTarget.model, primaryKey)
      if (primaryAttempt.res) {
        activeRes = primaryAttempt.res
      } else {
        this.logger?.warn?.(
          `[LLM-GATEWAY] Primary call to ${primaryTarget.provider} failed with network error: ${primaryAttempt.error?.message}`,
        )
      }
    } else {
      this.logger?.warn?.(
        `[LLM-GATEWAY] Primary provider ${primaryTarget.provider} has no API key configured`,
      )
    }

    // 3. Pre-chunk failover if primary failed or returned an eligible HTTP error code
    const needsFailover = !activeRes || FAILOVER_STATUS_CODES.has(activeRes.status)

    if (needsFailover && hasFailover && fallbackCandidate) {
      const fallbackProvider = fallbackCandidate.provider
      const fallbackModel = fallbackCandidate.model
      const fallbackKey = await this.masterCredentials.resolveKeyForProvider(fallbackProvider)

      if (fallbackKey) {
        const primaryStatus = activeRes ? activeRes.status : 'network_error'
        this.logger?.warn?.(
          `[LLM-GATEWAY] Failover triggered: ${primaryTarget.provider} (status: ${primaryStatus}) -> ${fallbackProvider} (${fallbackModel}) for tenant ${options?.tenantSlug ?? 'unknown'}`,
        )

        const fallbackAttempt = await tryCall(fallbackProvider, fallbackModel, fallbackKey)
        if (fallbackAttempt.res && fallbackAttempt.res.ok) {
          activeRes = fallbackAttempt.res
          activeProvider = fallbackProvider
          activeModel = fallbackModel
        } else if (fallbackAttempt.res && !activeRes) {
          activeRes = fallbackAttempt.res
        }
      }
    }

    // If still no response obtained
    if (!activeRes) {
      return {
        type: 'error',
        status: 502,
        error: {
          message: `Failed to connect to LLM provider (${activeProvider}): no response received or key missing`,
          type: 'upstream_connection_error',
        },
      }
    }

    // If upstream returned an error status (and failover was exhausted or unsuccessful)
    if (!activeRes.ok) {
      let errBody: any
      try {
        errBody = await activeRes.json()
      } catch {
        try {
          errBody = { message: await activeRes.text() }
        } catch {
          errBody = { message: `Upstream provider error (HTTP ${activeRes.status})` }
        }
      }

      const errMsg = errBody?.error?.message || errBody?.message || `Upstream error ${activeRes.status}`
      return {
        type: 'error',
        status: activeRes.status,
        error: {
          message: errMsg,
          type: errBody?.error?.type || 'upstream_error',
          code: errBody?.error?.code,
        },
      }
    }

    // 4. Handle successful response
    if (isStream) {
      if (!activeRes.body) {
        return {
          type: 'error',
          status: 502,
          error: {
            message: 'Upstream provider returned empty streaming body',
            type: 'empty_stream_error',
          },
        }
      }

      // Convert web ReadableStream to Node.js Readable
      const nodeStream = Readable.fromWeb(activeRes.body as any)
      return {
        type: 'stream',
        status: activeRes.status,
        headers: {
          'Content-Type': 'text/event-stream; charset=utf-8',
          'Cache-Control': 'no-cache',
          'Connection': 'keep-alive',
          'X-Accel-Buffering': 'no',
        },
        stream: nodeStream,
      }
    }

    // Non-streaming JSON response
    try {
      const data = await activeRes.json()
      return {
        type: 'json',
        status: activeRes.status,
        data,
      }
    } catch (err) {
      return {
        type: 'error',
        status: 502,
        error: {
          message: 'Failed to parse JSON response from upstream provider',
          type: 'invalid_json_error',
        },
      }
    }
  }
}
