/**
 * Central LLM Loopback Gateway Fastify Server.
 * Listens strictly on 127.0.0.1:4010 and services tenant inference requests
 * with session token verification, rate limiting, and SSE streaming.
 * @module dsh-server-login/gateway/llm-loopback-server
 */

import Fastify, { type FastifyInstance } from 'fastify'
import type { ServerConfig } from '../config.js'
import type { CentralRoutingStore } from '../config/llm-central-store.js'
import type { DbAdapter } from '../db/adapter.js'
import type { MasterCredentialsResolver } from '../supervisor/master-credentials.js'
import { verifyTenantToken } from './token-validator.js'
import {
  type ChatCompletionRequest,
  UpstreamLlmClient,
} from './upstream-client.js'

export interface LlmLoopbackServerOptions {
  config: ServerConfig
  db: Pick<DbAdapter, 'findUserById'>
  centralRoutingStore: CentralRoutingStore
  masterCredentials: MasterCredentialsResolver
  logger?: any
}

interface RateLimitBucket {
  count: number
  resetAt: number
}

const DEFAULT_RATE_LIMIT_PER_MINUTE = 60

/** Bucket-map size that triggers an expired-bucket sweep. */
const RATE_LIMIT_SWEEP_THRESHOLD = 1024

export class LlmLoopbackServer {
  private readonly app: FastifyInstance
  private readonly config: ServerConfig
  private readonly db: Pick<DbAdapter, 'findUserById'>
  private readonly masterCredentials: MasterCredentialsResolver
  private readonly upstreamClient: UpstreamLlmClient
  private readonly rateLimits = new Map<string, RateLimitBucket>()
  private readonly imageRateLimits = new Map<string, RateLimitBucket>()
  private running = false

  constructor(options: LlmLoopbackServerOptions) {
    this.config = options.config
    this.db = options.db
    this.masterCredentials = options.masterCredentials
    this.upstreamClient = new UpstreamLlmClient({
      masterCredentials: options.masterCredentials,
      centralRoutingStore: options.centralRoutingStore,
      logger: options.logger,
    })

    this.app = Fastify({
      logger: false,
      bodyLimit: 10 * 1024 * 1024, // 10MB payload max
    })

    this.registerRoutes()
  }

  public isRunning(): boolean {
    return this.running
  }

  public getFastify(): FastifyInstance {
    return this.app
  }

  /**
   * Drop rate-limit buckets whose window has closed.
   *
   * One bucket per tenant is created on demand and never removed otherwise, so
   * the map would grow for every tenant id the token validator has seen. A
   * sweep runs only once the map grows past a small bound, keeping the common
   * case O(1).
   * @param buckets - the per-endpoint bucket map to prune.
   * @param now - current epoch milliseconds.
   */
  private sweepRateLimits(buckets: Map<string, RateLimitBucket>, now: number): void {
    if (buckets.size < RATE_LIMIT_SWEEP_THRESHOLD) return
    for (const [key, bucket] of buckets) {
      if (now >= bucket.resetAt) buckets.delete(key)
    }
  }

  private registerRoutes(): void {
    // Health probe
    this.app.get('/internal/health', async (_req, reply) => {
      return reply.status(200).send({
        status: 'ok',
        uptime: process.uptime(),
        timestamp: Date.now(),
      })
    })

    // Chat completions endpoint
    this.app.post('/internal/v1/llm/chat/completions', async (request, reply) => {
      // 1. Authenticate Internal Session Token
      const authHeader = request.headers['authorization']
      if (!authHeader) {
        return reply.status(401).send({
          error: {
            message: 'Missing Authorization header: internal session token required',
            type: 'authentication_error',
          },
        })
      }

      const tokenResult = verifyTenantToken(authHeader, this.config.gatewayInternalSecret)
      if (!tokenResult.valid) {
        return reply.status(401).send({
          error: {
            message: `Unauthorized: ${tokenResult.error}`,
            type: 'authentication_error',
          },
        })
      }

      const { sub: userId, slug } = tokenResult.payload

      // 2. Authorize Tenant in DB
      try {
        const tenant = await this.db.findUserById(userId)
        if (!tenant) {
          return reply.status(403).send({
            error: {
              message: 'Forbidden: tenant not found',
              type: 'permission_error',
            },
          })
        }
        if (tenant.role === 'disabled') {
          return reply.status(403).send({
            error: {
              message: 'Forbidden: tenant account is disabled',
              type: 'permission_error',
            },
          })
        }
      } catch (err) {
        return reply.status(500).send({
          error: {
            message: `Internal authorization lookup failed: ${String(err)}`,
            type: 'internal_error',
          },
        })
      }

      // 3. Sliding window Rate Limiter
      const now = Date.now()
      this.sweepRateLimits(this.rateLimits, now)
      let bucket = this.rateLimits.get(userId)
      if (!bucket || now >= bucket.resetAt) {
        bucket = { count: 1, resetAt: now + 60_000 }
        this.rateLimits.set(userId, bucket)
      } else {
        bucket.count += 1
        if (bucket.count > DEFAULT_RATE_LIMIT_PER_MINUTE) {
          return reply.status(429).send({
            error: {
              message: 'Rate limit exceeded: too many requests per minute for tenant',
              type: 'rate_limit_error',
            },
          })
        }
      }

      // 4. Validate body
      const body = request.body as ChatCompletionRequest
      if (!body || typeof body !== 'object' || !Array.isArray(body.messages)) {
        return reply.status(400).send({
          error: {
            message: 'Bad Request: messages array is required',
            type: 'invalid_request_error',
          },
        })
      }

      // 5. Dispatch to Upstream
      const abortController = new AbortController()
      request.raw.on('close', () => {
        if (!reply.raw.writableEnded) {
          abortController.abort()
        }
      })

      const upstreamResult = await this.upstreamClient.dispatch(body, {
        signal: abortController.signal,
        tenantSlug: slug,
      })

      if (upstreamResult.type === 'error') {
        return reply.status(upstreamResult.status).send({
          error: upstreamResult.error,
        })
      }

      if (upstreamResult.type === 'json') {
        return reply.status(upstreamResult.status).send(upstreamResult.data)
      }

      // 6. Handle SSE Streaming
      reply.raw.writeHead(upstreamResult.status, {
        ...upstreamResult.headers,
        'Access-Control-Allow-Origin': '*',
      })

      upstreamResult.stream.on('data', (chunk: Buffer | string) => {
        reply.raw.write(chunk)
      })

      upstreamResult.stream.on('end', () => {
        reply.raw.end()
      })

      upstreamResult.stream.on('error', (streamErr) => {
        if (!reply.raw.writableEnded) {
          reply.raw.end()
        }
      })

      return reply
    })

    // Central Image Generation Handler
    const imageHandler = async (request: any, reply: any) => {
      // 1. Authenticate Internal Session Token
      const authHeader = request.headers['authorization']
      if (!authHeader) {
        return reply.status(401).send({
          error: {
            message: 'Missing Authorization header: internal session token required',
            type: 'authentication_error',
          },
        })
      }

      const tokenResult = verifyTenantToken(authHeader, this.config.gatewayInternalSecret)
      if (!tokenResult.valid) {
        return reply.status(401).send({
          error: {
            message: `Unauthorized: ${tokenResult.error}`,
            type: 'authentication_error',
          },
        })
      }

      const { sub: userId } = tokenResult.payload

      // 2. Authorize Tenant in DB
      try {
        const tenant = await this.db.findUserById(userId)
        if (!tenant) {
          return reply.status(403).send({
            error: {
              message: 'Forbidden: tenant not found',
              type: 'permission_error',
            },
          })
        }
        if (tenant.role === 'disabled') {
          return reply.status(403).send({
            error: {
              message: 'Forbidden: tenant account is disabled',
              type: 'permission_error',
            },
          })
        }
      } catch (err) {
        return reply.status(500).send({
          error: {
            message: `Internal authorization lookup failed: ${String(err)}`,
            type: 'internal_error',
          },
        })
      }

      // 3. Sliding window Rate Limiter for Images (30/min)
      const now = Date.now()
      this.sweepRateLimits(this.imageRateLimits, now)
      let bucket = this.imageRateLimits.get(userId)
      if (!bucket || now >= bucket.resetAt) {
        bucket = { count: 1, resetAt: now + 60_000 }
        this.imageRateLimits.set(userId, bucket)
      } else {
        bucket.count += 1
        if (bucket.count > 30) {
          return reply.status(429).send({
            error: {
              message: 'Rate limit exceeded: too many image generation requests per minute for tenant',
              type: 'rate_limit_error',
            },
          })
        }
      }

      // 4. Validate body
      const body = request.body as {
        prompt?: string
        model?: string
        num_steps?: number
        width?: number
        height?: number
      }
      if (!body || typeof body.prompt !== 'string' || body.prompt.trim().length === 0) {
        return reply.status(400).send({
          error: {
            message: 'Bad Request: prompt is required and must be a non-empty string',
            type: 'invalid_request_error',
          },
        })
      }

      // 5. Connect upstream signal
      const abortController = new AbortController()
      request.raw.on('close', () => {
        if (!reply.raw.writableEnded) {
          abortController.abort()
        }
      })

      // 6. Check Cloudflare Workers AI credentials first
      const cfCreds = await this.masterCredentials.resolveCloudflareCredentials()
      if (cfCreds.accountId && cfCreds.apiKey) {
        const model = (body.model && body.model.startsWith('@cf/'))
          ? body.model
          : '@cf/black-forest-labs/flux-1-schnell'
        const cfUrl = `https://api.cloudflare.com/client/v4/accounts/${encodeURIComponent(cfCreds.accountId)}/ai/run/${model}`

        try {
          const cfRes = await fetch(cfUrl, {
            method: 'POST',
            headers: {
              'Authorization': `Bearer ${cfCreds.apiKey}`,
              'Content-Type': 'application/json',
            },
            body: JSON.stringify({
              prompt: body.prompt.trim(),
              num_steps: body.num_steps ?? 4,
              ...(typeof body.width === 'number' ? { width: body.width } : {}),
              ...(typeof body.height === 'number' ? { height: body.height } : {}),
            }),
            signal: abortController.signal,
          })

          if (!cfRes.ok) {
            let upstreamErr = `Cloudflare Workers AI returned HTTP ${cfRes.status}`
            try {
              const errJson = await cfRes.json() as any
              if (errJson?.errors?.[0]?.message) {
                upstreamErr = errJson.errors[0].message
              }
            } catch {
              // use default message
            }
            return reply.status(502).send({
              error: {
                message: `Upstream image generation failed: ${upstreamErr}`,
                type: 'upstream_error',
              },
            })
          }

          const contentType = cfRes.headers.get('content-type') || 'image/png'
          const arrayBuffer = await cfRes.arrayBuffer()
          const buffer = Buffer.from(arrayBuffer)
          const b64Json = buffer.toString('base64')

          return reply.status(200).send({
            created: Math.floor(Date.now() / 1000),
            data: [
              {
                b64_json: b64Json,
                mime_type: contentType,
              },
            ],
          })
        } catch (err: unknown) {
          const msg = err instanceof Error ? err.message : String(err)
          return reply.status(502).send({
            error: {
              message: `Failed to connect to Cloudflare Workers AI image upstream: ${msg}`,
              type: 'upstream_error',
            },
          })
        }
      }

      // 7. Fallback: OpenAI if configured
      const openaiKey = await this.masterCredentials.resolveKeyForProvider('openai')
      if (openaiKey) {
        try {
          const oaiRes = await fetch('https://api.openai.com/v1/images/generations', {
            method: 'POST',
            headers: {
              'Authorization': `Bearer ${openaiKey}`,
              'Content-Type': 'application/json',
            },
            body: JSON.stringify({
              prompt: body.prompt.trim(),
              model: body.model || 'dall-e-3',
              n: 1,
              response_format: 'b64_json',
            }),
            signal: abortController.signal,
          })

          if (!oaiRes.ok) {
            const errText = await oaiRes.text()
            return reply.status(502).send({
              error: {
                message: `OpenAI image generation failed: ${errText}`,
                type: 'upstream_error',
              },
            })
          }

          const oaiJson = await oaiRes.json() as any
          return reply.status(200).send(oaiJson)
        } catch (err: unknown) {
          const msg = err instanceof Error ? err.message : String(err)
          return reply.status(502).send({
            error: {
              message: `Failed to connect to OpenAI image upstream: ${msg}`,
              type: 'upstream_error',
            },
          })
        }
      }

      // 8. No image generation provider configured
      return reply.status(502).send({
        error: {
          message: 'No image generation provider configured. Admin must configure Cloudflare Workers AI in Settings > Models.',
          type: 'configuration_error',
        },
      })
    }

    this.app.post('/internal/v1/images/generations', imageHandler)
    this.app.post('/internal/v1/llm/images/generations', imageHandler)
  }

  public async start(): Promise<void> {
    if (this.running) return
    const host = this.config.llmGatewayHost || '127.0.0.1'
    const port = this.config.llmGatewayPort || 4010

    await this.app.listen({ host, port })
    this.running = true
  }

  public async stop(): Promise<void> {
    if (!this.running) return
    await this.app.close()
    this.running = false
  }
}
