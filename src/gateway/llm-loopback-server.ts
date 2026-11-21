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

export class LlmLoopbackServer {
  private readonly app: FastifyInstance
  private readonly config: ServerConfig
  private readonly db: Pick<DbAdapter, 'findUserById'>
  private readonly upstreamClient: UpstreamLlmClient
  private readonly rateLimits = new Map<string, RateLimitBucket>()
  private running = false

  constructor(options: LlmLoopbackServerOptions) {
    this.config = options.config
    this.db = options.db
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
