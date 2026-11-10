import { CentralRoutingStore } from '../config/llm-central-store.js'
import { getSupabaseClient } from '../supabase.js'
/**
 * Fastify bootstrap: assembles the HTTP server, registers plugins and routes,
 * and owns the DB lifecycle via the close hook.
 * @module dsh-server-login/web/server
 */

import Fastify, { type FastifyInstance } from 'fastify'
import fastifyStatic from '@fastify/static'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import type { ServerConfig } from '../config.js'
import { createDbAdapter, type DbAdapter, type PublicUser } from '../db/index.js'
import { createUserFs } from '../fs/provider.js'
import type { UserFs } from '../fs/user-fs.js'
import { decrypt, deriveKey } from '../crypto.js'
import { hashUid } from '../isolation.js'
import { LocalSpawner } from '../supervisor/orchestrator.js'
import { K8sSpawner } from '../supervisor/k8s-spawner.js'
import { createIdentitySigner, type IdentitySigner } from '../identity.js'
import { registerDshProxy } from '../supervisor/proxy.js'
import type { Spawner } from '../supervisor/spawner.js'
import { rateLimit } from './middleware/rate-limit.js'
import { authRoutes } from './routes/auth.js'
import { adminRoutes } from './routes/admin.js'
import { desktopRoutes } from './routes/desktop.js'
import { dshRoutes } from './routes/dsh.js'
import { pluginRoutes } from './routes/plugins.js'
import { domainRoutes } from './routes/domain.js'

declare module 'fastify' {
  interface FastifyInstance {
    db: DbAdapter
    config: ServerConfig
    supervisor: Spawner
    userFs: UserFs
    identity: IdentitySigner
    centralRoutingStore: CentralRoutingStore
  }
  interface FastifyRequest {
    user: PublicUser | null
  }
}

/**
 * Peers whose `X-Forwarded-For` is believed.
 *
 * The production edge is the Cloudflare tunnel, which connects to the
 * orchestrator over loopback; anything else reaching the port directly is a
 * client that must not be able to name its own address. Deployments behind
 * another proxy add it through `DSH_SERVER_LOGIN_TRUSTED_PROXIES`.
 */
export const TRUSTED_PROXY_PEERS: readonly string[] = ['127.0.0.1', '::1']

/**
 * Content-Security-Policy for pages this process serves itself (the launching
 * page and error pages).
 *
 * `unsafe-inline` covers the inline reload script of the launching page and
 * `unsafe-eval` the JSON hydration some static pages rely on; the tenant DSH is
 * a separate origin and keeps its own policy.
 */
export const ORCHESTRATOR_CSP = [
  "default-src 'self'",
  "script-src 'self' 'unsafe-inline' 'unsafe-eval'",
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data: blob: https:",
  "font-src 'self' data:",
  "connect-src 'self'",
  "frame-ancestors 'none'",
  "base-uri 'self'",
  "form-action 'self'",
].join('; ')

/**
 * Build the `trustProxy` list for a deployment.
 *
 * Loopback is always trusted (the tunnel/edge runs on this host); additional
 * peers come from `DSH_SERVER_LOGIN_TRUSTED_PROXIES` as a comma-separated list.
 *
 * @param config - resolved server configuration.
 * @returns the peers Fastify may read `X-Forwarded-For` from.
 */
export function trustedProxyPeers(config: Pick<ServerConfig, 'trustedProxyCidrs'>): readonly string[] {
  return [...TRUSTED_PROXY_PEERS, ...config.trustedProxyCidrs]
}

const webRoot = join(dirname(fileURLToPath(import.meta.url)), '../../web')

/**
 * Build a fully-wired Fastify instance. Does not call `listen`; the caller owns
 * bind + shutdown.
 * @param config - resolved runtime configuration.
 */
export async function buildServer(config: ServerConfig): Promise<FastifyInstance> {
  const identity = createIdentitySigner(config.dataRoot)
  config.identityPublicKey = identity.publicKey
  const db = await createDbAdapter(config)
  const encryptionKey = deriveKey(config.encryptionSecret)
  const resolveApiKey = async (userId: string): Promise<string | null> => {
    const ref = await db.getEnabledCredentialKeyRef(userId)
    if (ref === null) return null
    try {
      return decrypt(ref, encryptionKey)
    } catch {
      return null // corrupt ref — treat as unset, let the user re-enter it
    }
  }
  const resolveUid = async (userId: string): Promise<number> => {
    const user = await db.findUserById(userId)
    return user?.uid ?? hashUid(userId, config.baseUid)
  }
  const supervisor: Spawner =
    config.deployMode === 'k8s'
      ? new K8sSpawner(config, db, resolveApiKey, resolveUid)
      : new LocalSpawner(config, resolveApiKey, resolveUid, db)
  const userFs = createUserFs(config, (userId) => supervisor.ensureFileService(userId))

  const app = Fastify({
    logger: { level: config.logLevel },
    // Only the edge in front of this process may set `X-Forwarded-For`.
    // `true` would make every client able to choose its own rate-limit and
    // audit address, so the trusted peers are named explicitly and are the
    // loopback proxy (cloudflared/tunnel) plus `config.trustedProxyCidrs`.
    trustProxy: [...trustedProxyPeers(config)],
    bodyLimit: config.maxUploadBytes,
  })

  app.decorate('db', db)
  app.decorate('config', config)
  app.decorate('supervisor', supervisor)
  app.decorate('userFs', userFs)
  app.decorate('identity', identity)

  // Centralized LLM routing store: reads from Supabase public.system_config
  // on boot with disk/memory fallback cache.
  let sbClient = null
  if (config.supabaseUrl && config.supabaseAnonKey) {
    try {
      sbClient = getSupabaseClient(config)
    } catch (err) {
      app.log.warn(`[server] Failed to initialize Supabase client for LLM routing: ${String(err)}`)
    }
  }
  const centralRoutingStore = new CentralRoutingStore({
    supabaseClient: sbClient,
    cacheDir: config.dataRoot,
    logger: app.log,
  })
  await centralRoutingStore.loadOnBoot()
  app.decorate('centralRoutingStore', centralRoutingStore)
  app.decorateRequest('user', null)

  // Reverse proxy (subdomain + legacy subpath). Registered first so its global
  // onRequest hook intercepts per-user subdomain traffic before other hooks.
  await registerDshProxy(app)

  // Security headers for this process's own responses. The proxied tenant DSH
  // sends its own; these cover HTML and JSON from the orchestrator itself.
  app.addHook('onSend', async (_request, reply, payload) => {
    reply.header('x-content-type-options', 'nosniff')
    reply.header('x-frame-options', 'DENY')
    reply.header('referrer-policy', 'strict-origin-when-cross-origin')
    reply.header('strict-transport-security', 'max-age=31536000; includeSubDomains')
    reply.header('content-security-policy', ORCHESTRATOR_CSP)
    return payload
  })

  app.addHook('onClose', async () => {
    await supervisor.teardown()
    await db.close()
  })

  // Rate limiting first so auth/admin surfaces are covered by default.
  await app.register(rateLimit)

  // Domain-specific route groups (API).
  await app.register(authRoutes)
  await app.register(adminRoutes)
  await app.register(desktopRoutes)
  await app.register(dshRoutes)
  await app.register(pluginRoutes)
  await app.register(domainRoutes)

  // Static placeholder SPA last, so exact API routes take precedence over the
  // wildcard static handler.
  await app.register(fastifyStatic, {
    root: webRoot,
    prefix: '/',
    wildcard: true,
    index: ['index.html'],
  })

  return app
}
