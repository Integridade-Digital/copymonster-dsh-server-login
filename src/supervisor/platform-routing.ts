import { createHmac } from 'node:crypto'
import { z } from 'zod'
import type { ServerConfig } from '../config.js'
import type { TenantRoutingPolicy } from '../fs/local-user-fs.js'

const ROUTING_PATH = '/api/internal/platform-model-routing'
const routeId = z.string().max(256)
const responseSchema = z.object({
  policy: z.object({
    primaryProvider: routeId,
    primaryModel: routeId,
    fallbackProvider: routeId,
    fallbackModel: routeId,
    fallbackPolicy: z.object({
      enabled: z.boolean(),
      maxAttempts: z.number().int().positive(),
      timeoutMs: z.number().int().positive(),
    }),
  }).nullable(),
})

/** Load the platform policy before preparing a local DSH profile. */
export async function loadPlatformRouting(
  config: Pick<ServerConfig, 'mainAppUrl' | 'sessionSecret'>,
): Promise<TenantRoutingPolicy | undefined> {
  const issued = String(Date.now())
  const signature = createHmac('sha256', config.sessionSecret)
    .update(`GET ${ROUTING_PATH}\n${issued}`).digest('hex')
  const response = await fetch(new URL(ROUTING_PATH, config.mainAppUrl), {
    headers: {
      'x-dsh-routing-issued': issued,
      'x-dsh-routing-signature': signature,
    },
    redirect: 'error',
    signal: AbortSignal.timeout(5_000),
  })
  // During a rolling upgrade the old main app does not expose the route.
  if (response.status === 404) return
  if (!response.ok) throw new Error(`Platform routing read failed (HTTP ${response.status})`)
  const { policy } = responseSchema.parse(await response.json())
  if (policy === null) return

  return {
    primary: { provider: policy.primaryProvider, model: policy.primaryModel },
    fallback: { provider: policy.fallbackProvider, model: policy.fallbackModel },
    failoverEnabled: policy.fallbackPolicy.enabled,
    maxAttempts: policy.fallbackPolicy.maxAttempts,
    timeoutMs: policy.fallbackPolicy.timeoutMs,
  }
}
