// M-13: the gateway rate limiter drops buckets whose window closed, so the map
// does not grow for every tenant id the validator has seen.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { LlmLoopbackServer } from '../lib/gateway/llm-loopback-server.js'

function makeServer() {
  const config = { secureCookies: true, llmGatewayPort: 4010 }
  // The constructor only registers routes and builds the upstream client; it
  // does not listen, so a minimal set of collaborators is enough.
  return new LlmLoopbackServer({
    config,
    db: { findUserById: async () => undefined },
    centralRoutingStore: { getConfig: () => ({ failover: {} }) },
    masterCredentials: { resolveKeyForProvider: async () => undefined },
  })
}

test('M-13: expired buckets are swept once the map grows', () => {
  const server = makeServer()
  const buckets = server['imageRateLimits']
  const now = Date.now()
  // Below the threshold nothing is swept.
  buckets.set('keep', { count: 1, resetAt: now + 60_000 })
  server['sweepRateLimits'](buckets, now)
  assert.equal(buckets.size, 1)

  // Fill past the threshold with expired buckets.
  for (let i = 0; i < 1100; i += 1) {
    buckets.set(`expired-${i}`, { count: 1, resetAt: now - 1 })
  }
  server['sweepRateLimits'](buckets, now)
  assert.equal(buckets.size, 1)
  assert.ok(buckets.has('keep'))
})

test('M-13: a live tenant bucket survives a sweep', () => {
  const server = makeServer()
  const buckets = server['rateLimits']
  const now = Date.now()
  for (let i = 0; i < 1100; i += 1) buckets.set(`dead-${i}`, { count: 1, resetAt: now - 1 })
  buckets.set('live', { count: 3, resetAt: now + 30_000 })
  server['sweepRateLimits'](buckets, now)
  assert.deepEqual(buckets.get('live'), { count: 3, resetAt: now + 30_000 })
})
