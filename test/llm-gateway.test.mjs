import { test } from 'node:test'
import assert from 'node:assert/strict'
import { LlmLoopbackServer } from '../lib/gateway/llm-loopback-server.js'
import { createTenantToken } from '../lib/gateway/token-validator.js'
import { CentralRoutingStore } from '../lib/config/llm-central-store.js'
import { MasterCredentialsResolver } from '../lib/supervisor/master-credentials.js'

const SECRET = 'test-internal-gateway-secret-32-chars-long'

function createTestSetup(overrides = {}) {
  const users = new Map([
    ['user-1', { id: 'user-1', username: 'tenant-one', role: 'active' }],
    ['user-disabled', { id: 'user-disabled', username: 'disabled-user', role: 'disabled' }],
  ])

  const mockDb = {
    findUserById: async (id) => users.get(id),
    findUserByUsername: async (name) => {
      for (const u of users.values()) {
        if (u.username === name) return u
      }
      return undefined
    },
    listPublicUsers: async () => Array.from(users.values()),
    ...overrides.db,
  }

  const routingStore = new CentralRoutingStore()
  if (overrides.routing) {
    routingStore.updateConfig(overrides.routing)
  }

  const credentialsResolver = new MasterCredentialsResolver({
    db: mockDb,
    dataRoot: '/tmp',
  })

  // Override resolveKeyForProvider if requested
  if (overrides.keys) {
    credentialsResolver.resolveKeyForProvider = async (provider) => overrides.keys[provider]
  }

  const config = {
    dataRoot: '/tmp',
    llmGatewayHost: '127.0.0.1',
    llmGatewayPort: 4010,
    gatewayInternalSecret: SECRET,
    ...overrides.config,
  }

  const server = new LlmLoopbackServer({
    config,
    db: mockDb,
    centralRoutingStore: routingStore,
    masterCredentials: credentialsResolver,
  })

  return { server, routingStore, credentialsResolver, mockDb }
}

test('llm gateway: GET /internal/health returns status ok', async () => {
  const { server } = createTestSetup()
  const res = await server.getFastify().inject({
    method: 'GET',
    url: '/internal/health',
  })

  assert.equal(res.statusCode, 200)
  const body = JSON.parse(res.body)
  assert.equal(body.status, 'ok')
  assert.ok(typeof body.timestamp === 'number')
})

test('llm gateway: rejects requests without Authorization header with 401', async () => {
  const { server } = createTestSetup()
  const res = await server.getFastify().inject({
    method: 'POST',
    url: '/internal/v1/llm/chat/completions',
    payload: { model: 'copymonster/copy-monster-default', messages: [] },
  })

  assert.equal(res.statusCode, 401)
  const body = JSON.parse(res.body)
  assert.match(body.error.message, /authorization header/i)
})

test('llm gateway: rejects requests with invalid or tampered token with 401', async () => {
  const { server } = createTestSetup()
  const res = await server.getFastify().inject({
    method: 'POST',
    url: '/internal/v1/llm/chat/completions',
    headers: { authorization: 'Bearer invalid.token.signature' },
    payload: { model: 'copymonster/copy-monster-default', messages: [] },
  })

  assert.equal(res.statusCode, 401)
  const body = JSON.parse(res.body)
  assert.match(body.error.message, /unauthorized/i)
})

test('llm gateway: rejects requests for unknown or disabled tenant with 403', async () => {
  const { server } = createTestSetup()

  // 1. Unknown tenant
  const unknownToken = createTenantToken({
    userId: 'unknown-id',
    slug: 'unknown-slug',
    secret: SECRET,
  })
  const res1 = await server.getFastify().inject({
    method: 'POST',
    url: '/internal/v1/llm/chat/completions',
    headers: { authorization: `Bearer ${unknownToken}` },
    payload: { model: 'copymonster/copy-monster-default', messages: [{ role: 'user', content: 'hi' }] },
  })
  assert.equal(res1.statusCode, 403)
  assert.match(JSON.parse(res1.body).error.message, /not found/i)

  // 2. Disabled tenant
  const disabledToken = createTenantToken({
    userId: 'user-disabled',
    slug: 'disabled-user',
    secret: SECRET,
  })
  const res2 = await server.getFastify().inject({
    method: 'POST',
    url: '/internal/v1/llm/chat/completions',
    headers: { authorization: `Bearer ${disabledToken}` },
    payload: { model: 'copymonster/copy-monster-default', messages: [{ role: 'user', content: 'hi' }] },
  })
  assert.equal(res2.statusCode, 403)
  assert.match(JSON.parse(res2.body).error.message, /disabled/i)
})

test('llm gateway: successfully dispatches non-streaming chat completion', async () => {
  const oldFetch = globalThis.fetch
  globalThis.fetch = async (url, options) => {
    assert.match(url, /deepseek\.com/)
    const headers = options.headers
    assert.equal(headers['Authorization'], 'Bearer sk-ds-test-key')

    return new Response(
      JSON.stringify({
        id: 'chatcmpl-test',
        choices: [{ message: { role: 'assistant', content: 'Hello from DeepSeek!' } }],
      }),
      { status: 200, headers: { 'Content-Type': 'application/json' } },
    )
  }

  try {
    const { server } = createTestSetup({
      keys: { deepseek: 'sk-ds-test-key' },
    })

    const token = createTenantToken({
      userId: 'user-1',
      slug: 'tenant-one',
      secret: SECRET,
    })

    const res = await server.getFastify().inject({
      method: 'POST',
      url: '/internal/v1/llm/chat/completions',
      headers: { authorization: `Bearer ${token}` },
      payload: {
        model: 'copymonster/copy-monster-default',
        messages: [{ role: 'user', content: 'Hello' }],
      },
    })

    assert.equal(res.statusCode, 200)
    const body = JSON.parse(res.body)
    assert.equal(body.choices[0].message.content, 'Hello from DeepSeek!')
  } finally {
    globalThis.fetch = oldFetch
  }
})

test('llm gateway: transparent failover before first chunk on HTTP 402', async () => {
  const calls = []
  const oldFetch = globalThis.fetch

  globalThis.fetch = async (url, options) => {
    calls.push({ url, headers: options.headers })

    // Simulate primary (deepseek) payment required (402)
    if (url.includes('deepseek.com')) {
      return new Response(
        JSON.stringify({ error: { message: 'Insufficient balance', code: 'insufficient_quota' } }),
        { status: 402, headers: { 'Content-Type': 'application/json' } },
      )
    }

    // Secondary (openrouter) succeeds
    if (url.includes('openrouter.ai')) {
      return new Response(
        JSON.stringify({
          id: 'chatcmpl-openrouter',
          choices: [{ message: { role: 'assistant', content: 'Fallback answer from OpenRouter' } }],
        }),
        { status: 200, headers: { 'Content-Type': 'application/json' } },
      )
    }

    return new Response('Not found', { status: 404 })
  }

  try {
    const { server } = createTestSetup({
      keys: {
        deepseek: 'sk-ds-key',
        openrouter: 'sk-or-fallback-key',
      },
      routing: {
        version: 1,
        mask: { enabled: true, publicModelId: 'copy-monster-default', publicModelName: 'Model CopyMonster', applyToTenantsOnly: true },
        routing: {
          light: { provider: 'deepseek', model: 'deepseek-chat', tasks: [] },
          heavy: { provider: 'deepseek', model: 'deepseek-chat', tasks: [] },
        },
        failover: {
          enabled: true,
          primary: { provider: 'deepseek', model: 'deepseek-chat' },
          chain: [{ provider: 'openrouter', model: 'deepseek/deepseek-chat', maxRetries: 1, timeoutMs: 15000 }],
        },
      },
    })

    const token = createTenantToken({
      userId: 'user-1',
      slug: 'tenant-one',
      secret: SECRET,
    })

    const res = await server.getFastify().inject({
      method: 'POST',
      url: '/internal/v1/llm/chat/completions',
      headers: { authorization: `Bearer ${token}` },
      payload: {
        model: 'copymonster/copy-monster-default',
        messages: [{ role: 'user', content: 'Test failover' }],
      },
    })

    assert.equal(res.statusCode, 200)
    const body = JSON.parse(res.body)
    assert.equal(body.choices[0].message.content, 'Fallback answer from OpenRouter')

    // Confirm both upstream endpoints were invoked
    assert.equal(calls.length, 2)
    assert.match(calls[0].url, /deepseek\.com/)
    assert.match(calls[1].url, /openrouter\.ai/)
  } finally {
    globalThis.fetch = oldFetch
  }
})

test('llm gateway: enforces rate limiting per tenant', async () => {
  const oldFetch = globalThis.fetch
  globalThis.fetch = async () => new Response(JSON.stringify({ ok: true }), { status: 200, headers: { 'Content-Type': 'application/json' } })

  try {
    const { server } = createTestSetup({
      keys: { deepseek: 'sk-key' },
    })

    const token = createTenantToken({
      userId: 'user-1',
      slug: 'tenant-one',
      secret: SECRET,
    })

    // Fire 60 requests (within limit)
    for (let i = 0; i < 60; i++) {
      const r = await server.getFastify().inject({
        method: 'POST',
        url: '/internal/v1/llm/chat/completions',
        headers: { authorization: `Bearer ${token}` },
        payload: { model: 'copymonster/copy-monster-default', messages: [{ role: 'user', content: 'hi' }] },
      })
      assert.equal(r.statusCode, 200)
    }

    // 61st request triggers 429
    const blocked = await server.getFastify().inject({
      method: 'POST',
      url: '/internal/v1/llm/chat/completions',
      headers: { authorization: `Bearer ${token}` },
      payload: { model: 'copymonster/copy-monster-default', messages: [{ role: 'user', content: 'hi' }] },
    })

    assert.equal(blocked.statusCode, 429)
    assert.match(JSON.parse(blocked.body).error.message, /rate limit/i)
  } finally {
    globalThis.fetch = oldFetch
  }
})
