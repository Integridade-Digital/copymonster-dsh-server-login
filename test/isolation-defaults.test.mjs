// Production isolation defaults (SEC-007): a deployment must not inherit a
// shared-uid fleet or an unguarded loopback port by leaving a variable unset.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { assertProductionIsolation, resolveConfig } from '../lib/config.js'

const BASE_ENV = {
  DSH_SERVER_LOGIN_SUPABASE_URL: 'https://example.supabase.co',
  DSH_SERVER_LOGIN_SUPABASE_ANON_KEY: 'anon-key',
  SESSION_SECRET: 'isolation-test-session-secret-32chars',
}

function withEnv(overrides, run) {
  const saved = {}
  for (const [key, value] of Object.entries({ ...BASE_ENV, ...overrides })) {
    saved[key] = process.env[key]
    if (value === undefined) delete process.env[key]
    else process.env[key] = value
  }
  try {
    return run()
  } finally {
    for (const [key, value] of Object.entries(saved)) {
      if (value === undefined) delete process.env[key]
      else process.env[key] = value
    }
  }
}

test('isolation: a fresh config defaults to account isolation and the port guard', () => {
  withEnv({ DSH_SERVER_LOGIN_ISOLATION_MODE: undefined, DSH_SERVER_LOGIN_PORT_GUARD: undefined }, () => {
    const config = resolveConfig()
    assert.equal(config.isolationMode, 'account')
    assert.equal(config.portGuard, true)
  })
})

test('isolation: production accepts the account default', () => {
  withEnv({ NODE_ENV: 'production' }, () => {
    assert.doesNotThrow(() => assertProductionIsolation(resolveConfig()))
  })
})

test('isolation: production refuses soft isolation', () => {
  withEnv({ NODE_ENV: 'production', DSH_SERVER_LOGIN_ISOLATION_MODE: 'soft' }, () => {
    assert.throws(
      () => assertProductionIsolation(resolveConfig()),
      /refuses DSH_SERVER_LOGIN_ISOLATION_MODE=soft/,
    )
  })
})

test('isolation: production refuses a disabled port guard', () => {
  withEnv({ NODE_ENV: 'production', DSH_SERVER_LOGIN_PORT_GUARD: 'false' }, () => {
    assert.throws(
      () => assertProductionIsolation(resolveConfig()),
      /refuses DSH_SERVER_LOGIN_PORT_GUARD=false/,
    )
  })
})

test('isolation: a non-production process may still opt into soft isolation', () => {
  withEnv({ NODE_ENV: 'development', DSH_SERVER_LOGIN_ISOLATION_MODE: 'soft' }, () => {
    const config = resolveConfig()
    assert.equal(config.isolationMode, 'soft')
    assert.doesNotThrow(() => assertProductionIsolation(config))
  })
})
