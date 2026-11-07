import test from 'node:test'
import assert from 'node:assert/strict'
import { rmSync, existsSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import {
  CentralRoutingConfigSchema,
  DEFAULT_CENTRAL_ROUTING_CONFIG,
  parseCentralRoutingConfig,
  SYSTEM_CONFIG_LLM_ROUTING_KEY,
} from '../lib/config/llm-central-routing.js'
import { CentralRoutingStore } from '../lib/config/llm-central-store.js'

test('llm-central-routing schema: DEFAULT_CENTRAL_ROUTING_CONFIG is valid', () => {
  const config = parseCentralRoutingConfig(DEFAULT_CENTRAL_ROUTING_CONFIG)
  assert.equal(config.version, 1)
  assert.equal(config.mask.enabled, true)
  assert.equal(config.mask.publicModelName, 'Model CopyMonster')
  assert.equal(config.mask.publicModelId, 'copy-monster-default')
  assert.equal(config.mask.applyToTenantsOnly, true)
  assert.equal(config.routing.light.model, 'deepseek-v4.1-flash')
  assert.equal(config.routing.heavy.model, 'deepseek-v4.1-pro')
  assert.equal(config.failover.primary.model, 'deepseek-v4.1-pro')
  assert.equal(config.failover.chain.length, 2)
})

test('llm-central-routing schema: rejects invalid configs', () => {
  assert.throws(() => {
    parseCentralRoutingConfig({
      version: 0,
    })
  })

  assert.throws(() => {
    parseCentralRoutingConfig({
      ...DEFAULT_CENTRAL_ROUTING_CONFIG,
      mask: {
        ...DEFAULT_CENTRAL_ROUTING_CONFIG.mask,
        applyToTenantsOnly: false, // must be literal true
      },
    })
  })
})

test('CentralRoutingStore: falls back to defaults when Supabase is unavailable', async () => {
  const tmpDir = join('/tmp', `store-test-${Date.now()}`)
  const store = new CentralRoutingStore({
    cacheDir: tmpDir,
  })

  const cfg = await store.loadOnBoot()
  assert.equal(cfg.mask.publicModelName, 'Model CopyMonster')
  assert.equal(cfg.routing.light.model, 'deepseek-v4.1-flash')

  const cacheFile = join(tmpDir, 'llm-central-routing.cache.json')
  assert.ok(existsSync(cacheFile))
  const saved = JSON.parse(readFileSync(cacheFile, 'utf-8'))
  assert.equal(saved.mask.publicModelName, 'Model CopyMonster')

  rmSync(tmpDir, { recursive: true, force: true })
})

test('CentralRoutingStore: successfully loads and caches config from Supabase client', async () => {
  const tmpDir = join('/tmp', `store-test-sb-${Date.now()}`)
  const mockSupabase = {
    from(table) {
      assert.equal(table, 'system_config')
      return {
        select(cols) {
          return {
            eq(keyCol, val) {
              assert.equal(keyCol, 'key')
              assert.equal(val, SYSTEM_CONFIG_LLM_ROUTING_KEY)
              return {
                async maybeSingle() {
                  return {
                    data: {
                      value: {
                        version: 2,
                        mask: {
                          enabled: true,
                          publicModelId: 'copy-monster-default',
                          publicModelName: 'Model CopyMonster Super',
                          applyToTenantsOnly: true,
                        },
                        routing: {
                          light: {
                            provider: 'deepseek',
                            model: 'deepseek-v4.1-flash',
                            tasks: ['chat_title'],
                          },
                          heavy: {
                            provider: 'deepseek',
                            model: 'deepseek-v4.1-pro',
                            tasks: ['code_refactor'],
                          },
                        },
                        failover: {
                          enabled: true,
                          primary: {
                            provider: 'deepseek',
                            model: 'deepseek-v4.1-pro',
                          },
                          chain: [],
                        },
                      },
                    },
                    error: null,
                  }
                },
              }
            },
          }
        },
      }
    },
  }

  const store = new CentralRoutingStore({
    supabaseClient: mockSupabase,
    cacheDir: tmpDir,
  })

  const cfg = await store.loadOnBoot()
  assert.equal(cfg.version, 2)
  assert.equal(cfg.mask.publicModelName, 'Model CopyMonster Super')

  // Verify disk cache was updated
  const cacheFile = join(tmpDir, 'llm-central-routing.cache.json')
  const saved = JSON.parse(readFileSync(cacheFile, 'utf-8'))
  assert.equal(saved.mask.publicModelName, 'Model CopyMonster Super')

  rmSync(tmpDir, { recursive: true, force: true })
})

test('CentralRoutingStore: falls back to disk cache if Supabase query fails', async () => {
  const tmpDir = join('/tmp', `store-test-fail-${Date.now()}`)
  const failingSupabase = {
    from() {
      return {
        select() {
          return {
            eq() {
              return {
                async maybeSingle() {
                  return { data: null, error: new Error('Network timeout') }
                },
              }
            },
          }
        },
      }
    },
  }

  // Pre-seed disk cache with version 5
  const store1 = new CentralRoutingStore({ cacheDir: tmpDir })
  store1.updateConfig({
    ...DEFAULT_CENTRAL_ROUTING_CONFIG,
    version: 5,
    mask: {
      ...DEFAULT_CENTRAL_ROUTING_CONFIG.mask,
      publicModelName: 'Cached CopyMonster',
    },
  })

  // Start with failing Supabase
  const store2 = new CentralRoutingStore({
    supabaseClient: failingSupabase,
    cacheDir: tmpDir,
  })

  const cfg = await store2.loadOnBoot()
  assert.equal(cfg.version, 5)
  assert.equal(cfg.mask.publicModelName, 'Cached CopyMonster')

  rmSync(tmpDir, { recursive: true, force: true })
})
