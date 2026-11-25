// M-6: a running gateway adopts an Admin routing change without a restart.
// Realtime delivers the change immediately; the poll is the backstop; a
// concurrent burst collapses onto one Supabase read.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { CentralRoutingStore } from '../lib/config/llm-central-store.js'

function routing(provider, model) {
  return {
    version: 1,
    mask: {
      enabled: true,
      publicModelId: 'copy-monster-default',
      publicModelName: 'Model CopyMonster',
      applyToTenantsOnly: true,
    },
    routing: {
      light: { provider: '', model: '', tasks: [] },
      heavy: { provider: '', model: '', tasks: [] },
    },
    failover: {
      enabled: false,
      primary: { provider, model },
      chain: [],
    },
  }
}

/** A Supabase stub whose single row can be swapped between reads. */
function makeClient(initial) {
  const state = { value: initial, reads: 0, failNext: false }
  const client = {
    from() {
      return {
        select() {
          return this
        },
        eq() {
          return this
        },
        maybeSingle: async () => {
          if (state.failNext) {
            state.failNext = false
            return { data: null, error: { message: 'boom' } }
          }
          state.reads += 1
          return { data: { value: state.value }, error: null }
        },
      }
    },
  }
  return { client, state }
}

test('M-6: a live gateway swaps to the new provider after a reload', async () => {
  const { client, state } = makeClient(routing('openrouter', 'old/model'))
  const store = new CentralRoutingStore({ supabaseClient: client })
  await store.loadOnBoot()
  assert.equal(store.getConfig().failover.primary.provider, 'openrouter')

  state.value = routing('deepseek', 'deepseek-chat')
  await store.triggerReload()

  // The next turn resolves through getConfig, so it sees the new route.
  assert.equal(store.getConfig().failover.primary.provider, 'deepseek')
  assert.equal(store.getConfig().failover.primary.model, 'deepseek-chat')
})

test('M-6: an invalid row keeps the working route instead of blanking it', async () => {
  const { client, state } = makeClient(routing('openrouter', 'good/model'))
  const store = new CentralRoutingStore({ supabaseClient: client })
  await store.loadOnBoot()

  state.value = { version: 1, failover: { primary: { provider: '', model: '' } } }
  await store.triggerReload()

  assert.equal(store.getConfig().failover.primary.provider, 'openrouter')
})

test('M-6: a Supabase failure during reload keeps the loaded configuration', async () => {
  const { client, state } = makeClient(routing('openrouter', 'good/model'))
  const store = new CentralRoutingStore({ supabaseClient: client })
  await store.loadOnBoot()

  state.failNext = true
  await store.triggerReload()

  assert.equal(store.getConfig().failover.primary.model, 'good/model')
})

test('M-6: concurrent reload triggers share one Supabase read', async () => {
  const { client, state } = makeClient(routing('openrouter', 'a/model'))
  const store = new CentralRoutingStore({ supabaseClient: client })
  await store.loadOnBoot()
  const before = state.reads

  await Promise.all([store.triggerReload(), store.triggerReload(), store.triggerReload()])

  assert.equal(state.reads - before, 1)
})

test('M-6: the poll adopts a change even when no event arrives', async () => {
  const { client, state } = makeClient(routing('openrouter', 'first/model'))
  const store = new CentralRoutingStore({ supabaseClient: client })
  await store.loadOnBoot()

  state.value = routing('openai', 'second/model')
  store.startPolling(10)
  try {
    const deadline = Date.now() + 2_000
    while (store.getConfig().failover.primary.provider !== 'openai' && Date.now() < deadline) {
      await new Promise((resolve) => setTimeout(resolve, 10))
    }
    assert.equal(store.getConfig().failover.primary.provider, 'openai')
  } finally {
    store.stopPolling()
  }
})

test('M-6: subscribing without Realtime support is harmless', () => {
  const store = new CentralRoutingStore({ supabaseClient: { from() {} } })
  assert.doesNotThrow(() => store.subscribeToChanges())
  // A realtime-capable stub that throws must also be contained.
  const throwing = new CentralRoutingStore({
    supabaseClient: {
      from() {},
      channel() {
        throw new Error('realtime disabled')
      },
    },
  })
  assert.doesNotThrow(() => throwing.subscribeToChanges())
})

test('M-6: shutdown removes the realtime channel so the process can drain', async () => {
  let removed
  const channel = { on() { return channel }, subscribe() { return channel } }
  const store = new CentralRoutingStore({
    supabaseClient: {
      from() {},
      channel() {
        return channel
      },
      async removeChannel(value) {
        removed = value
      },
    },
  })
  store.subscribeToChanges()
  await store.unsubscribe()
  assert.equal(removed, channel)
  // Unsubscribing twice, or with no channel, is a no-op.
  await store.unsubscribe()
})
