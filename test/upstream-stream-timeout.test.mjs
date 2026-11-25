// M-8: the 60 s upstream timeout must cover the wait for response headers
// only. A streaming body lives past that deadline, so the timer is released
// once the stream is handed to the caller instead of aborting the generation.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { Readable } from 'node:stream'
import { UpstreamLlmClient } from '../lib/gateway/upstream-client.js'

function makeClient() {
  const centralRoutingStore = {
    getConfig: () => ({
      failover: {
        primary: { provider: 'openrouter', model: 'primary/model' },
        chain: [],
      },
    }),
  }
  const masterCredentials = {
    resolveKeyForProvider: async () => 'sk-test',
  }
  return new UpstreamLlmClient({ masterCredentials, centralRoutingStore })
}

function streamingResponse() {
  const encoder = new TextEncoder()
  let controllerRef
  const body = new ReadableStream({
    start(controller) {
      controllerRef = controller
      controller.enqueue(encoder.encode('data: {"chunk":1}\n\n'))
    },
  })
  return {
    response: new Response(body, { status: 200, headers: { 'content-type': 'text/event-stream' } }),
    push: (text) => controllerRef.enqueue(encoder.encode(text)),
    close: () => controllerRef.close(),
  }
}

test('M-8: a streamed body is not aborted by the header timeout', async (t) => {
  const originalFetch = globalThis.fetch
  const { response, push, close } = streamingResponse()
  let capturedSignal
  globalThis.fetch = async (_url, init) => {
    capturedSignal = init.signal
    return response
  }
  t.after(() => {
    globalThis.fetch = originalFetch
  })

  const client = makeClient()
  const result = await client.dispatch(
    { model: 'copymonster/copy-monster-default', messages: [], stream: true },
    {},
  )
  assert.equal(result.type, 'stream')

  // The signal is no longer the caller's to abort: emitting more chunks after
  // the dispatch returned proves the stream stayed open past the header phase.
  assert.equal(capturedSignal.aborted, false)
  push('data: {"chunk":2}\n\n')
  close()

  const chunks = []
  for await (const chunk of result.stream) chunks.push(chunk.toString())
  const body = chunks.join('')
  assert.match(body, /"chunk":1/)
  assert.match(body, /"chunk":2/)
})

test('M-8: the header timeout still bounds a request that never answers', async (t) => {
  const originalFetch = globalThis.fetch
  globalThis.fetch = (_url, init) =>
    new Promise((_resolve, reject) => {
      init.signal.addEventListener('abort', () => reject(init.signal.reason))
    })
  t.after(() => {
    globalThis.fetch = originalFetch
  })

  const client = makeClient()
  // A request whose headers never arrive fails fast through the error path
  // rather than hanging; the abort reaches the fetch, not the stream.
  const startedAt = performance.now()
  const pending = client.dispatch(
    { model: 'copymonster/copy-monster-default', messages: [], stream: true },
    { signal: AbortSignal.timeout(50) },
  )
  const result = await pending
  assert.equal(result.type, 'error')
  assert.ok(performance.now() - startedAt < 5_000)
})

test('M-8: a non-streaming body still reads under the header timeout', async () => {
  const originalFetch = globalThis.fetch
  globalThis.fetch = async () =>
    new Response(JSON.stringify({ choices: [{ message: { content: 'ok' } }] }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    })
  try {
    const client = makeClient()
    const result = await client.dispatch(
      { model: 'copymonster/copy-monster-default', messages: [], stream: false },
      {},
    )
    assert.equal(result.type, 'json')
    assert.deepEqual(result.data, { choices: [{ message: { content: 'ok' } }] })
  } finally {
    globalThis.fetch = originalFetch
  }
})
