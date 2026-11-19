import { test } from 'node:test'
import assert from 'node:assert/strict'
import { platformApiKey } from '../lib/supervisor/platform-key.js'

test('tenants get the platform DeepSeek key from the server environment', () => {
  assert.equal(platformApiKey({ DEEPSEEK_API_KEY: 'sk-platform' }), 'sk-platform')
})

test('surrounding whitespace is trimmed from the platform key', () => {
  assert.equal(platformApiKey({ DEEPSEEK_API_KEY: '  sk-platform \n' }), 'sk-platform')
})

test('no platform key yields null so no key is injected', () => {
  assert.equal(platformApiKey({}), null)
  assert.equal(platformApiKey({ DEEPSEEK_API_KEY: '   ' }), null)
})
