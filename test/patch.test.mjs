import { test } from 'node:test'
import assert from 'node:assert/strict'
import { renderPatch, resolveDefaultRoutingPolicy } from '../lib/supervisor/patch.js'
import { platformApiKeys } from '../lib/supervisor/platform-key.js'

test('renderPatch generates central patch with runtime, model-mask and agent-default-model', () => {
  const patch = renderPatch(['extra-plugin'])

  assert.ok(patch.includes('id: dsh-server-login-runtime'))
  assert.ok(patch.includes('id: model-mask'))
  assert.ok(patch.includes('name: "@changfenhuang/dsh-host-model-mask"'))
  assert.ok(patch.includes('virtualProvider: copymonster'))
  assert.ok(patch.includes('virtualModel: copy-monster-default'))
  assert.ok(patch.includes('virtualModelName: Model CopyMonster'))
  assert.ok(patch.includes('id: agent-default-model'))
  assert.ok(patch.includes('name: "@deepseek-ai/dsh-agent-default-model"'))
  assert.ok(patch.includes('provider: copymonster'))
  assert.ok(patch.includes('model: copy-monster-default'))
  assert.ok(patch.includes('id: extra-plugin'))
})

test('renderPatch accepts custom routing policy', () => {
  const patch = renderPatch([], {
    routingPolicy: {
      primaryProvider: 'deepseek-official',
      primaryModel: 'deepseek-chat',
      fallbackProvider: 'openrouter',
      fallbackModel: 'deepseek/deepseek-chat',
      failoverEnabled: true,
      maxAttempts: 3,
      timeoutMs: 45000,
    },
  })

  assert.ok(patch.includes('primaryProvider: deepseek-official'))
  assert.ok(patch.includes('primaryModel: deepseek-chat'))
  assert.ok(patch.includes('fallbackProvider: openrouter'))
  assert.ok(patch.includes('fallbackModel: deepseek/deepseek-chat'))
  assert.ok(patch.includes('maxAttempts: 3'))
  assert.ok(patch.includes('timeoutMs: 45000'))
})

test('platformApiKeys collects all set keys and trims whitespace', () => {
  const keys = platformApiKeys({
    DEEPSEEK_API_KEY: '  sk-deepseek  ',
    OPENROUTER_API_KEY: 'sk-or-v1-abc',
    OPENAI_API_KEY: '  sk-proj-xyz  ',
    OTHER_KEY: 'ignore-me',
  })

  assert.equal(keys.DEEPSEEK_API_KEY, 'sk-deepseek')
  assert.equal(keys.OPENROUTER_API_KEY, 'sk-or-v1-abc')
  assert.equal(keys.OPENAI_API_KEY, 'sk-proj-xyz')
  assert.equal(keys.OTHER_KEY, undefined)
})
