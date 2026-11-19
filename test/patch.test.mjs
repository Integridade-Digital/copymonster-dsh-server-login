import { test } from 'node:test'
import assert from 'node:assert/strict'
import { renderPatch } from '../lib/supervisor/patch.js'
import { platformApiKeys } from '../lib/supervisor/platform-key.js'

test('renderPatch generates central patch with runtime and agent-default-model', () => {
  const patch = renderPatch(['extra-plugin'])

  assert.ok(patch.includes('id: dsh-server-login-runtime'))
  assert.ok(patch.includes('id: agent-default-model'))
  assert.ok(patch.includes('name: "@deepseek-ai/dsh-agent-default-model"'))
  assert.ok(patch.includes('provider: copymonster'))
  assert.ok(patch.includes('model: copy-monster-default'))
  assert.ok(patch.includes('id: extra-plugin'))
})

test('renderPatch omits the model-mask row so the profile patch owns it', () => {
  const patch = renderPatch(['extra-plugin'])

  // The overlay outranks the profile patch, so a model-mask row here makes DSH
  // refuse every Settings > Models write as "overridden by a home patch".
  assert.ok(!patch.includes('id: model-mask'))
  assert.ok(!patch.includes('@deepseek-ai/dsh-host-model-mask'))
  assert.ok(!patch.includes('primaryProvider'))
  assert.ok(!patch.includes('applyToTenantsOnly'))
  assert.ok(patch.includes('id: extra-plugin'), 'the enabled plugin is still injected')
})

test('renderPatch accepts an options object', () => {
  const patch = renderPatch({ enabledPlugins: ['extra-plugin'] })

  assert.ok(patch.includes('id: dsh-server-login-runtime'))
  assert.ok(patch.includes('id: agent-default-model'))
  assert.ok(patch.includes('id: extra-plugin'))
  assert.ok(!patch.includes('id: model-mask'))
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
