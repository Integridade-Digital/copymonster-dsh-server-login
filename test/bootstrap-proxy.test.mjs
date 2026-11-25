import assert from 'node:assert/strict'
import test from 'node:test'
import { buildUpstreamHeaders } from '../lib/supervisor/proxy.js'
import { apply } from '../lib/runtime.js'

test('proxy replaces client forwarding headers with canonical tenant host', () => {
  const headers = buildUpstreamHeaders({
    host: 'digital.copymonster.co',
    'x-forwarded-host': 'attacker.example',
    'x-forwarded-proto': 'http',
    cookie: 'sid=valid',
  }, 43127, 'digital.copymonster.co')
  assert.equal(headers.host, '127.0.0.1:43127')
  assert.equal(headers['x-forwarded-host'], 'digital.copymonster.co')
  assert.equal(headers['x-forwarded-proto'], 'https')
  assert.equal(headers.cookie, 'sid=valid')
})

test('tenant runtime registers watchdog section when role is main', () => {
  const previousRole = process.env.DSH_SERVER_LOGIN_ROLE
  const previousHandoff = process.env.DSH_SERVER_LOGIN_HANDOFF_PATH
  process.env.DSH_SERVER_LOGIN_ROLE = 'main'
  process.env.DSH_SERVER_LOGIN_HANDOFF_PATH = '/tmp/handoff.json'

  let registeredSection = null
  let disposed = false
  const ctx = {
    get(name) {
      if (name === 'systemPrompt') {
        return {
          section(section) {
            registeredSection = section
            return () => { disposed = true }
          },
        }
      }
      return undefined
    },
    on(event, fn) {
      if (event === 'dispose') {
        fn()
      }
    },
  }

  try {
    apply(ctx)
    assert.ok(registeredSection)
    assert.equal(registeredSection.name, 'dsh-server-login/watchdog')
    assert.ok(typeof registeredSection.text === 'string')
    assert.ok(registeredSection.text.includes('/tmp/handoff.json'))
    assert.equal(disposed, true)
  } finally {
    if (previousRole === undefined) delete process.env.DSH_SERVER_LOGIN_ROLE
    else process.env.DSH_SERVER_LOGIN_ROLE = previousRole
    if (previousHandoff === undefined) delete process.env.DSH_SERVER_LOGIN_HANDOFF_PATH
    else process.env.DSH_SERVER_LOGIN_HANDOFF_PATH = previousHandoff
  }
})
