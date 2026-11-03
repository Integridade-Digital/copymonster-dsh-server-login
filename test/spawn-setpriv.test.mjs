import test from 'node:test'
import assert from 'node:assert/strict'
import { sanitizePath, resolveBinary, scrubEnv } from '../lib/supervisor/spawn.js'

test('sanitizePath: empty or undefined path returns default system paths', () => {
  const p1 = sanitizePath(undefined)
  assert.match(p1, /\/usr\/bin/)
  assert.match(p1, /\/bin/)
  assert.match(p1, /\/usr\/local\/bin/)

  const p2 = sanitizePath('')
  assert.match(p2, /\/usr\/bin/)
  assert.match(p2, /\/bin/)
})

test('sanitizePath: preserves custom paths and appends standard directories', () => {
  const custom = '/opt/custom/node/bin:/home/user/.nvm/bin'
  const result = sanitizePath(custom)
  assert.ok(result.startsWith('/opt/custom/node/bin:/home/user/.nvm/bin'))
  assert.match(result, /\/usr\/bin/)
  assert.match(result, /\/bin/)
  // Verify no duplicate entries
  const parts = result.split(':')
  const unique = new Set(parts)
  assert.equal(parts.length, unique.size)
})

test('resolveBinary: leaves paths with slashes untouched', () => {
  assert.equal(resolveBinary('/custom/bin/setpriv'), '/custom/bin/setpriv')
  assert.equal(resolveBinary('./bin/setpriv'), './bin/setpriv')
})

test('resolveBinary: resolves setpriv to existing system binary', () => {
  const resolved = resolveBinary('setpriv')
  // In Linux systems, setpriv should resolve to /bin/setpriv or /usr/bin/setpriv if present
  assert.ok(resolved.endsWith('setpriv'))
  if (resolved !== 'setpriv') {
    assert.ok(resolved.startsWith('/'))
  }
})

test('scrubEnv: guarantees PATH is populated with system paths', () => {
  const clean = scrubEnv({ SECRET_TOKEN: 'leaked', PATH: '/custom/bin' })
  assert.equal(clean.SECRET_TOKEN, undefined)
  assert.match(clean.PATH, /\/custom\/bin/)
  assert.match(clean.PATH, /\/usr\/bin/)
  assert.match(clean.PATH, /\/bin/)
})

test('scrubEnv: populates PATH even if input PATH is undefined', () => {
  const clean = scrubEnv({ HOME: '/tmp' })
  assert.ok(clean.PATH)
  assert.match(clean.PATH, /\/usr\/bin/)
  assert.match(clean.PATH, /\/bin/)
})
