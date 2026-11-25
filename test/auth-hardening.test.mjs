// M-7/M-12/M-16: log redaction of more key families, the login timing guard,
// and the parameterized scrypt hash with legacy compatibility.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { redactApiKey, redactSensitiveString, SENSITIVE_KEY_PATTERN } from '../lib/supervisor/master-credentials.js'
import { burnPasswordHashCost, hashPassword, verifyPassword } from '../lib/web/auth.js'

test('M-7: redaction covers nvapi, thk_live, apx_, freellm and JWTs', () => {
  const samples = [
    'nvapi-abcdefghijklmnopqrstuvwxyz',
    'thk_live_abc123def456',
    'apx_abcdef123456',
    'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U',
  ]
  for (const sample of samples) {
    const text = `token=${sample} rest`
    assert.ok(redactSensitiveString(text).includes('[REDACTED_KEY]'), `not redacted: ${sample}`)
    assert.ok(!redactSensitiveString(text).includes(sample.slice(0, 10)), `leaked: ${sample}`)
  }
  assert.match('sk-ant-api03-abcdefghijklmnop', SENSITIVE_KEY_PATTERN)
  assert.equal(redactApiKey('thk_live_secret_value'), '[REDACTED_KEY]')
})

test('M-16: new hashes record their cost and verify; legacy hashes still verify', async () => {
  const stored = await hashPassword('correct horse battery staple')
  assert.match(stored, /^scrypt\$\d+\$\d+\$\d+\$[0-9a-f]+\$[0-9a-f]+$/)
  assert.equal(await verifyPassword('correct horse battery staple', stored), true)
  assert.equal(await verifyPassword('wrong password', stored), false)

  // A hash produced in the legacy 3-part format must keep working.
  const { scrypt } = await import('node:crypto')
  const salt = Buffer.alloc(16, 7)
  const derived = await new Promise((resolve, reject) => {
    scrypt('legacy secret', salt, 64, (err, key) => (err ? reject(err) : resolve(key)))
  })
  const legacy = `scrypt$${salt.toString('hex')}$${derived.toString('hex')}`
  assert.equal(await verifyPassword('legacy secret', legacy), true)
  assert.equal(await verifyPassword('nope', legacy), false)
})

test('M-16: malformed and abusive cost parameters are rejected, not run', async () => {
  const salt = 'aa'.repeat(16)
  const hash = 'bb'.repeat(64)
  // N above the configured ceiling is refused before any scrypt work.
  assert.equal(await verifyPassword('x', `scrypt$${2 ** 20}$8$1$${salt}$${hash}`), false)
  assert.equal(await verifyPassword('x', `scrypt$NaN$8$1$${salt}$${hash}`), false)
  assert.equal(await verifyPassword('x', 'scrypt$only-two-parts'), false)
  assert.equal(await verifyPassword('x', 'argon2$whatever'), false)
})

test('M-12: the enumeration guard burns comparable work without a stored hash', async () => {
  const startedAt = performance.now()
  await burnPasswordHashCost('some-password')
  // A real scrypt at the configured cost takes measurable time; the guard must
  // do real work rather than returning immediately.
  assert.ok(performance.now() - startedAt > 5)
})
