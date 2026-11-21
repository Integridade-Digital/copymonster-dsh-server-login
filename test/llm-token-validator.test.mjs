import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createTenantToken, verifyTenantToken } from '../lib/gateway/token-validator.js'

const SECRET = 'test-secret-key-at-least-32-chars-long-12345'

test('token validator: mints and verifies valid tenant token', () => {
  const token = createTenantToken({
    userId: 'user-uuid-123',
    slug: 'acme-corp',
    secret: SECRET,
  })

  assert.ok(typeof token === 'string')
  assert.equal(token.split('.').length, 3)

  const res = verifyTenantToken(token, SECRET)
  assert.equal(res.valid, true)
  if (res.valid) {
    assert.equal(res.payload.sub, 'user-uuid-123')
    assert.equal(res.payload.slug, 'acme-corp')
    assert.equal(res.payload.scope, 'llm:infer')
    assert.ok(res.payload.exp > res.payload.iat)
  }
})

test('token validator: accepts Bearer prefix in header', () => {
  const rawToken = createTenantToken({
    userId: 'user-uuid-456',
    slug: 'beta-tenant',
    secret: SECRET,
  })

  const res = verifyTenantToken(`Bearer ${rawToken}`, SECRET)
  assert.equal(res.valid, true)
  if (res.valid) {
    assert.equal(res.payload.sub, 'user-uuid-456')
  }
})

test('token validator: rejects expired token', () => {
  const expiredToken = createTenantToken({
    userId: 'user-uuid-123',
    slug: 'acme-corp',
    secret: SECRET,
    ttlSeconds: -10, // already expired
  })

  const res = verifyTenantToken(expiredToken, SECRET)
  assert.equal(res.valid, false)
  if (!res.valid) {
    assert.match(res.error, /expired/i)
  }
})

test('token validator: rejects tampered signature', () => {
  const token = createTenantToken({
    userId: 'user-uuid-123',
    slug: 'acme-corp',
    secret: SECRET,
  })

  const parts = token.split('.')
  // Change one character in signature
  const tamperedSig = parts[2].slice(0, -1) + (parts[2].slice(-1) === 'a' ? 'b' : 'a')
  const tamperedToken = `${parts[0]}.${parts[1]}.${tamperedSig}`

  const res = verifyTenantToken(tamperedToken, SECRET)
  assert.equal(res.valid, false)
  if (!res.valid) {
    assert.match(res.error, /signature/i)
  }
})

test('token validator: rejects token verified with wrong secret', () => {
  const token = createTenantToken({
    userId: 'user-uuid-123',
    slug: 'acme-corp',
    secret: SECRET,
  })

  const res = verifyTenantToken(token, 'different-secret-key-32-chars-long-67890')
  assert.equal(res.valid, false)
  if (!res.valid) {
    assert.match(res.error, /signature/i)
  }
})

test('token validator: rejects malformed or missing token', () => {
  assert.equal(verifyTenantToken(null, SECRET).valid, false)
  assert.equal(verifyTenantToken('', SECRET).valid, false)
  assert.equal(verifyTenantToken('not-a-token', SECRET).valid, false)
  assert.equal(verifyTenantToken('a.b', SECRET).valid, false)
})
