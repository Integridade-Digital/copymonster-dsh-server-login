// Per-account login lockout: guessing costs progressively more regardless of the
// source address, and a legitimate user recovers after the window (SEC-017).
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { LoginThrottle, LOGIN_FREE_ATTEMPTS, LOGIN_MAX_DELAY_MS } from '../lib/web/middleware/login-throttle.js'

function clock(start = 1_000_000) {
  let now = start
  return { now: () => now, advance: (ms) => { now += ms } }
}

test('throttle: the free allowance costs nothing', () => {
  const c = clock()
  const throttle = new LoginThrottle({ now: c.now })
  for (let i = 0; i < LOGIN_FREE_ATTEMPTS; i += 1) throttle.recordFailure('alice')
  assert.equal(throttle.check('alice').allowed, true)
})

test('throttle: the next failure blocks the account immediately', () => {
  const c = clock()
  const throttle = new LoginThrottle({ now: c.now })
  for (let i = 0; i < LOGIN_FREE_ATTEMPTS; i += 1) throttle.recordFailure('alice')

  const { strikes, delayMs } = throttle.recordFailure('alice')
  assert.equal(strikes, LOGIN_FREE_ATTEMPTS + 1)
  assert.ok(delayMs > 0)

  const decision = throttle.check('alice')
  assert.equal(decision.allowed, false)
  assert.ok(decision.retryAfterMs > 0)
  assert.equal(decision.retryAfterMs, delayMs)
})

test('throttle: the wait grows with each further failure and is capped', () => {
  const c = clock()
  const throttle = new LoginThrottle({ now: c.now })
  const delays = []
  for (let i = 0; i < LOGIN_FREE_ATTEMPTS + 12; i += 1) {
    delays.push(throttle.recordFailure('alice').delayMs)
  }
  const penalised = delays.slice(LOGIN_FREE_ATTEMPTS)
  for (let i = 1; i < penalised.length; i += 1) {
    assert.ok(penalised[i] >= penalised[i - 1], `delay ${i} should not shrink`)
  }
  assert.ok(penalised.some((d) => d > penalised[0]))
  assert.ok(Math.max(...penalised) <= LOGIN_MAX_DELAY_MS)
})

test('throttle: a forged forwarding address cannot dodge the account limit', () => {
  const c = clock()
  const throttle = new LoginThrottle({ now: c.now })
  // The tracker keys on the account only, so changing the network path changes
  // nothing: ten failures from one address block the same account elsewhere.
  for (let i = 0; i < LOGIN_FREE_ATTEMPTS; i += 1) throttle.recordFailure('alice')
  throttle.recordFailure('alice')
  assert.equal(throttle.check('alice').allowed, false)
  // A different account is unaffected.
  assert.equal(throttle.check('bob').allowed, true)
})

test('throttle: the account recovers once the wait elapses', () => {
  const c = clock()
  const throttle = new LoginThrottle({ now: c.now })
  for (let i = 0; i < LOGIN_FREE_ATTEMPTS + 1; i += 1) throttle.recordFailure('alice')
  assert.equal(throttle.check('alice').allowed, false)

  c.advance(5_000)
  assert.equal(throttle.check('alice').allowed, true)
})

test('throttle: a successful login clears the strikes', () => {
  const c = clock()
  const throttle = new LoginThrottle({ now: c.now })
  for (let i = 0; i < LOGIN_FREE_ATTEMPTS + 1; i += 1) throttle.recordFailure('alice')
  throttle.recordSuccess('alice')
  assert.equal(throttle.strikesFor('alice'), 0)
  assert.equal(throttle.check('alice').allowed, true)
})

test('throttle: an idle account is forgotten after the reset window', () => {
  const c = clock()
  const throttle = new LoginThrottle({ now: c.now, resetAfterMs: 60_000 })
  for (let i = 0; i < LOGIN_FREE_ATTEMPTS + 1; i += 1) throttle.recordFailure('alice')
  c.advance(60_001)
  assert.equal(throttle.strikesFor('alice'), 0)
})

test('throttle: the account handle is matched case-insensitively', () => {
  const c = clock()
  const throttle = new LoginThrottle({ now: c.now })
  for (let i = 0; i < LOGIN_FREE_ATTEMPTS + 1; i += 1) throttle.recordFailure('Alice')
  assert.equal(throttle.check('ALICE').allowed, false)
})
