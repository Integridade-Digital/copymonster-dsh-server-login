import test from 'node:test'
import assert from 'node:assert/strict'
import { staleScopeUnits, tenantScopeStem } from '../lib/supervisor/orchestrator.js'

test('tenantScopeStem: names the tenant and role in a systemd-safe stem', () => {
  assert.equal(tenantScopeStem('abc-123', 'main'), 'copymonster-main-abc-123')
  assert.equal(tenantScopeStem('user/with/slashes', 'watchdog'), 'copymonster-watchdog-user-with-slashes')
})

test('staleScopeUnits: matches the retired unsuffixed name and unique successors', () => {
  const stem = tenantScopeStem('abc-123', 'main')
  const entries = [
    'copymonster-main-abc-123.scope',
    'copymonster-main-abc-123-3f2a1b.scope',
    'copymonster-main-other.scope',
    'copymonster-watchdog-abc-123-3f2a1b.scope',
    'copymonster-main-abc-123.conf',
    'copymonster.service',
  ]
  assert.deepEqual(staleScopeUnits(entries, stem), [
    'copymonster-main-abc-123.scope',
    'copymonster-main-abc-123-3f2a1b.scope',
  ])
})

test('staleScopeUnits: a prefix that is only a name prefix does not match', () => {
  const stem = tenantScopeStem('abc', 'main')
  assert.deepEqual(staleScopeUnits(['copymonster-main-abcd-x.scope'], stem), [])
})
