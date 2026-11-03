import test from 'node:test'
import assert from 'node:assert/strict'
import { existsSync } from 'node:fs'
import { resolveBinary } from '../lib/supervisor/spawn.js'

test('resolveBinary falls back to basename when configured absolute path is missing', () => {
  if (!existsSync('/bin/setpriv')) return
  assert.equal(resolveBinary('/usr/bin/setpriv', '/usr/bin:/bin'), '/bin/setpriv')
})

test('resolveBinary resolves absolute binaries unchanged when they exist', () => {
  if (!existsSync('/bin/sh')) return
  assert.equal(resolveBinary('/bin/sh', '/usr/bin:/bin'), '/bin/sh')
})

test('resolveBinary resolves names from standard system directories', () => {
  if (!existsSync('/bin/sh')) return
  assert.equal(resolveBinary('sh', ''), '/bin/sh')
})
