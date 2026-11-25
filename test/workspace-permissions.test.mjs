// M-10: a tenant's workspace tree is owner-only after handover, so a co-tenant
// or another local user cannot read it.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdirSync, mkdtempSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { grantUserRootPermissions } from '../lib/fs/workspace.js'

test('M-10: handover removes group and other permission bits recursively', (t) => {
  const root = mkdtempSync(join(tmpdir(), 'dsh-workspace-'))
  t.after(() => rmSync(root, { recursive: true, force: true }))

  const nested = join(root, 'home', 'workspace', 'deep')
  mkdirSync(nested, { recursive: true, mode: 0o755 })
  const file = join(nested, 'secret.txt')
  writeFileSync(file, 'tenant data', { mode: 0o644 })

  grantUserRootPermissions(root, process.getuid())

  for (const path of [root, join(root, 'home'), join(root, 'home', 'workspace'), nested, file]) {
    const mode = statSync(path).mode & 0o777
    assert.equal(mode & 0o077, 0, `${path} still exposes group/other bits (${mode.toString(8)})`)
  }
  // The owner keeps read/write access.
  assert.ok((statSync(file).mode & 0o777) & 0o600)
})
