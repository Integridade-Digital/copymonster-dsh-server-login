// Workspace sandbox handover tests (node:test, against built lib/).
//
// The tenant's Workspace sandbox lives outside its per-user root, so the
// control plane must hand `<dataRoot>/<tenantId>/<userId>/workspaces` to the
// tenant's own uid. Without it the tenant's `mkdir` fails EACCES and every
// Workspace pick leaves the composer inert.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdirSync, mkdtempSync, rmSync, statSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { grantUserSandboxPermissions } from '../lib/fs/workspace.js'

const USER = 'user-1'
const TENANT = 'tenant-1'

function makeDataRoot(t) {
  const dataRoot = mkdtempSync(join(tmpdir(), 'dsh-sandbox-'))
  t.after(() => rmSync(dataRoot, { recursive: true, force: true }))
  return dataRoot
}

test('grantUserSandboxPermissions: creates the sandbox for every tenant holding this user', (t) => {
  const dataRoot = makeDataRoot(t)
  mkdirSync(join(dataRoot, TENANT, USER), { recursive: true })
  // A tenant without this user's directory is skipped, not created.
  mkdirSync(join(dataRoot, 'tenant-2'), { recursive: true })

  grantUserSandboxPermissions(dataRoot, USER, process.getuid())

  const sandbox = join(dataRoot, TENANT, USER, 'workspaces')
  assert.ok(statSync(sandbox).isDirectory())
  assert.equal(statSync(sandbox).uid, process.getuid())
  assert.equal(statSync(sandbox).mode & 0o777, 0o700)
  assert.throws(() => statSync(join(dataRoot, 'tenant-2', USER)), { code: 'ENOENT' })
})

test('grantUserSandboxPermissions: an existing sandbox keeps its contents', (t) => {
  const dataRoot = makeDataRoot(t)
  const sandbox = join(dataRoot, TENANT, USER, 'workspaces')
  mkdirSync(join(sandbox, 'default'), { recursive: true })

  grantUserSandboxPermissions(dataRoot, USER, process.getuid())

  assert.ok(statSync(join(sandbox, 'default')).isDirectory())
})

test('grantUserSandboxPermissions: a missing data root is not created', (t) => {
  const dataRoot = join(makeDataRoot(t), 'absent')
  grantUserSandboxPermissions(dataRoot, USER, process.getuid())
  assert.throws(() => statSync(dataRoot), { code: 'ENOENT' })
})
