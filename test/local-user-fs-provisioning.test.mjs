// Provisioning regression tests for LocalUserFs (Fase 4).
// Focus: (1) settings.yaml is never copied from the Admin template;
// (2) a virtual-model settings.yaml is written instead;
// (3) model-mask is injected into cordis.patch.yml (idempotent).
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { lstatSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync, existsSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { LocalUserFs } from '../lib/fs/local-user-fs.js'

const USER = 'u1'
const TARGET_VERSION = 1

function makeUser(t) {
  const dataRoot = mkdtempSync(join(tmpdir(), 'dsh-lufs-prov-'))
  t.after(() => rmSync(dataRoot, { recursive: true, force: true }))
  return { fs: new LocalUserFs((id) => join(dataRoot, 'users', id)), dataRoot }
}

/** Create an Admin-style template profile with a real settings.yaml and cordis.patch.yml. */
function makeTemplate(dataRoot) {
  const template = join(dataRoot, 'template-profile')
  mkdirSync(join(template, 'profiles', 'web', 'node_modules'), { recursive: true })
  writeFileSync(
    join(template, 'profiles', 'web', 'settings.yaml'),
    'llm:\n  providers:\n    - id: deepseek\n      models:\n        - id: deepseek-chat\n  default: deepseek-chat\n',
  )
  writeFileSync(join(template, 'profiles', 'web', 'cordis.patch.yml'), '- insert:\n    - id: existing-row\n')
  writeFileSync(join(template, 'package.json'), JSON.stringify({ dsh: { profile: { bundles: [] } } }))
  return join(template, 'profiles', 'web')
}

test('initUserRoot does not copy Admin settings.yaml; writes virtual-model settings.yaml instead', async (t) => {
  const { fs, dataRoot } = makeUser(t)
  const templateProfile = makeTemplate(dataRoot)

  // Point the resolver at the template root so initUserRoot finds it.
  const provFs = new LocalUserFs((id) => join(dataRoot, 'users', id))
  await provFs.initUserRoot(USER, undefined, 'https://u1.app.copymonster.co')

  const userProfile = join(dataRoot, 'users', USER, 'home', 'profiles', 'web')
  const settingsYaml = join(userProfile, 'settings.yaml')

  // Admin settings.yaml must NOT be present as copied from the template.
  const templateSettings = join(templateProfile, 'settings.yaml')
  assert.ok(existsSync(templateSettings), 'template has settings.yaml')
  assert.ok(existsSync(settingsYaml), 'tenant settings.yaml was written')

  const content = readFileSync(settingsYaml, 'utf8')
  assert.ok(content.includes('copy-monster-default'), 'settings.yaml advertises virtual model id')
  assert.ok(content.includes('Model CopyMonster'), 'settings.yaml advertises virtual model name')
  assert.ok(!content.includes('deepseek-chat'), 'settings.yaml does not leak real Admin model')

  // node_modules from template must NOT be copied (existing behavior): it is
  // shared via symlink, not a real directory copy.
  const nm = join(userProfile, 'node_modules')
  assert.ok(existsSync(nm), 'node_modules symlink exists')
  assert.ok(
    lstatSync(nm).isSymbolicLink(),
    'node_modules is a symlink (shared, not copied)',
  )
})

test('initUserRoot injects model-mask row into cordis.patch.yml (idempotent)', async (t) => {
  const { fs, dataRoot } = makeUser(t)
  const templateProfile = makeTemplate(dataRoot)

  const provFs = new LocalUserFs((id) => join(dataRoot, 'users', id))
  await provFs.initUserRoot(USER, undefined, 'https://u1.app.copymonster.co')

  const userProfile = join(dataRoot, 'users', USER, 'home', 'profiles', 'web')
  const patchPath = join(userProfile, 'cordis.patch.yml')
  const content = readFileSync(patchPath, 'utf8')

  assert.ok(content.includes('- id: model-mask'), 'model-mask row present')
  assert.ok(content.includes('name: "@deepseek-ai/dsh-host-model-mask"'), 'model-mask bundle named')
  assert.ok(content.includes('virtualModel: copy-monster-default'), 'virtual model id configured')
  assert.ok(content.includes('virtualModelName: Model CopyMonster'), 'virtual model name configured')
  assert.ok(content.includes('applyToTenantsOnly: true'), 'applyToTenantsOnly set')

  // Second call must be idempotent: only one model-mask row.
  await provFs.initUserRoot(USER, undefined, 'https://u1.app.copymonster.co')
  const content2 = readFileSync(patchPath, 'utf8')
  const maskCount = (content2.match(/- id: model-mask/g) ?? []).length
  assert.equal(maskCount, 1, 'model-mask row is idempotent (exactly one)')
})

test('initUserRoot updates existing model-mask row when stale', async (t) => {
  const { fs, dataRoot } = makeUser(t)
  const templateProfile = makeTemplate(dataRoot)

  // Pre-seed a stale model-mask row with wrong config.
  const patchPath = join(templateProfile, 'cordis.patch.yml')
  const stale = [
    '- insert:',
    '    - id: model-mask',
    '      name: "@deepseek-ai/dsh-host-model-mask"',
    '      config:',
    '        virtualModel: old-model',
    '',
  ].join('\n')
  writeFileSync(patchPath, stale)

  const provFs = new LocalUserFs((id) => join(dataRoot, 'users', id))
  await provFs.initUserRoot(USER, undefined, 'https://u1.app.copymonster.co')

  const userProfile = join(dataRoot, 'users', USER, 'home', 'profiles', 'web')
  const content = readFileSync(join(userProfile, 'cordis.patch.yml'), 'utf8')
  assert.ok(content.includes('virtualModel: copy-monster-default'), 'stale model-mask row updated')
  assert.ok(!content.includes('virtualModel: old-model'), 'stale value replaced')
})

test('initUserRoot creates tenant root even when no template exists', async (t) => {
  const { fs, dataRoot } = makeUser(t)
  await fs.initUserRoot(USER, undefined, 'https://u1.app.copymonster.co')

  const userRoot = join(dataRoot, 'users', USER)
  assert.ok(existsSync(join(userRoot, 'home')), 'home created')
  assert.ok(existsSync(join(userRoot, 'ws')), 'workspace created')
})
