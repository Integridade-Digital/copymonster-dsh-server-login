// Provisioning regression tests for the MCP bundle backfill (Fase 4).
// Focus: every MCP bundle (zernio, sendpulse, leadlovers, kiwify) reaches the
// tenant profile's `dsh.profile.bundles`, a resolvable @deepseek-ai link, and a
// cordis.patch.yml row pinned to the tenant's public origin — including for a
// profile copied before the template gained the bundles.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { LocalUserFs } from '../lib/fs/local-user-fs.js'

const USER = 'u1'
const ORIGIN = 'https://u1.app.copymonster.co'

const MCP_BUNDLES = [
  '@deepseek-ai/dsh-experimental-zernio-mcp',
  '@deepseek-ai/dsh-experimental-sendpulse-mcp',
  '@deepseek-ai/dsh-experimental-leadlovers-mcp',
  '@deepseek-ai/dsh-experimental-kiwify-mcp',
]

const ROW_IDS = ['zernio-mcp', 'sendpulse-mcp', 'leadlovers-mcp', 'kiwify-mcp']

function makeUser(t) {
  const dataRoot = mkdtempSync(join(tmpdir(), 'dsh-lufs-mcp-'))
  t.after(() => rmSync(dataRoot, { recursive: true, force: true }))
  // Pin the template so a profile installed on the control-plane host cannot
  // shadow the one this test builds.
  const previous = process.env.DSH_SERVER_LOGIN_TEMPLATE_PROFILE
  process.env.DSH_SERVER_LOGIN_TEMPLATE_PROFILE = join(dataRoot, 'template-profile', 'profiles', 'web')
  t.after(() => {
    if (previous === undefined) delete process.env.DSH_SERVER_LOGIN_TEMPLATE_PROFILE
    else process.env.DSH_SERVER_LOGIN_TEMPLATE_PROFILE = previous
  })
  return { dataRoot }
}

/**
 * Create a template profile in the shape a tenant is copied from. `modules`
 * decides whether the template's node_modules can satisfy the bundle links.
 */
function makeTemplate(dataRoot, { modules }) {
  const profile = join(dataRoot, 'template-profile', 'profiles', 'web')
  mkdirSync(join(profile, 'node_modules'), { recursive: true })
  writeFileSync(join(profile, 'cordis.patch.yml'), '- id: locale\n  name: "@deepseek-ai/dsh-client-locale"\n')
  writeFileSync(
    join(profile, 'package.json'),
    JSON.stringify({ dsh: { profile: { bundles: ['@deepseek-ai/dsh-base', '@deepseek-ai/dsh-web-app'] } } }),
  )
  if (modules) {
    for (const bundle of MCP_BUNDLES) {
      const dir = join(profile, 'node_modules', '@deepseek-ai', bundle)
      mkdirSync(dir, { recursive: true })
      writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: bundle, type: 'module' }))
    }
  }
  return profile
}

function readBundles(profile) {
  return JSON.parse(readFileSync(join(profile, 'package.json'), 'utf8')).dsh.profile.bundles
}

function assertAllMcpBundles(profile) {
  const bundles = readBundles(profile)
  for (const bundle of MCP_BUNDLES) {
    assert.ok(bundles.includes(bundle), `${bundle} is in dsh.profile.bundles`)
  }
  // The MCP layers sit between the Web app layer and the rest of the roster, so
  // they apply after `dsh-base`/`dsh-web-app`.
  const webAppIdx = bundles.indexOf('@deepseek-ai/dsh-web-app')
  assert.ok(webAppIdx !== -1)
  for (const bundle of MCP_BUNDLES) {
    assert.ok(bundles.indexOf(bundle) > webAppIdx, `${bundle} applies after the Web app layer`)
  }
}

function assertAllMcpRows(profile) {
  const patch = readFileSync(join(profile, 'cordis.patch.yml'), 'utf8')
  for (const rowId of ROW_IDS) {
    const rows = (patch.match(new RegExp(`- id: ${rowId}$`, 'gm')) ?? []).length
    assert.equal(rows, 1, `exactly one ${rowId} row`)
    const rowStart = patch.indexOf(`- id: ${rowId}\n`)
    assert.ok(rowStart !== -1)
    const nextRow = patch.indexOf('\n- ', rowStart + 1)
    const row = patch.slice(rowStart, nextRow === -1 ? undefined : nextRow)
    assert.ok(row.includes(`name: "@deepseek-ai/dsh-experimental-${rowId}"`), `${rowId} row mounts its bundle`)
    assert.ok(row.includes(`publicOrigin: ${ORIGIN}`), `${rowId} row pins the tenant origin`)
  }
}

function assertAllMcpLinks(profile) {
  for (const bundle of MCP_BUNDLES) {
    assert.ok(existsSync(join(profile, 'node_modules', '@deepseek-ai', bundle)), `${bundle} is linked into node_modules`)
  }
}

test('first provisioning mounts every MCP bundle with its origin row and link', async (t) => {
  const { dataRoot } = makeUser(t)
  const template = makeTemplate(dataRoot, { modules: true })
  const fs = new LocalUserFs((id) => join(dataRoot, 'users', id))

  await fs.initUserRoot(USER, undefined, ORIGIN)

  const profile = join(dataRoot, 'users', USER, 'home', 'profiles', 'web')
  assertAllMcpBundles(profile)
  assertAllMcpRows(profile)
  assertAllMcpLinks(profile)
  assert.equal(
    realpathSync(join(profile, 'node_modules', '@deepseek-ai', MCP_BUNDLES[0])),
    realpathSync(join(template, 'node_modules', '@deepseek-ai', MCP_BUNDLES[0])),
    'links reuse the template package',
  )
})

test('a profile copied before the MCP bundles existed is backfilled on relaunch', async (t) => {
  const { dataRoot } = makeUser(t)
  makeTemplate(dataRoot, { modules: true })
  const fs = new LocalUserFs((id) => join(dataRoot, 'users', id))

  await fs.initUserRoot(USER, undefined, ORIGIN)
  const profile = join(dataRoot, 'users', USER, 'home', 'profiles', 'web')
  assertAllMcpBundles(profile)

  // Simulate an older profile: the roster and rows predate the MCP bundles.
  writeFileSync(
    join(profile, 'package.json'),
    JSON.stringify({ dsh: { profile: { bundles: ['@deepseek-ai/dsh-base', '@deepseek-ai/dsh-web-app'] } } }),
  )
  writeFileSync(join(profile, 'cordis.patch.yml'), '- id: locale\n  name: "@deepseek-ai/dsh-client-locale"\n')

  await fs.initUserRoot(USER, undefined, ORIGIN)

  assertAllMcpBundles(profile)
  assertAllMcpRows(profile)
  assertAllMcpLinks(profile)
})

test('MCP rows are idempotent and their origin follows the tenant origin', async (t) => {
  const { dataRoot } = makeUser(t)
  makeTemplate(dataRoot, { modules: true })
  const fs = new LocalUserFs((id) => join(dataRoot, 'users', id))

  await fs.initUserRoot(USER, undefined, ORIGIN)
  const profile = join(dataRoot, 'users', USER, 'home', 'profiles', 'web')
  const first = readFileSync(join(profile, 'cordis.patch.yml'), 'utf8')

  await fs.initUserRoot(USER, undefined, ORIGIN)
  assert.equal(
    readFileSync(join(profile, 'cordis.patch.yml'), 'utf8'),
    first,
    'a second launch leaves the patch unchanged',
  )
  for (const bundle of MCP_BUNDLES) {
    const entries = readBundles(profile).filter((entry) => entry === bundle).length
    assert.equal(entries, 1, `${bundle} appears once`)
  }

  await fs.initUserRoot(USER, undefined, 'https://u1.other.example')
  const patch = readFileSync(join(profile, 'cordis.patch.yml'), 'utf8')
  assert.ok(!patch.includes(ORIGIN), 'stale origins are replaced')
  assert.equal((patch.match(/publicOrigin: https:\/\/u1\.other\.example/g) ?? []).length, 4)
})

test('rows already present under an insert block are updated, not duplicated', async (t) => {
  const { dataRoot } = makeUser(t)
  const template = makeTemplate(dataRoot, { modules: true })
  // The bundle layer's own patch inserts rows two spaces deeper.
  writeFileSync(
    join(template, 'cordis.patch.yml'),
    [
      '- insert:',
      '    - id: zernio-mcp',
      '      name: "@deepseek-ai/dsh-experimental-zernio-mcp"',
      '      config:',
      '        announceToAgent: true',
      '',
    ].join('\n'),
  )
  const fs = new LocalUserFs((id) => join(dataRoot, 'users', id))

  await fs.initUserRoot(USER, undefined, ORIGIN)

  const profile = join(dataRoot, 'users', USER, 'home', 'profiles', 'web')
  const patch = readFileSync(join(profile, 'cordis.patch.yml'), 'utf8')
  const rows = (patch.match(/- id: zernio-mcp$/gm) ?? []).length
  assert.equal(rows, 1, 'the nested zernio row is reused')
  assert.ok(patch.includes(`      publicOrigin: ${ORIGIN}`), 'the nested row keeps its indentation')
  assert.ok(patch.includes('announceToAgent: true'), 'existing row config survives')
})

test('a tenant profile with no node_modules directory gets the links from the template tree', async (t) => {
  const { dataRoot } = makeUser(t)
  makeTemplate(dataRoot, { modules: true })
  const fs = new LocalUserFs((id) => join(dataRoot, 'users', id))

  await fs.initUserRoot(USER, undefined, ORIGIN)

  // Drop the shared tree, as a tenant whose profile was copied without one.
  const profile = join(dataRoot, 'users', USER, 'home', 'profiles', 'web')
  const shared = join(profile, 'node_modules')
  assert.ok(lstatSync(shared).isSymbolicLink(), 'the first launch shares the template tree')
  rmSync(shared, { recursive: true, force: true })

  await fs.initUserRoot(USER, undefined, ORIGIN)

  assert.ok(lstatSync(shared).isSymbolicLink(), 'the tree is shared again')
  assertAllMcpBundles(profile)
  assertAllMcpRows(profile)
  assertAllMcpLinks(profile)
})

test('an empty tenant node_modules directory is replaced by the shared tree', async (t) => {
  const { dataRoot } = makeUser(t)
  makeTemplate(dataRoot, { modules: true })
  const fs = new LocalUserFs((id) => join(dataRoot, 'users', id))
  await fs.initUserRoot(USER, undefined, ORIGIN)

  const profile = join(dataRoot, 'users', USER, 'home', 'profiles', 'web')
  const shared = join(profile, 'node_modules')
  rmSync(shared, { recursive: true, force: true })
  mkdirSync(shared)

  await fs.initUserRoot(USER, undefined, ORIGIN)

  assert.ok(lstatSync(shared).isSymbolicLink(), 'the empty directory no longer shadows the template tree')
  assertAllMcpLinks(profile)
})

test('a bundle the template does not provide is reported instead of silently skipped', async (t) => {
  const { dataRoot } = makeUser(t)
  const template = makeTemplate(dataRoot, { modules: true })
  // A template installed before one bundle shipped still has the others.
  rmSync(join(template, 'node_modules', '@deepseek-ai', MCP_BUNDLES[3]), { recursive: true, force: true })
  const fs = new LocalUserFs((id) => join(dataRoot, 'users', id))

  const warnings = []
  const originalWarn = console.warn
  console.warn = (message) => warnings.push(String(message))
  t.after(() => { console.warn = originalWarn })

  await fs.initUserRoot(USER, undefined, ORIGIN)

  const profile = join(dataRoot, 'users', USER, 'home', 'profiles', 'web')
  assert.ok(warnings.some((line) => line.includes(`resolve ${MCP_BUNDLES[3]} package`)), 'the missing package is logged')
  assert.ok(existsSync(join(profile, 'node_modules', '@deepseek-ai', MCP_BUNDLES[0])), 'the others are still linked')
})

test('without a public origin the bundles and links still mount', async (t) => {
  const { dataRoot } = makeUser(t)
  makeTemplate(dataRoot, { modules: true })
  const fs = new LocalUserFs((id) => join(dataRoot, 'users', id))

  await fs.initUserRoot(USER)

  const profile = join(dataRoot, 'users', USER, 'home', 'profiles', 'web')
  assertAllMcpBundles(profile)
  assertAllMcpLinks(profile)
  assert.ok(
    !readFileSync(join(profile, 'cordis.patch.yml'), 'utf8').includes('publicOrigin:'),
    'no origin is invented for a tenant without a subdomain',
  )
})
