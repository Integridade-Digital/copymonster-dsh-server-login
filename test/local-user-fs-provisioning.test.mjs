// Provisioning regression tests for LocalUserFs (Fase 4).
// Focus: (1) settings.yaml is never copied from the Admin template;
// (2) the tenant document selects the virtual CopyMonster alias;
// (3) model-mask and agent-default-model rows are enforced on every launch,
//     including for profiles provisioned before the platform route changed.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { lstatSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync, existsSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { LocalUserFs } from '../lib/fs/local-user-fs.js'
import { loadPlatformRouting } from '../lib/supervisor/platform-routing.js'
import { createHmac } from 'node:crypto'

const USER = 'u1'

function makeUser(t) {
  const dataRoot = mkdtempSync(join(tmpdir(), 'dsh-lufs-prov-'))
  t.after(() => rmSync(dataRoot, { recursive: true, force: true }))
  return { fs: new LocalUserFs((id) => join(dataRoot, 'users', id)), dataRoot }
}

/** Point provisioning at a test template for the duration of one test. */
function useTemplate(t, templateProfile) {
  const previous = process.env.DSH_SERVER_LOGIN_TEMPLATE_PROFILE
  process.env.DSH_SERVER_LOGIN_TEMPLATE_PROFILE = templateProfile
  t.after(() => {
    if (previous === undefined) delete process.env.DSH_SERVER_LOGIN_TEMPLATE_PROFILE
    else process.env.DSH_SERVER_LOGIN_TEMPLATE_PROFILE = previous
  })
}

/** Create an Admin-style template profile with a real settings.yaml and cordis.patch.yml. */
function makeTemplate(dataRoot) {
  const template = join(dataRoot, 'template-profile')
  mkdirSync(join(template, 'profiles', 'web', 'node_modules'), { recursive: true })
  writeFileSync(
    join(template, 'profiles', 'web', 'settings.yaml'),
    'agent-default-model:\n  provider: tokenharbor\n  model: deepseek-v4.1-flash:free\n',
  )
  writeFileSync(
    join(template, 'profiles', 'web', 'cordis.patch.yml'),
    [
      '- insert:',
      '    - id: existing-row',
      '      name: "@deepseek-ai/dsh-example"',
      '- id: llm-pi-ai',
      '  name: "@deepseek-ai/dsh-llm-pi-ai"',
      '  config:',
      '    providers:',
      '      closed:',
      '        apiKeyEnv: CLOSED_API_KEY',
      '        baseURL: https://closed.example/v1',
      '        models:',
      '          - id: only-model',
      '            name: Only Model',
      '      openrouter:',
      '        baseURL: https://openrouter.ai/api/v1',
      '        models:',
      '          - id: openrouter/free',
      '            name: Free Models Openrouter',
      '        apiKeyEnv: OPENROUTER_API_KEY',
      '- id: agent-default-model',
      '  name: "@deepseek-ai/dsh-agent-default-model"',
      '  config:',
      '    provider: tokenharbor',
      '    model: deepseek-v4.1-flash:free',
      '',
    ].join('\n'),
  )
  writeFileSync(join(template, 'package.json'), JSON.stringify({ dsh: { profile: { bundles: [] } } }))
  return join(template, 'profiles', 'web')
}

function tenantProfile(dataRoot) {
  return join(dataRoot, 'users', USER, 'home', 'profiles', 'web')
}

test('initUserRoot does not copy Admin settings.yaml; writes the virtual alias instead', async (t) => {
  const { dataRoot } = makeUser(t)
  const templateProfile = makeTemplate(dataRoot)
  useTemplate(t, templateProfile)
  const provFs = new LocalUserFs((id) => join(dataRoot, 'users', id))
  await provFs.initUserRoot(USER, undefined, 'https://u1.app.copymonster.co')

  const userProfile = tenantProfile(dataRoot)
  const settingsYaml = join(userProfile, 'settings.yaml')

  assert.ok(existsSync(join(templateProfile, 'settings.yaml')), 'template has settings.yaml')
  assert.ok(existsSync(settingsYaml), 'tenant settings.yaml was written')

  const content = readFileSync(settingsYaml, 'utf8')
  assert.match(content, /agent-default-model:\n  provider: copymonster\n  model: copy-monster-default\n/)
  assert.ok(!content.includes('tokenharbor'), 'settings.yaml does not keep the Admin provider')
  assert.ok(!content.includes('llm-pi-ai'), 'settings.yaml declares no real provider routes')

  const nm = join(userProfile, 'node_modules')
  assert.ok(existsSync(nm), 'node_modules symlink exists')
  assert.ok(lstatSync(nm).isSymbolicLink(), 'node_modules is a symlink (shared, not copied)')
})

test('initUserRoot pins agent-default-model to the virtual alias on every launch', async (t) => {
  const { dataRoot } = makeUser(t)
  const templateProfile = makeTemplate(dataRoot)
  useTemplate(t, templateProfile)
  const provFs = new LocalUserFs((id) => join(dataRoot, 'users', id))
  await provFs.initUserRoot(USER, undefined, 'https://u1.app.copymonster.co')

  const patchPath = join(tenantProfile(dataRoot), 'cordis.patch.yml')
  const first = readFileSync(patchPath, 'utf8')
  const row = /- id: agent-default-model\n(?:.*\n)*?    model: ([^\n]+)/
  assert.match(first, /- id: agent-default-model\n  name: "@deepseek-ai\/dsh-agent-default-model"\n  config:\n    provider: copymonster\n    model: copy-monster-default\n/)
  assert.ok(!first.includes('provider: tokenharbor'), 'stale Admin selection replaced')
  assert.equal((first.match(/- id: agent-default-model/g) ?? []).length, 1, 'exactly one default-model row')
  assert.ok(row.test(first), 'row keeps its model key')

  await provFs.initUserRoot(USER, undefined, 'https://u1.app.copymonster.co')
  const second = readFileSync(patchPath, 'utf8')
  assert.equal(second, first, 'second launch rewrites the same bytes')
})

test('initUserRoot injects the model-mask row with the configured platform route', async (t) => {
  const { dataRoot } = makeUser(t)
  const templateProfile = makeTemplate(dataRoot)
  useTemplate(t, templateProfile)
  const previous = process.env.DSH_SERVER_LOGIN_LLM_PRIMARY_MODEL
  process.env.DSH_SERVER_LOGIN_LLM_PRIMARY_MODEL = 'deepseek/deepseek-chat'
  t.after(() => {
    if (previous === undefined) delete process.env.DSH_SERVER_LOGIN_LLM_PRIMARY_MODEL
    else process.env.DSH_SERVER_LOGIN_LLM_PRIMARY_MODEL = previous
  })

  const provFs = new LocalUserFs((id) => join(dataRoot, 'users', id))
  await provFs.initUserRoot(USER, undefined, 'https://u1.app.copymonster.co')

  const patchPath = join(tenantProfile(dataRoot), 'cordis.patch.yml')
  const content = readFileSync(patchPath, 'utf8')

  assert.ok(content.includes('- id: model-mask'), 'model-mask row present')
  assert.ok(content.includes('name: "@deepseek-ai/dsh-host-model-mask"'), 'model-mask bundle named')
  assert.ok(content.includes('virtualModel: copy-monster-default'), 'virtual model id configured')
  assert.ok(content.includes('virtualModelName: Model CopyMonster'), 'virtual model name configured')
  assert.ok(content.includes('applyToTenantsOnly: true'), 'applyToTenantsOnly set')
  assert.match(content, /primaryProvider: openrouter\n    primaryModel: deepseek\/deepseek-chat/)
  assert.match(content, /fallbackProvider: openrouter\n    fallbackModel: openrouter\/free/)
  assert.ok(!content.includes('deepseek-official'), 'the revoked platform route is not configured')

  await provFs.initUserRoot(USER, undefined, 'https://u1.app.copymonster.co')
  const second = readFileSync(patchPath, 'utf8')
  assert.equal((second.match(/- id: model-mask/g) ?? []).length, 1, 'model-mask row is idempotent')
})

test('initUserRoot declares the platform route model on the provider that serves it', async (t) => {
  const { dataRoot } = makeUser(t)
  const templateProfile = makeTemplate(dataRoot)
  useTemplate(t, templateProfile)
  const provFs = new LocalUserFs((id) => join(dataRoot, 'users', id))
  await provFs.initUserRoot(USER, undefined, 'https://u1.app.copymonster.co')

  const patchPath = join(tenantProfile(dataRoot), 'cordis.patch.yml')
  const content = readFileSync(patchPath, 'utf8')

  // An explicit `models` list serves exactly that list, so the dispatch route
  // must be advertised or the tenant turn fails as UNKNOWN_MODEL.
  assert.match(content, /models:\n(?:\s+- id: .*\n\s+name: .*\n)*\s+- id: "deepseek\/deepseek-chat"\n\s+name: "deepseek\/deepseek-chat"/)
  assert.match(content, /- id: openrouter\/free/, 'the existing entry is kept')
  assert.doesNotMatch(content, /- id: "deepseek\/deepseek-chat"\n\s+name: "deepseek\/deepseek-chat"\n\s+- id: only-model/, 'inserted inside the openrouter list')

  await provFs.initUserRoot(USER, undefined, 'https://u1.app.copymonster.co')
  const second = readFileSync(patchPath, 'utf8')
  assert.equal((second.match(/- id: "deepseek\/deepseek-chat"/g) ?? []).length, 1, 'model listed once per launch')
})

test('initUserRoot copies the routing policy the operator configured in the template', async (t) => {
  const { dataRoot } = makeUser(t)
  const templateProfile = makeTemplate(dataRoot)
  useTemplate(t, templateProfile)
  // Settings → Models stores the platform routing in the template's own row.
  writeFileSync(
    join(templateProfile, 'cordis.patch.yml'),
    `${readFileSync(join(templateProfile, 'cordis.patch.yml'), 'utf8')}`
      + [
        '- id: model-mask',
        '  name: "@deepseek-ai/dsh-host-model-mask"',
        '  config:',
        '    primaryProvider: openrouter',
        '    primaryModel: openrouter/free',
        '    fallbackProvider: openrouter',
        '    fallbackModel: openrouter/free',
        '    fallbackPolicy:',
        '      enabled: false',
        '      maxAttempts: 4',
        '      timeoutMs: 12000',
        '    applyToTenantsOnly: true',
        '',
      ].join('\n'),
  )

  const provFs = new LocalUserFs((id) => join(dataRoot, 'users', id))
  await provFs.initUserRoot(USER, undefined, 'https://u1.app.copymonster.co')

  const content = readFileSync(join(tenantProfile(dataRoot), 'cordis.patch.yml'), 'utf8')
  assert.match(content, /primaryProvider: openrouter\n    primaryModel: openrouter\/free/)
  assert.match(content, /fallbackPolicy:\n      enabled: false\n      maxAttempts: 4\n      timeoutMs: 12000/)
  assert.ok(!content.includes('deepseek/deepseek-chat'), 'the default route does not override the operator policy')
})

test('initUserRoot leaves a provider without a models list untouched', async (t) => {
  const { dataRoot } = makeUser(t)
  const templateProfile = makeTemplate(dataRoot)
  useTemplate(t, templateProfile)
  const provFs = new LocalUserFs((id) => join(dataRoot, 'users', id))
  const previousProvider = process.env.DSH_SERVER_LOGIN_LLM_PRIMARY_PROVIDER
  const previousModel = process.env.DSH_SERVER_LOGIN_LLM_PRIMARY_MODEL
  process.env.DSH_SERVER_LOGIN_LLM_PRIMARY_PROVIDER = 'catalog'
  process.env.DSH_SERVER_LOGIN_LLM_PRIMARY_MODEL = 'catalog/model'
  t.after(() => {
    if (previousProvider === undefined) delete process.env.DSH_SERVER_LOGIN_LLM_PRIMARY_PROVIDER
    else process.env.DSH_SERVER_LOGIN_LLM_PRIMARY_PROVIDER = previousProvider
    if (previousModel === undefined) delete process.env.DSH_SERVER_LOGIN_LLM_PRIMARY_MODEL
    else process.env.DSH_SERVER_LOGIN_LLM_PRIMARY_MODEL = previousModel
  })

  const patchPath = join(tenantProfile(dataRoot), 'cordis.patch.yml')
  await provFs.initUserRoot(USER, undefined, 'https://u1.app.copymonster.co')

  // `catalog` has no profile in the template, so nothing can be inserted and the
  // launch still succeeds; only a route the profile owns gains an entry.
  const content = readFileSync(patchPath, 'utf8')
  assert.ok(content.includes('primaryProvider: catalog'), 'mask still points at the configured route')
  assert.ok(!content.includes('- id: "catalog/model"'), 'no entry invented for a route the profile lacks')
  assert.match(content, /- id: only-model/, 'the unrelated provider list is unchanged')
})

test('initUserRoot repairs a tenant profile provisioned with a stale provider', async (t) => {
  const { dataRoot } = makeUser(t)
  const templateProfile = makeTemplate(dataRoot)
  useTemplate(t, templateProfile)
  const provFs = new LocalUserFs((id) => join(dataRoot, 'users', id))
  await provFs.initUserRoot(USER, undefined, 'https://u1.app.copymonster.co')

  // Simulate a profile copied long ago: the old selection is back in both files.
  const userProfile = tenantProfile(dataRoot)
  const patchPath = join(userProfile, 'cordis.patch.yml')
  writeFileSync(patchPath, readFileSync(patchPath, 'utf8').replace(
    'provider: copymonster\n    model: copy-monster-default',
    'provider: tokenharbor\n    model: deepseek-v4.1-flash:free',
  ))
  writeFileSync(
    join(userProfile, 'settings.yaml'),
    'agent-default-model:\n  provider: tokenharbor\n  model: deepseek-v4.1-flash:free\n',
  )

  await provFs.initUserRoot(USER, undefined, 'https://u1.app.copymonster.co')

  assert.match(readFileSync(patchPath, 'utf8'), /provider: copymonster\n    model: copy-monster-default/)
  assert.doesNotMatch(readFileSync(patchPath, 'utf8'), /deepseek-v4\.1-flash:free/)
  assert.match(
    readFileSync(join(userProfile, 'settings.yaml'), 'utf8'),
    /agent-default-model:\n  provider: copymonster\n  model: copy-monster-default/,
  )
})

test('initUserRoot creates tenant root even when no template exists', async (t) => {
  const { fs, dataRoot } = makeUser(t)
  const missing = join(dataRoot, 'missing-template')
  useTemplate(t, missing)
  await fs.initUserRoot(USER, undefined, 'https://u1.app.copymonster.co')

  const userRoot = join(dataRoot, 'users', USER)
  assert.ok(existsSync(join(userRoot, 'home')), 'home created')
  assert.ok(existsSync(join(userRoot, 'ws')), 'workspace created')
})


test('central routing replaces a legacy profile on provisioning and applies to new tenants', async (t) => {
  const { dataRoot, fs } = makeUser(t)
  useTemplate(t, makeTemplate(dataRoot))
  await fs.initUserRoot(USER)
  const config = { mainAppUrl: 'http://main-app.test', sessionSecret: 'test-platform-routing-secret-only' }
  const fetchMock = t.mock.method(globalThis, 'fetch', async (url, options) => {
    assert.equal(String(url), 'http://main-app.test/api/internal/platform-model-routing')
    const issued = options.headers['x-dsh-routing-issued']
    assert.equal(options.headers['x-dsh-routing-signature'],
      createHmac('sha256', config.sessionSecret)
        .update(`GET /api/internal/platform-model-routing\n${issued}`).digest('hex'))
    return Response.json({ policy: {
      primaryProvider: 'deepseek',
      primaryModel: 'deepseek-v4.1-flash',
      fallbackProvider: 'deepseek',
      fallbackModel: 'deepseek-v4-pro',
      fallbackPolicy: { enabled: true, maxAttempts: 2, timeoutMs: 30000 },
    } })
  })
  const centralFs = new LocalUserFs((id) => join(dataRoot, 'users', id), () => loadPlatformRouting(config))
  for (const id of [USER, 'new-user']) {
    await centralFs.initUserRoot(id)
    const patch = readFileSync(join(dataRoot, 'users', id, 'home', 'profiles', 'web', 'cordis.patch.yml'), 'utf8')
    assert.match(patch, /primaryProvider: "deepseek"\s+primaryModel: "deepseek-v4\.1-flash"/)
    assert.match(patch, /fallbackProvider: "deepseek"\s+fallbackModel: "deepseek-v4-pro"/)
    assert.ok(!patch.includes(config.sessionSecret))
  }
  assert.equal(fetchMock.mock.callCount(), 2)
})
