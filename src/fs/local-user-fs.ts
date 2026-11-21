/**
 * Direct-filesystem {@link UserFs}: the control plane owns the users volume and
 * touches it in-process. This is the `deployMode=local` implementation, and it
 * is also what the per-user file sidecar runs behind its HTTP surface — the
 * sidecar is just a `LocalUserFs` pinned to one user's root.
 * @module dsh-server-login/fs/local-user-fs
 */

import {
  chownSync,
  chmodSync,
  cpSync,
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs'
import { homedir } from 'node:os'
import { mkdir, writeFile } from 'node:fs/promises'
import { stat } from 'node:fs/promises'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { dump as dumpYaml, load as loadYaml } from 'js-yaml'
import { PathEscapeError, resolveWithinRoot, safeFilename } from '../web/middleware/fs-guard.js'
import { listInstalledPlugins, type PluginInfo } from './plugins.js'
import { UserFsError, type UserFs } from './user-fs.js'
import { ensureDir, grantUserRootPermissions, grantUserSandboxPermissions, handoffPath, homeRoot, listDir, rejectSymlinkEscape, workspaceRoot, type FsEntry } from './workspace.js'

/** Resolve a user id to that user's data root (`<dataRoot>/users/<id>`, or a
 * fixed directory when the sidecar serves exactly one user). */
export type UserRootResolver = (userId: string) => string

/** Map a Node errno onto the wire code the desktop already handles. */
function fsError(err: unknown, onMissing: 'not_found' | 'parent_missing'): never {
  const code = (err as NodeJS.ErrnoException).code
  if (code === 'EEXIST') throw new UserFsError('exists')
  if (code === 'ENOENT' || code === 'ENOTDIR') throw new UserFsError(onMissing)
  throw err
}


function chownRecursiveSync(targetPath: string, uid: number, gid: number): void {
  try {
    chownSync(targetPath, uid, gid)
    const entries = readdirSync(targetPath, { withFileTypes: true })
    for (const entry of entries) {
      const full = join(targetPath, entry.name)
      if (entry.isDirectory()) {
        chownRecursiveSync(full, uid, gid)
      } else {
        try {
          chownSync(full, uid, gid)
        } catch {}
      }
    }
  } catch {}
}

const COPYMONSTER_BUNDLE = '@deepseek-ai/dsh-copymonster'
const WEB_APP_BUNDLE = '@deepseek-ai/dsh-web-app'
const MODEL_MASK_BUNDLE = '@deepseek-ai/dsh-host-model-mask'
/** Profile patch row id the model-mask bundle inserts; tenants only see the virtual CopyMonster model. */
const MODEL_MASK_ROW_ID = 'model-mask'
/** Profile patch row id that owns the tenant's default model selection. */
const AGENT_DEFAULT_MODEL_ROW_ID = 'agent-default-model'
/** Virtual provider route every tenant selects; the mask resolves it to the platform route. */
const TENANT_MODEL_PROVIDER = 'copymonster'
/** Virtual model id every tenant selects; the mask resolves it to the platform route. */
const TENANT_MODEL_ID = 'copy-monster-default'

/**
 * One MCP bundle the control plane mounts in every tenant profile.
 *
 * Each of these registers a remote MCP endpoint and serves a Web settings card,
 * so it needs all three of: a `dsh.profile.bundles` entry (the Host mounts the
 * plugin and therefore announces its client module in `__DSH_BOOT__`), a
 * resolvable package in the profile's `node_modules`, and a profile patch row
 * carrying this tenant's own public origin (the plugin's trusted-host fence
 * would otherwise reject `<username>.<baseDomain>` and register a loopback
 * callback).
 */
interface McpBundle {
  /** Bundle package name. */
  readonly bundle: string
  /** Profile patch row id the bundle inserts and this provisioning overrides. */
  readonly rowId: string
}

/** MCP bundles that must be present, in this order, in every tenant profile. */
const MCP_BUNDLES: readonly McpBundle[] = [
  { bundle: '@deepseek-ai/dsh-experimental-zernio-mcp', rowId: 'zernio-mcp' },
  { bundle: '@deepseek-ai/dsh-experimental-sendpulse-mcp', rowId: 'sendpulse-mcp' },
  { bundle: '@deepseek-ai/dsh-experimental-leadlovers-mcp', rowId: 'leadlovers-mcp' },
  { bundle: '@deepseek-ai/dsh-experimental-kiwify-mcp', rowId: 'kiwify-mcp' },
]

/**
 * Append a YAML block to existing patch content, guaranteeing a newline
 * separator between the existing content and the new block and a trailing
 * newline. Prevents rows from different blocks being fused onto a single
 * line when the source file lacks a trailing newline.
 */
function appendYamlBlock(raw: string, block: string): string {
  const separator = raw.endsWith('\n') ? '' : '\n'
  return `${raw}${separator}${block.endsWith('\n') ? block : `${block}\n`}`
}

/** Shared workspace sandbox the tenant DSH writes under, unless configured. */
const DEFAULT_COPYMONSTER_DATA_DIR = '/var/copymonster/data'



/** One route the model-mask resolves the virtual alias to. */
interface TenantModelRoute {
  readonly provider: string
  readonly model: string
}

/** Platform routing the tenant profile's model-mask row carries. */
export interface TenantRoutingPolicy {
  readonly primary: TenantModelRoute
  readonly fallback: TenantModelRoute
  readonly failoverEnabled: boolean
  readonly maxAttempts: number
  readonly timeoutMs: number
}

/** Environment defaults, used only while the operator profile carries no policy. */
const DEFAULT_PRIMARY_ROUTE: TenantModelRoute = { provider: 'openrouter', model: 'deepseek/deepseek-chat' }
const DEFAULT_FALLBACK_ROUTE: TenantModelRoute = { provider: 'openrouter', model: 'openrouter/free' }

/** Narrow one decoded YAML value to a plain object. */
function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

/** Read one non-empty string member, or undefined. */
function stringMember(node: unknown, key: string): string | undefined {
  if (!isRecord(node)) return undefined
  const value = node[key]
  return typeof value === 'string' && value !== '' ? value : undefined
}

/** Read one boolean member, or undefined. */
function booleanMember(node: unknown, key: string): boolean | undefined {
  if (!isRecord(node)) return undefined
  const value = node[key]
  return typeof value === 'boolean' ? value : undefined
}

/** Read one positive integer member, or undefined. */
function countMember(node: unknown, key: string): number | undefined {
  if (!isRecord(node)) return undefined
  const value = node[key]
  return typeof value === 'number' && Number.isInteger(value) && value > 0 ? value : undefined
}

/** Flatten a patch document's root rows and its `- insert:` groups. */
function patchRows(document: unknown): Record<string, unknown>[] {
  if (!Array.isArray(document)) return []
  const rows: Record<string, unknown>[] = []
  for (const row of document) {
    if (!isRecord(row)) continue
    if (Array.isArray(row.insert)) {
      for (const nested of row.insert) if (isRecord(nested)) rows.push(nested)
      continue
    }
    rows.push(row)
  }
  return rows
}

/**
 * Platform routing policy the tenant profile must carry.
 *
 * The operator configures it once in Settings → Models, which stores the
 * `model-mask` row of the template profile. Tenants copy that policy on every
 * launch: the platform credential pays for the route, so it must not be left to
 * whatever a tenant profile was copied with. Environment values stand in until
 * the operator configures a policy.
 * @param templateProfile - the operator profile tenants are provisioned from, when present.
 * @returns the primary and fallback routes with the failover policy.
 */
function tenantRoutingPolicy(templateProfile?: string): TenantRoutingPolicy {
  const policy: TenantRoutingPolicy = {
    primary: {
      provider: process.env.DSH_SERVER_LOGIN_LLM_PRIMARY_PROVIDER ?? DEFAULT_PRIMARY_ROUTE.provider,
      model: process.env.DSH_SERVER_LOGIN_LLM_PRIMARY_MODEL ?? DEFAULT_PRIMARY_ROUTE.model,
    },
    fallback: {
      provider: process.env.DSH_SERVER_LOGIN_LLM_FALLBACK_PROVIDER ?? DEFAULT_FALLBACK_ROUTE.provider,
      model: process.env.DSH_SERVER_LOGIN_LLM_FALLBACK_MODEL ?? DEFAULT_FALLBACK_ROUTE.model,
    },
    failoverEnabled: true,
    maxAttempts: 2,
    timeoutMs: 30000,
  }
  if (templateProfile === undefined) return policy
  const patchPath = join(templateProfile, 'cordis.patch.yml')
  if (!existsSync(patchPath)) return policy
  try {
    const row = patchRows(loadYaml(readFileSync(patchPath, 'utf8')))
      .find(candidate => candidate.id === MODEL_MASK_ROW_ID)
    const config = row?.config
    const failover = isRecord(config) ? config.fallbackPolicy : undefined
    return {
      primary: {
        provider: stringMember(config, 'primaryProvider') ?? policy.primary.provider,
        model: stringMember(config, 'primaryModel') ?? policy.primary.model,
      },
      fallback: {
        provider: stringMember(config, 'fallbackProvider') ?? policy.fallback.provider,
        model: stringMember(config, 'fallbackModel') ?? policy.fallback.model,
      },
      failoverEnabled: booleanMember(failover, 'enabled') ?? policy.failoverEnabled,
      maxAttempts: countMember(failover, 'maxAttempts') ?? policy.maxAttempts,
      timeoutMs: countMember(failover, 'timeoutMs') ?? policy.timeoutMs,
    }
  } catch (error) {
    warnProvisioning(`read ${MODEL_MASK_ROW_ID} routing policy`, patchPath, error)
    return policy
  }
}

/**
 * Tenant `settings.yaml` handed to the harness profile on boot.
 *
 * The harness imports this legacy document into the profile patch and renames
 * it, so writing it before every launch keeps the tenant's default selection at
 * the virtual alias even when the source profile carried the operator's own
 * provider. Only the selection is declared here; the real provider routes live
 * in the profile patch and stay out of the tenant-visible document.
 */
function tenantSettingsYaml(): string {
  return [
    `${AGENT_DEFAULT_MODEL_ROW_ID}:`,
    `  provider: ${TENANT_MODEL_PROVIDER}`,
    `  model: ${TENANT_MODEL_ID}`,
    '',
  ].join('\n')
}


/** Shape of a harness credential store, as far as provisioning reads it. */
interface CredentialStore {
  version?: number
  refs?: Record<string, string>
  records?: Record<string, unknown>
}

/**
 * Known platform LLM provider keys that belong strictly in admin/control plane.
 */
export const PLATFORM_CREDENTIAL_KEYS = new Set([
  'OPENROUTER_API_KEY',
  'DEEPSEEK_API_KEY',
  'OPENAI_API_KEY',
  'ANTHROPIC_API_KEY',
])

/**
 * Sanitize a tenant's credentials store.
 * Ensures that regular tenants never store or inherit platform master API keys
 * in their home `.credentials.yaml`.
 *
 * If the tenant store contains platform references (e.g. OpenRouter, DeepSeek,
 * OpenAI, Anthropic) or keys with sensitive provider prefixes (sk-or-v1-, sk-ant-,
 * sk-proj-, dsk-, sk-), they are purged.
 *
 * @param home - the tenant's DSH home directory.
 */
export function sanitizeTenantCredentials(home: string): void {
  const target = join(home, '.credentials.yaml')
  if (!existsSync(target)) return

  let tenant: CredentialStore
  try {
    const parsed: unknown = loadYaml(readFileSync(target, 'utf8'))
    if (parsed === null || typeof parsed !== 'object') return
    tenant = parsed as CredentialStore
  } catch (error) {
    warnProvisioning('read tenant credentials for sanitization', target, error)
    return
  }

  if (!tenant.refs || typeof tenant.refs !== 'object') return

  const SENSITIVE_KEY_PREFIX = /^(sk-or-v1-|sk-ant-|sk-proj-|dsk-|sk-)/i
  let modified = false
  const sanitizedRefs: Record<string, string> = {}

  for (const [k, v] of Object.entries(tenant.refs)) {
    const normKey = k.trim().toUpperCase()
    const strVal = typeof v === 'string' ? v.trim() : ''

    if (PLATFORM_CREDENTIAL_KEYS.has(normKey) || SENSITIVE_KEY_PREFIX.test(strVal)) {
      modified = true
      continue
    }

    sanitizedRefs[k] = v
  }

  if (!modified) return

  const sanitized: CredentialStore = {
    version: tenant.version ?? 1,
    refs: sanitizedRefs,
    ...(tenant.records === undefined ? {} : { records: tenant.records }),
  }

  try {
    writeFileSync(target, dumpYaml(sanitized, { lineWidth: 120 }), { mode: 0o600 })
  } catch (error) {
    warnProvisioning('write sanitized tenant credentials', target, error)
  }
}

/**
 * Prepare the shared workspace sandbox for tenant uids.
 *
 * The sandbox lives at `<dir>/<tenantId>/<userId>/workspaces` and is created by
 * the tenant's own DSH process, which runs as that tenant's uid, while the
 * parent directory is created by the root control plane. Without a writable
 * parent the tenant fails with `EACCES` on its first workspace. The sticky
 * world-writable mode gives the directory `/tmp` semantics: every tenant
 * creates its own entry and the sticky bit stops one tenant from removing
 * another's. Tenant ids are UUIDs, so a tenant cannot address another's entry.
 * @param dataRoot - the shared sandbox root to prepare.
 */
function ensureSharedSandboxRoot(dataRoot: string): void {
  mkdirSync(dataRoot, { recursive: true, mode: 0o1777 })
  chmodSync(dataRoot, 0o1777)
  for (const entry of readdirSync(dataRoot, { withFileTypes: true })) {
    if (!entry.isDirectory()) continue
    try {
      chmodSync(join(dataRoot, entry.name), 0o1777)
    } catch (error) {
      warnProvisioning('prepare shared sandbox', join(dataRoot, entry.name), error)
    }
  }
}

/** Log one provisioning failure that would otherwise pass silently. */
function warnProvisioning(step: string, target: string, error: unknown): void {
  const detail = error instanceof Error ? error.message : String(error)
  console.warn(`[provisioning] ${step} failed for ${target}: ${detail}`)
}

/** This package's root, used to expose `dsh-server-login/runtime` to tenants. */
const PACKAGE_ROOT = fileURLToPath(new URL('../../', import.meta.url))

/**
 * Expose a package to a tenant profile by placing a link in the user root's
 * `node_modules`, which Node walks up to from `<home>/profiles/<name>/`.
 * @param root - the tenant root directory.
 * @param name - the bare package name to link.
 * @param target - the package directory the link points at.
 */
function linkPackageIntoUserRoot(root: string, name: string, target: string): void {
  const modulesDir = join(root, 'node_modules')
  ensureDir(modulesDir)
  const link = join(modulesDir, name)
  if (existsSync(link)) return
  try {
    symlinkSync(target, link, 'dir')
  } catch (error) {
    // Without this link the tenant cannot resolve `dsh-server-login/runtime`
    // and its child fails to boot, so the failure must reach the journal.
    warnProvisioning('link package', link, error)
  }
}

/** Restrict a file to its owner when the recursive permission pass widened it. */
function restrictToOwner(targetPath: string): void {
  try {
    if (existsSync(targetPath)) chmodSync(targetPath, 0o600)
  } catch {}
}

/**
 * Ensure one bundle appears in a profile's `dsh.profile.bundles`, inserted
 * directly after the given anchor layer so it applies after `dsh-base` and
 * `dsh-web-app` but before the profile's own `cordis.patch.yml`.
 * @param packageJsonPath - the profile's `package.json`.
 * @param bundle - bare bundle package name.
 * @param after - bundle to insert after; appended to the list when absent.
 */
function ensureBundle(packageJsonPath: string, bundle: string, after: string = WEB_APP_BUNDLE): void {
  try {
    if (!existsSync(packageJsonPath)) return
    const raw = readFileSync(packageJsonPath, 'utf8')
    const manifest = JSON.parse(raw)
    const profile = manifest?.dsh?.profile
    if (profile === undefined || !Array.isArray(profile.bundles)) return
    if (profile.bundles.includes(bundle)) return
    const bundles = [...profile.bundles]
    const anchorIdx = bundles.indexOf(after)
    if (anchorIdx === -1) {
      bundles.push(bundle)
    } else {
      bundles.splice(anchorIdx + 1, 0, bundle)
    }
    manifest.dsh.profile.bundles = bundles
    writeFileSync(packageJsonPath, `${JSON.stringify(manifest, undefined, 2)}\n`)
  } catch (error) {
    warnProvisioning(`ensure ${bundle} bundle`, packageJsonPath, error)
  }
}

/**
 * Ensure the profile patch carries one MCP bundle's row with this deployment's
 * own public origin. The bundle's own patch inserts the row without an origin.
 *
 * The row is matched by its id inside a `- insert:` block (the form the bundle
 * layer itself produces) as well as at the document root, so a profile whose
 * patch was written either way is updated instead of duplicated.
 * @param cordisPatchPath - the profile's `cordis.patch.yml`.
 * @param rowId - profile patch row id the bundle's own patch inserts.
 * @param bundle - bundle package name the row mounts.
 * @param publicOrigin - browser-facing origin of this tenant.
 */
function ensureMcpEntry(cordisPatchPath: string, rowId: string, bundle: string, publicOrigin: string): void {
  try {
    if (!existsSync(cordisPatchPath)) return
    const raw = readFileSync(cordisPatchPath, 'utf8')
    const lines = raw.split('\n')
    const idIdx = lines.findIndex(line => line.trim() === `- id: ${rowId}`)
    if (idIdx === -1) {
      const block = [`- id: ${rowId}`, `  name: "${bundle}"`, '  config:', `    publicOrigin: ${publicOrigin}`].join('\n')
      writeFileSync(cordisPatchPath, appendYamlBlock(raw, block))
      return
    }
    // A row under an `insert:` list starts its `- id:` marker two spaces left of
    // its keys, so the keys' indentation is read from the row's own `name:`.
    const siblingLine = lines.slice(idIdx + 1).find(line => line.trimStart().startsWith('name:'))
    const markerIndent = /^\s*/.exec(lines[idIdx])?.[0] ?? ''
    const keyIndent = siblingLine === undefined ? `${markerIndent}  ` : (/^\s*/.exec(siblingLine)?.[0] ?? '')
    let end = lines.length
    for (let i = idIdx + 1; i < lines.length; i += 1) {
      if (lines[i].trimStart().startsWith('- ')) {
        end = i
        break
      }
    }
    const originIdx = lines.findIndex((line, i) => i > idIdx && i < end && line.trimStart().startsWith('publicOrigin:'))
    const configIdx = lines.findIndex((line, i) => i > idIdx && i < end && line.trim() === 'config:')
    if (originIdx !== -1) {
      lines[originIdx] = `${configIdx === -1 ? keyIndent : `${keyIndent}  `}publicOrigin: ${publicOrigin}`
    } else if (configIdx !== -1) {
      lines.splice(configIdx + 1, 0, `${keyIndent}  publicOrigin: ${publicOrigin}`)
    } else {
      lines.splice(end, 0, `${keyIndent}config:`, `${keyIndent}  publicOrigin: ${publicOrigin}`)
    }
    const updated = lines.join('\n')
    writeFileSync(cordisPatchPath, updated.endsWith('\n') ? updated : `${updated}\n`)
  } catch (error) {
    warnProvisioning(`ensure ${rowId} profile entry`, cordisPatchPath, error)
  }
}
/**
 * Replace one patch row with a freshly rendered block, or append the row when
 * the profile has none. Idempotent: re-running with the same block rewrites the
 * same bytes.
 * @param cordisPatchPath - the profile's `cordis.patch.yml`.
 * @param rowId - profile patch row id to replace.
 * @param block - complete row lines, without a trailing newline element.
 */
function writePatchRow(cordisPatchPath: string, rowId: string, block: readonly string[]): void {
  const raw = readFileSync(cordisPatchPath, 'utf8')
  const lines = raw.split('\n')
  const text = block.join('\n')
  const idIdx = lines.findIndex(line => line.trim() === `- id: ${rowId}`)
  if (idIdx === -1) {
    writeFileSync(cordisPatchPath, appendYamlBlock(raw, text))
    return
  }
  let end = lines.length
  for (let i = idIdx + 1; i < lines.length; i += 1) {
    if (lines[i].startsWith('- ')) {
      end = i
      break
    }
  }
  const prefix = lines.slice(0, idIdx).join('\n')
  const suffix = lines.slice(end).join('\n')
  writeFileSync(cordisPatchPath, `${appendYamlBlock(prefix, text)}${suffix}`)
}

/** Provider route whose profile the tenant's `llm-pi-ai` row owns. */
const LLM_PI_AI_ROW_ID = 'llm-pi-ai'

/** Escape one literal for use inside a regular expression. */
function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

/**
 * Ensure one provider route in the tenant profile advertises a model id.
 *
 * A route that declares a `models` list serves exactly that list, so a platform
 * model the operator's own profile never listed is refused as `UNKNOWN_MODEL`
 * even though the route's credential and endpoint are configured. The model is
 * inserted as text lines beside the existing entries to keep the operator's
 * comments and formatting, unlike a full YAML round trip.
 * @param cordisPatchPath - the profile's `cordis.patch.yml`.
 * @param provider - provider route that must advertise the model.
 * @param modelId - model id the platform route resolves to.
 * @returns whether a model entry was added; false when the route already
 *   advertises the id, omits a `models` list (serving the installed catalog),
 *   or is absent from the profile.
 */
function ensureProviderModel(cordisPatchPath: string, provider: string, modelId: string): boolean {
  const raw = readFileSync(cordisPatchPath, 'utf8')
  const lines = raw.split('\n')
  const rowIdx = lines.findIndex(line => line.trim() === `- id: ${LLM_PI_AI_ROW_ID}`)
  if (rowIdx === -1) return false
  let rowEnd = lines.length
  for (let i = rowIdx + 1; i < lines.length; i += 1) {
    if (lines[i].startsWith('- ')) {
      rowEnd = i
      break
    }
  }

  const providerPattern = new RegExp(`^(\\s+)${escapeRegExp(provider)}:\\s*$`)
  let providerIdx = -1
  let providerIndent = ''
  for (let i = rowIdx + 1; i < rowEnd; i += 1) {
    const match = providerPattern.exec(lines[i])
    if (match === null) continue
    providerIdx = i
    providerIndent = match[1]
    break
  }
  if (providerIdx === -1) return false

  // The provider block ends at the next line indented no deeper than its own key.
  let blockEnd = rowEnd
  for (let i = providerIdx + 1; i < rowEnd; i += 1) {
    if (lines[i].trim() === '') continue
    const indent = /^\s*/.exec(lines[i])?.[0] ?? ''
    if (indent.length <= providerIndent.length) {
      blockEnd = i
      break
    }
  }

  const modelsIdx = lines.findIndex((line, i) => i > providerIdx && i < blockEnd && line.trim() === 'models:')
  // No list means the route serves the installed catalog, which may already
  // describe the model; only an explicit list can omit it.
  if (modelsIdx === -1) return false
  const entryIndent = `${/^\s*/.exec(lines[modelsIdx])?.[0] ?? ''}  `
  const listed = lines.slice(modelsIdx + 1, blockEnd).some((line) => {
    const match = /^\s*-\s*id:\s*(.+?)\s*$/.exec(line)
    return match !== null && match[1].replace(/^(['"])(.*)\1$/, '$2') === modelId
  })
  if (listed) return false

  lines.splice(modelsIdx + 1, 0, `${entryIndent}- id: ${JSON.stringify(modelId)}`, `${entryIndent}  name: ${JSON.stringify(modelId)}`)
  writeFileSync(cordisPatchPath, lines.join('\n'))
  return true
}

/**
 * Ensure the tenant's `cordis.patch.yml` mounts the model-mask bundle with the
 * virtual CopyMonster model and the platform routing policy. Idempotent: an
 * existing row is rewritten, a missing row is appended.
 * @param cordisPatchPath - the profile's `cordis.patch.yml`.
 * @param policy - platform routing the tenant must resolve the alias to.
 */
function ensureModelMaskEntry(cordisPatchPath: string, policy: TenantRoutingPolicy, strict = false): void {
  try {
    if (!existsSync(cordisPatchPath)) {
      if (strict) throw new Error('Tenant profile patch is missing')
      return
    }
    // The mask resolves the alias to these routes at dispatch time, so the
    // profile must advertise both or the tenant turn fails as UNKNOWN_MODEL.
    if (policy.primary.provider && policy.primary.model) {
      ensureProviderModel(cordisPatchPath, policy.primary.provider, policy.primary.model)
    }
    if (policy.fallback.provider && policy.fallback.model) {
      ensureProviderModel(cordisPatchPath, policy.fallback.provider, policy.fallback.model)
    }
    writePatchRow(cordisPatchPath, MODEL_MASK_ROW_ID, [
      `- id: ${MODEL_MASK_ROW_ID}`,
      `  name: "${MODEL_MASK_BUNDLE}"`,
      '  config:',
      `    virtualProvider: ${TENANT_MODEL_PROVIDER}`,
      `    virtualModel: ${TENANT_MODEL_ID}`,
      '    virtualModelName: Model CopyMonster',
      `    primaryProvider: ${strict ? JSON.stringify(policy.primary.provider) : policy.primary.provider}`,
      `    primaryModel: ${strict ? JSON.stringify(policy.primary.model) : policy.primary.model}`,
      `    fallbackProvider: ${strict ? JSON.stringify(policy.fallback.provider) : policy.fallback.provider}`,
      `    fallbackModel: ${strict ? JSON.stringify(policy.fallback.model) : policy.fallback.model}`,
      `    fallbackPolicy:`,
      `      enabled: ${policy.failoverEnabled}`,
      `      maxAttempts: ${policy.maxAttempts}`,
      `      timeoutMs: ${policy.timeoutMs}`,
      `    applyToTenantsOnly: true`,
    ])
  } catch (error) {
    if (strict) throw error
    warnProvisioning('ensure model-mask profile entry', cordisPatchPath, error)
  }
}

/**
 * Ensure the tenant's default model selection is the virtual CopyMonster alias.
 *
 * A profile copied from the operator's own profile keeps that operator's
 * provider selection, and a stale selection keeps every tenant turn on a route
 * the tenant cannot pay for. Rewriting the row on every launch makes the
 * platform route authoritative regardless of when the profile was provisioned.
 * @param cordisPatchPath - the profile's `cordis.patch.yml`.
 */
function ensureAgentDefaultModel(cordisPatchPath: string): void {
  try {
    if (!existsSync(cordisPatchPath)) return
    writePatchRow(cordisPatchPath, AGENT_DEFAULT_MODEL_ROW_ID, [
      `- id: ${AGENT_DEFAULT_MODEL_ROW_ID}`,
      `  name: "@deepseek-ai/dsh-agent-default-model"`,
      '  config:',
      `    provider: ${TENANT_MODEL_PROVIDER}`,
      `    model: ${TENANT_MODEL_ID}`,
    ])
  } catch (error) {
    warnProvisioning('ensure agent-default-model profile entry', cordisPatchPath, error)
  }
}

/**
 * Make one bundle's package resolvable from a profile whose `node_modules` is
 * a real directory: a tenant copied before the template gained the package, or
 * a fresh copy sharing the template tree that never had the scope link.
 *
 * The target is the template's own entry when it has one, so the tenant keeps
 * resolving whatever tree the template was installed from. Without the link the
 * Host cannot import the plugin, so the bundle drops out of the roster and its
 * Web card never boots.
 * @param userModules - the profile's `node_modules`.
 * @param templateModules - the template profile's `node_modules`, when present.
 * @param bundle - bundle package name to link.
 */
function linkBundlePackage(userModules: string, templateModules: string | undefined, bundle: string): void {
  // `bundle` already carries its scope, so it is one path segment under
  // `node_modules`; the template entry is the same segment under the template.
  const link = join(userModules, bundle)
  if (existsSync(link)) return
  const candidate = templateModules === undefined ? undefined : join(templateModules, bundle)
  if (candidate === undefined || !existsSync(candidate)) {
    warnProvisioning(`resolve ${bundle} package`, candidate ?? link, new Error('not present in the template profile'))
    return
  }
  try {
    ensureDir(join(userModules, '@deepseek-ai'))
    symlinkSync(realpathSync(candidate), link, 'dir')
  } catch (error) {
    warnProvisioning(`link ${bundle} package`, link, error)
  }
}

export class LocalUserFs implements UserFs {
  constructor(
    private readonly rootFor: UserRootResolver,
    private readonly loadRouting?: () => Promise<TenantRoutingPolicy | undefined>,
  ) {}

  /**
   * Provision a tenant root and keep its web profile aligned with the template.
   * @param userId - tenant user id.
   * @param uid - tenant Linux uid, when the control plane assigns one.
   * @param publicOrigin - browser-facing origin of this tenant; when set, every
   *   MCP bundle's profile row pins it.
   */
  async initUserRoot(userId: string, uid?: number, publicOrigin?: string, options?: { isAdmin?: boolean }): Promise<void> {
    const platformRouting = await this.loadRouting?.()
    const root = this.rootFor(userId)
    ensureDir(homeRoot(root))
    ensureDir(workspaceRoot(root))
    ensureDir(join(workspaceRoot(root), 'workspace'))

    // The workspace sandbox sits outside this per-user root, so the tenant uid
    // needs the shared root prepared before its DSH can create a workspace.
    // The sandbox itself is handed to that uid too: a directory this control
    // plane created as root would refuse the tenant's own `mkdir` (EACCES).
    if (typeof process.getuid === 'function' && process.getuid() === 0) {
      const dataRoot = process.env.COPYMONSTER_DATA_DIR ?? DEFAULT_COPYMONSTER_DATA_DIR
      try {
        ensureSharedSandboxRoot(dataRoot)
      } catch {}
      if (uid !== undefined) grantUserSandboxPermissions(dataRoot, userId, uid)
    }

    // Provision the resident web profile so the per-user DSH can boot without
    // missing node_modules. Check known template profile locations, and let a
    // deployment pin the one it installs so a stray home directory on the
    // control-plane host never shadows it.
    const configuredTemplate = process.env.DSH_SERVER_LOGIN_TEMPLATE_PROFILE
    const candidateTemplates = configuredTemplate !== undefined && configuredTemplate !== ''
      ? [configuredTemplate]
      : [
          '/root/.dsh/profiles/web',
          '/var/lib/copymonster-dsh/profiles/web',
          join(homedir(), '.dsh', 'profiles', 'web'),
        ]
    const templateProfile = candidateTemplates.find((p) => existsSync(p))
    const userProfile = join(homeRoot(root), 'profiles', 'web')

    if (templateProfile && !existsSync(userProfile)) {
      cpSync(templateProfile, userProfile, {
        recursive: true,
        filter: (src) => {
          const base = join(templateProfile, 'node_modules')
          const settingsYaml = join(templateProfile, 'settings.yaml')
          // Never copy the Admin's raw settings.yaml — it names the operator's
          // own provider and selection. The tenant document is written below.
          return src !== base && src !== settingsYaml
        },
      })
    }

    // Write the tenant document on every launch, not only at first provisioning:
    // a profile copied before this rule kept the operator's selection, and the
    // harness imports this document over the profile on boot. Only the virtual
    // alias is declared, so the real route never reaches the tenant.
    const tenantSettingsYamlPath = join(userProfile, 'settings.yaml')
    if (existsSync(userProfile)) {
      try {
        writeFileSync(tenantSettingsYamlPath, tenantSettingsYaml(), { mode: 0o644 })
      } catch (error) {
        warnProvisioning('write virtual settings.yaml', tenantSettingsYamlPath, error)
      }
    }

    // Share the template's installed dependencies rather than copying them: the
    // profile's own links resolve against the template tree, and every tenant
    // reads the same modules without a per-tenant install.
    const templateModules = templateProfile === undefined ? undefined : join(templateProfile, 'node_modules')
    let userModules = join(userProfile, 'node_modules')
    // A tenant copied without the template's `node_modules` keeps its own empty
    // directory, and the share below would then skip it, leaving every profile
    // dependency — the MCP bundles included — unresolvable.
    if (existsSync(userModules) && readdirSync(userModules).length === 0) {
      rmSync(userModules, { recursive: true, force: true })
    }
    if (templateModules !== undefined && existsSync(templateModules) && !existsSync(userModules)) {
      try {
        symlinkSync(realpathSync(templateModules), userModules, 'dir')
      } catch (error) {
        warnProvisioning('share template node_modules', userModules, error)
      }
    }
    // `linkBundlePackage` links into `<profile>/node_modules`, so keep that
    // exact path even when the scope directory had to be created per tenant.
    userModules = join(userProfile, 'node_modules')

    // The supervisor patch mounts `dsh-server-login/runtime` in every child, and
    // Node resolves it by walking up from `<home>/profiles/<profile>/`.
    linkPackageIntoUserRoot(root, 'dsh-server-login', PACKAGE_ROOT)

    // Always ensure the tenant's web profile includes the CopyMonster bundle
    const userPackageJson = join(userProfile, 'package.json')
    ensureBundle(userPackageJson, COPYMONSTER_BUNDLE)

    // Existing profiles were copied before later template additions, so every
    // MCP bundle is backfilled on each launch rather than only at first
    // provisioning: an absent bundle leaves its plugin out of the Host loader,
    // which keeps its client module out of `__DSH_BOOT__` and drops its settings
    // card from the tenant's Web app.
    let anchor = WEB_APP_BUNDLE
    for (const { bundle, rowId } of MCP_BUNDLES) {
      ensureBundle(userPackageJson, bundle, anchor)
      linkBundlePackage(userModules, templateModules, bundle)
      if (publicOrigin !== undefined) {
        ensureMcpEntry(join(userProfile, 'cordis.patch.yml'), rowId, bundle, publicOrigin)
      }
      anchor = bundle
    }

    // Inject the model-mask row into the tenant's cordis.patch.yml so tenants
    // only see the virtual `copy-monster-default` / "Model CopyMonster" model,
    // carrying the platform routing the operator configured in Settings, and pin
    // the default selection to that alias on every launch.
    const cordisPatchPath = join(userProfile, 'cordis.patch.yml')
    ensureModelMaskEntry(cordisPatchPath, platformRouting ?? tenantRoutingPolicy(templateProfile), platformRouting !== undefined)
    ensureAgentDefaultModel(cordisPatchPath)

    // Under the Central Loopback Gateway architecture, tenants infer via
    // 127.0.0.1:4010 with ephemeral internal session tokens. Master provider
    // credentials are never seeded to tenant homes. Existing tenant stores are
    // sanitized to purge any legacy master keys.
    const isAdmin = options?.isAdmin === true
    if (!isAdmin) {
      sanitizeTenantCredentials(homeRoot(root))
    }

    // The roots were created by the (possibly root) control plane; the DSH child
    // runs as the user's own uid and must be able to traverse + write them.
    // Recursively chown the entire tree so the tenant has full permission over all files.
    if (uid !== undefined && typeof process.getuid === 'function' && process.getuid() === 0) {
      try {
        grantUserRootPermissions(root, uid)
        // The recursive pass above grants group/other read so the tenant's own
        // DSH can traverse what the control plane created. The per-user root,
        // its home and its workspace stay owner-only: the tenant owns them and
        // runs as this uid, so 0700 is enough for it and stops another tenant
        // from reading this one's sessions, credentials and workspace files.
        chmodSync(root, 0o700)
        chmodSync(homeRoot(root), 0o700)
        chmodSync(workspaceRoot(root), 0o700)
      } catch (error) {
        warnProvisioning('grant user root permissions', root, error)
        chownRecursiveSync(root, uid, uid)
        // The recursive pass grants group/other read; credential stores must stay
        // owner-only or the credentials plugin refuses to start.
        restrictToOwner(join(homeRoot(root), '.credentials.yaml'))
      }
    }
  }

  resolvePath(userId: string, relPath: string): string {
    return this.resolve(userId, relPath)
  }

  async listDir(userId: string, relPath: string): Promise<FsEntry[]> {
    const abs = this.resolve(userId, relPath)
    await this.assertNoLinks(userId, abs)
    try {
      return await listDir(abs)
    } catch (err) {
      fsError(err, 'not_found')
    }
  }

  async mkdir(userId: string, relPath: string): Promise<void> {
    const abs = this.resolve(userId, relPath)
    await this.assertNoLinks(userId, abs)
    try {
      await mkdir(abs)
    } catch (err) {
      fsError(err, 'parent_missing')
    }
  }

  async createEntry(userId: string, relPath: string, name: string, type: 'file' | 'dir'): Promise<string> {
    const dirAbs = this.resolve(userId, relPath)
    const filename = this.sanitize(name)
    const target = join(dirAbs, filename)
    await this.assertNoLinks(userId, target)
    try {
      if (type === 'dir') await mkdir(target)
      else await writeFile(target, '')
    } catch (err) {
      fsError(err, 'parent_missing')
    }
    return filename
  }

  async upload(userId: string, relPath: string, name: string, data: Buffer): Promise<string> {
    const dirAbs = this.resolve(userId, relPath)
    const filename = this.sanitize(name)
    const target = join(dirAbs, filename)
    await this.assertNoLinks(userId, target)
    try {
      await writeFile(target, data)
    } catch (err) {
      fsError(err, 'parent_missing')
    }
    return filename
  }

  async isDirectory(userId: string, relPath: string): Promise<boolean> {
    const abs = this.resolve(userId, relPath)
    await this.assertNoLinks(userId, abs)
    try {
      return (await stat(abs)).isDirectory()
    } catch (err) {
      fsError(err, 'not_found')
    }
  }

  async listInstalledPlugins(userId: string): Promise<PluginInfo[]> {
    return listInstalledPlugins(this.rootFor(userId))
  }

  async writeHandoff(userId: string, content: string): Promise<void> {
    const root = this.rootFor(userId)
    ensureDir(root)
    await writeFile(handoffPath(root), content)
  }

  /** Resolve a workspace-relative path, self-healing the root the way the
   * pre-seam routes did (every one of them called `ensureWorkspaceRoot` first). */
  private resolve(userId: string, relPath: string): string {
    const ws = workspaceRoot(this.rootFor(userId))
    ensureDir(ws)
    try {
      return resolveWithinRoot(ws, relPath)
    } catch (err) {
      if (err instanceof PathEscapeError) throw new UserFsError('bad_path')
      throw err
    }
  }

  /** The lexical guard above is prefix-only and blind to links planted inside
   * the workspace, so every operation re-walks its final absolute path (the
   * write target for upload/createEntry) and rejects any symlink component —
   * `writeFile`/`mkdir` would otherwise follow it outside the root with this
   * process's privileges. Surfaces as the usual `bad_path` wire code. */
  private async assertNoLinks(userId: string, abs: string): Promise<void> {
    try {
      await rejectSymlinkEscape(workspaceRoot(this.rootFor(userId)), abs)
    } catch (err) {
      if (err instanceof PathEscapeError) throw new UserFsError('bad_path')
      throw err
    }
  }

  private sanitize(name: string): string {
    try {
      return safeFilename(name)
    } catch (err) {
      if (err instanceof PathEscapeError) throw new UserFsError('bad_name')
      throw err
    }
  }
}
