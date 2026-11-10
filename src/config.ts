/**
 * Deployment-varying configuration. Every tunable is a validated field here
 * (or read from env), never a hardcoded constant inside the app.
 * @module dsh-server-login/config
 */

import { randomBytes } from 'node:crypto'
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { homedir, hostname } from 'node:os'
import { join } from 'node:path'

/** Isolation tier. `soft` = per-user home/workspace + sandbox (same OS user);
 * `account` = per-user OS account via a setuid wrapper (Linux, needs root). */
export type IsolationMode = 'soft' | 'account'

/** Deployment mode. `local` = single-host child_process (setuid/iptables);
 * `k8s` = multi-replica control plane spawning per-user DSH Pods via the K8s API. */
export type DeployMode = 'local' | 'k8s'

/** Resolved, immutable runtime configuration. */
export interface ServerConfig {
  /** Bind host for the orchestrator HTTP server. */
  host: string
  /** Bind port; `0` requests an ephemeral port. */
  port: number
  /** SQLite database path. */
  dbPath: string
  /** Postgres connection string; when set, the DB backend is Postgres (k8s/HA). */
  dbUrl?: string
  /** Root under which per-user homes (`users/<id>/home`) and workspaces live. */
  dataRoot: string
  /** Argv used to launch a child DSH; first element is the executable. */
  dshCommand: string[]
  /** Pino log level. */
  logLevel: string
  /** Set the `Secure` flag on session cookies (enable behind HTTPS). */
  secureCookies: boolean
  /** Session lifetime in seconds. */
  sessionTtlSeconds: number
  /** Max upload request body in bytes (base64 JSON; ~0.75× the file size). */
  maxUploadBytes: number
  /** Delay before auto-restarting a crashed child DSH, in milliseconds. */
  restartBackoffMs: number
  /** Isolation tier (see {@link IsolationMode}); local mode only. */
  isolationMode: IsolationMode
  /** Argv prefix that drops privileges; `{UID}`/`{GID}` are substituted. Local mode only. */
  spawnAsUserCommand: string[]
  /** Base uid for the deterministic per-user uid. */
  baseUid: number
  /** Parent domain for per-user subdomains (`<username>.<baseDomain>`); empty = disabled. */
  baseDomain: string
  /** Cookie `Domain` value (e.g. `.example.com`) so the session reaches subdomains; empty = host-only. */
  cookieDomain: string
  /** Whether to pass `--patch` to child DSHs (needs a dsh CLI that supports it). */
  enablePatch: boolean
  /**
   * Base64 SPKI Ed25519 public key the tenant verifies signed identities with.
   * Filled from the control plane's key at startup; empty disables the handshake.
   */
  identityPublicKey: string
  /** Enable the loopback OUTPUT owner-match port guard (Linux + root). Local mode only. */
  portGuard: boolean
  /**
   * `MemoryMax` for each tenant DSH scope (systemd syntax, e.g. `2G`). Unset
   * leaves the child unbounded; the scope wrapper also requires `cpuQuota` or
   * `tasksMax` to be meaningful. Local mode only.
   */
  memoryMax?: string
  /** `CPUQuota` for each tenant DSH scope (systemd syntax, e.g. `200%`). */
  cpuQuota?: string
  /** `TasksMax` for each tenant DSH scope; caps process and thread count. */
  tasksMax?: number
  /**
   * Whether tenant children run inside a transient systemd scope.
   *
   * Off by default: on this host `systemd-run --scope` from inside the
   * orchestrator service fails to exec the tenant binary and leaves the
   * service's cgroup teardown timing out, so the feature must be enabled only
   * after it is validated on the target host.
   */
  resourceScopes: boolean
  /**
   * Per-plan scope limits, keyed by plan slug. The main app reports the slug on
   * every SSO exchange and the orchestrator stores the resolved values on the
   * user row; a slug absent from this map leaves that tenant on the global
   * `memoryMax`/`cpuQuota`/`tasksMax` above.
   */
  planLimits: Record<string, { memoryMax?: string; cpuQuota?: string; tasksMax?: number }>
  /** Secret used to encrypt per-user secrets at rest (from env or dataRoot/secret.key). */
  encryptionSecret: string
  /** Deployment mode (see {@link DeployMode}). */
  deployMode: DeployMode
  /** K8s namespace for per-user DSH resources (k8s mode only). */
  k8sNamespace: string
  /** Image for per-user DSH Pods (k8s mode only). */
  dshImage: string
  /** Image for the per-user file sidecar (k8s mode only; shares the control-plane image). */
  controlPlaneImage: string
  /** imagePullSecret every generated per-user Pod/Job uses (k8s mode only). */
  imagePullSecret: string
  /** 443 egress whitelist CIDRs for per-user DSH Pods (Phase 4 egress 收敛);
   * empty = keep the current `0.0.0.0/0` (except private ranges). */
  egressCidrs: string[]
  /** ServiceAccount the orchestrator runs as (k8s mode only). */
  k8sServiceAccount: string
  /** This replica's identity for leader election (POD_NAME, else hostname). */
  podName: string
  /** Supabase project URL (required for Supabase Auth integration). */
  supabaseUrl: string
  /** Supabase anon/public key (required for Supabase Auth integration). */
  supabaseAnonKey: string
  /** HMAC key for the signed `sid` cookie; shared with the main app. */
  sessionSecret: string
  /** Base URL of the main app that owns Supabase session-token exchange. */
  mainAppUrl: string
}

/** Untyped overrides collected from argv / env. */
export interface ConfigOverrides {
  host?: string
  port?: string | number
  dbPath?: string
  dbUrl?: string
  dataRoot?: string
  dshCommand?: string[]
  logLevel?: string
  secureCookies?: boolean
  sessionTtlSeconds?: number | string
  maxUploadBytes?: number | string
  restartBackoffMs?: number | string
  isolationMode?: IsolationMode | string
  spawnAsUserCommand?: string[]
  baseUid?: number | string
  baseDomain?: string
  cookieDomain?: string
  enablePatch?: boolean
  portGuard?: boolean
  encryptionSecret?: string
  deployMode?: DeployMode | string
  k8sNamespace?: string
  dshImage?: string
  controlPlaneImage?: string
  imagePullSecret?: string
  egressCidrs?: string[]
  k8sServiceAccount?: string
  podName?: string
  supabaseUrl?: string
  supabaseAnonKey?: string
  sessionSecret?: string
  mainAppUrl?: string
}

const DEFAULT_HOST = '127.0.0.1'
const DEFAULT_PORT = 3080
const DEFAULT_DSH_COMMAND = ['dsh']
const DEFAULT_LOG_LEVEL = 'info'
const DEFAULT_SESSION_TTL_SECONDS = 60 * 60 * 24 * 7
const DEFAULT_MAX_UPLOAD_BYTES = 25 * 1024 * 1024
const DEFAULT_RESTART_BACKOFF_MS = 1000
const DEFAULT_ISOLATION_MODE: IsolationMode = 'account'
function defaultSpawnAsUserCommand(): string[] {
  const binary =
    ['/usr/bin/setpriv', '/bin/setpriv', '/usr/local/bin/setpriv'].find((p) => existsSync(p)) ??
    'setpriv'
  return [
    binary,
    '--reuid',
    '{UID}',
    '--regid',
    '{GID}',
    '--inh-caps=-all',
    '--clear-groups',
    '--',
  ]
}
const DEFAULT_SPAWN_AS_USER_COMMAND = defaultSpawnAsUserCommand()
const DEFAULT_BASE_UID = 100000
const DEFAULT_BASE_DOMAIN = ''
const DEFAULT_COOKIE_DOMAIN = ''
const DEFAULT_ENABLE_PATCH = false

/** systemd size syntax: a positive integer with an optional K/M/G/T suffix. */
const MEMORY_MAX_PATTERN = /^[1-9][0-9]*[KMGT]?$/
/** systemd CPU quota syntax: a positive percentage, optionally fractional. */
const CPU_QUOTA_PATTERN = /^[1-9][0-9]*(\.[0-9]+)?%$/

/**
 * Validate one resource-limit value at load time.
 * @param name - environment variable name, used in the failure message.
 * @param value - raw configured value.
 * @param pattern - accepted syntax.
 * @returns the value, or undefined when unset.
 * @throws Error when the value does not match the expected systemd syntax.
 */
function parseLimit(name: string, value: string | undefined, pattern: RegExp): string | undefined {
  if (value === undefined || value.trim() === '') return undefined
  const trimmed = value.trim()
  if (!pattern.test(trimmed)) {
    throw new Error(`${name} must match ${pattern.source}, got ${JSON.stringify(value)}`)
  }
  return trimmed
}

/**
 * Parse and validate the per-plan limit map.
 *
 * Every entry is checked against the same systemd syntax as the global limits,
 * so a typo fails at load instead of at the first tenant spawn.
 * @param raw - JSON object keyed by plan slug.
 * @returns the validated map, empty when unset.
 * @throws Error when the JSON or any value is invalid.
 */
function parsePlanLimits(raw: string | undefined): Record<string, { memoryMax?: string; cpuQuota?: string; tasksMax?: number }> {
  if (raw === undefined || raw.trim() === '') return {}
  let parsed: unknown
  try {
    parsed = JSON.parse(raw)
  } catch {
    throw new Error('DSH_SERVER_LOGIN_PLAN_LIMITS must be valid JSON')
  }
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('DSH_SERVER_LOGIN_PLAN_LIMITS must be a JSON object keyed by plan slug')
  }
  const limits: Record<string, { memoryMax?: string; cpuQuota?: string; tasksMax?: number }> = {}
  for (const [slug, value] of Object.entries(parsed as Record<string, unknown>)) {
    if (!/^[a-z0-9-]{1,32}$/.test(slug)) {
      throw new Error(`DSH_SERVER_LOGIN_PLAN_LIMITS: invalid plan slug ${JSON.stringify(slug)}`)
    }
    if (value === null || typeof value !== 'object' || Array.isArray(value)) {
      throw new Error(`DSH_SERVER_LOGIN_PLAN_LIMITS: ${slug} must be an object`)
    }
    const entry = value as Record<string, unknown>
    const memoryMax = entry.memoryMax === undefined ? undefined : String(entry.memoryMax)
    const cpuQuota = entry.cpuQuota === undefined ? undefined : String(entry.cpuQuota)
    const tasksMax = entry.tasksMax === undefined ? undefined : Number(entry.tasksMax)
    if (memoryMax !== undefined && !MEMORY_MAX_PATTERN.test(memoryMax)) {
      throw new Error(`DSH_SERVER_LOGIN_PLAN_LIMITS: ${slug}.memoryMax must match ${MEMORY_MAX_PATTERN.source}`)
    }
    if (cpuQuota !== undefined && !CPU_QUOTA_PATTERN.test(cpuQuota)) {
      throw new Error(`DSH_SERVER_LOGIN_PLAN_LIMITS: ${slug}.cpuQuota must match ${CPU_QUOTA_PATTERN.source}`)
    }
    if (tasksMax !== undefined && (!Number.isInteger(tasksMax) || tasksMax <= 0)) {
      throw new Error(`DSH_SERVER_LOGIN_PLAN_LIMITS: ${slug}.tasksMax must be a positive integer`)
    }
    limits[slug] = {
      ...(memoryMax === undefined ? {} : { memoryMax }),
      ...(cpuQuota === undefined ? {} : { cpuQuota }),
      ...(tasksMax === undefined ? {} : { tasksMax }),
    }
  }
  return limits
}

/**
 * Validate a positive integer limit.
 * @param name - environment variable name, used in the failure message.
 * @param value - raw configured value.
 * @returns the number, or undefined when unset.
 * @throws Error when the value is not a positive integer.
 */
function parsePositiveInt(name: string, value: string | undefined): number | undefined {
  if (value === undefined || value.trim() === '') return undefined
  const parsed = Number(value)
  if (!Number.isInteger(parsed) || parsed <= 0) {
    throw new Error(`${name} must be a positive integer, got ${JSON.stringify(value)}`)
  }
  return parsed
}
const DEFAULT_DEPLOY_MODE: DeployMode = 'local'
const DEFAULT_K8S_NAMESPACE = 'dsh'
const DEFAULT_K8S_SERVICE_ACCOUNT = 'dsh-orchestrator'
const DEFAULT_IMAGE_PULL_SECRET = 'dsh-acr-pull'
const DEFAULT_MAIN_APP_URL = 'http://127.0.0.1:3080'

function requireSessionSecret(value: string | undefined): string {
  if (value === undefined || value.length < 32) {
    throw new Error('SESSION_SECRET must be set to at least 32 characters')
  }
  return value
}

function requireEnv(name: string): string {
  const value = process.env[name]
  if (value === undefined || value === '') {
    throw new Error(`Missing required environment variable: ${name}`)
  }
  return value
}

/** Load the encryption secret from env, or persist a generated one at
 * `<dataRoot>/secret.key` (0600) so it survives restarts without setup. */
function resolveEncryptionSecret(dataRoot: string): string {
  const fromEnv = process.env.DSH_SERVER_LOGIN_SECRET
  if (fromEnv !== undefined && fromEnv !== '') return fromEnv
  const path = join(dataRoot, 'secret.key')
  try {
    const existing = readFileSync(path, 'utf8').trim()
    if (existing !== '') return existing
  } catch {
    // fall through to generate
  }
  const secret = randomBytes(32).toString('hex')
  mkdirSync(dataRoot, { recursive: true })
  writeFileSync(path, secret, { mode: 0o600 })
  return secret
}

function toBool(value: string | undefined, fallback: boolean): boolean {
  if (value === undefined) return fallback
  return value === 'true' || value === '1'
}

/** Split a comma-separated CIDR list into a trimmed, de-duplicated array. */
function parseCidrs(value: string | undefined): string[] {
  if (value === undefined || value === '') return []
  return [...new Set(value.split(',').map((c) => c.trim()).filter((c) => c !== ''))]
}

/** Parse an isolation-mode value, rejecting anything outside `soft`/`account`
 * so a typo in the env var fails loudly at startup instead of silently
 * falling back to `soft` isolation. */
function toIsolationMode(value: string | undefined): IsolationMode | undefined {
  if (value === undefined) return undefined
  const normalized = value.trim().toLowerCase()
  if (normalized === 'soft' || normalized === 'account') return normalized
  throw new Error(`invalid isolation mode "${value}" (expected "soft" or "account")`)
}

/** Parse a deploy-mode value, rejecting anything outside `local`/`k8s`. */
function toDeployMode(value: string | undefined): DeployMode | undefined {
  if (value === undefined) return undefined
  const normalized = value.trim().toLowerCase()
  if (normalized === 'local' || normalized === 'k8s') return normalized
  throw new Error(`invalid deploy mode "${value}" (expected "local" or "k8s")`)
}

/**
 * Fold argv/env overrides over defaults. `dataRoot` defaults to
 * `~/.dsh-server-login` (always writable for dev); production sets
 * `DSH_SERVER_LOGIN_DATA_ROOT=/var/lib/dsh-server-login`.
 */
export function resolveConfig(overrides: ConfigOverrides = {}): ServerConfig {
  const dataRoot =
    overrides.dataRoot ?? process.env.DSH_SERVER_LOGIN_DATA_ROOT ?? join(homedir(), '.dsh-server-login')
  const port = overrides.port ?? process.env.DSH_SERVER_LOGIN_PORT ?? DEFAULT_PORT
  const dshBin = process.env.DSH_SERVER_LOGIN_DSH_BIN
  const isolationMode =
    toIsolationMode(overrides.isolationMode) ??
    toIsolationMode(process.env.DSH_SERVER_LOGIN_ISOLATION_MODE) ??
    DEFAULT_ISOLATION_MODE
  const deployMode =
    toDeployMode(overrides.deployMode) ??
    toDeployMode(process.env.DSH_SERVER_LOGIN_DEPLOY_MODE) ??
    DEFAULT_DEPLOY_MODE
  return {
    host: overrides.host ?? DEFAULT_HOST,
    port: typeof port === 'number' ? port : Number(port),
    dbPath: overrides.dbPath ?? join(dataRoot, 'server-login.db'),
    dbUrl: overrides.dbUrl ?? process.env.DSH_SERVER_LOGIN_DB_URL,
    dataRoot,
    dshCommand: overrides.dshCommand ?? (dshBin !== undefined ? [dshBin] : DEFAULT_DSH_COMMAND),
    logLevel: overrides.logLevel ?? DEFAULT_LOG_LEVEL,
    secureCookies:
      overrides.secureCookies ?? toBool(process.env.DSH_SERVER_LOGIN_SECURE_COOKIES, false),
    sessionTtlSeconds: Number(
      overrides.sessionTtlSeconds ?? process.env.DSH_SERVER_LOGIN_SESSION_TTL ?? DEFAULT_SESSION_TTL_SECONDS,
    ),
    maxUploadBytes: Number(
      overrides.maxUploadBytes ?? process.env.DSH_SERVER_LOGIN_MAX_UPLOAD ?? DEFAULT_MAX_UPLOAD_BYTES,
    ),
    restartBackoffMs: Number(
      overrides.restartBackoffMs ?? process.env.DSH_SERVER_LOGIN_RESTART_BACKOFF ?? DEFAULT_RESTART_BACKOFF_MS,
    ),
    isolationMode,
    spawnAsUserCommand: overrides.spawnAsUserCommand ?? DEFAULT_SPAWN_AS_USER_COMMAND,
    baseUid: Number(overrides.baseUid ?? process.env.DSH_SERVER_LOGIN_BASE_UID ?? DEFAULT_BASE_UID),
    baseDomain: overrides.baseDomain ?? process.env.DSH_SERVER_LOGIN_BASE_DOMAIN ?? DEFAULT_BASE_DOMAIN,
    cookieDomain: overrides.cookieDomain ?? process.env.DSH_SERVER_LOGIN_COOKIE_DOMAIN ?? DEFAULT_COOKIE_DOMAIN,
    enablePatch: overrides.enablePatch ?? toBool(process.env.DSH_SERVER_LOGIN_ENABLE_PATCH, DEFAULT_ENABLE_PATCH),
    identityPublicKey: '',
    portGuard: overrides.portGuard ?? toBool(process.env.DSH_SERVER_LOGIN_PORT_GUARD, true),
    memoryMax: parseLimit('DSH_SERVER_LOGIN_MEMORY_MAX', process.env.DSH_SERVER_LOGIN_MEMORY_MAX, MEMORY_MAX_PATTERN),
    cpuQuota: parseLimit('DSH_SERVER_LOGIN_CPU_QUOTA', process.env.DSH_SERVER_LOGIN_CPU_QUOTA, CPU_QUOTA_PATTERN),
    tasksMax: parsePositiveInt('DSH_SERVER_LOGIN_TASKS_MAX', process.env.DSH_SERVER_LOGIN_TASKS_MAX),
    resourceScopes: toBool(process.env.DSH_SERVER_LOGIN_RESOURCE_SCOPES, false),
    planLimits: parsePlanLimits(process.env.DSH_SERVER_LOGIN_PLAN_LIMITS),
    encryptionSecret:
      overrides.encryptionSecret ?? resolveEncryptionSecret(dataRoot),
    deployMode,
    k8sNamespace: overrides.k8sNamespace ?? process.env.DSH_SERVER_LOGIN_NAMESPACE ?? DEFAULT_K8S_NAMESPACE,
    dshImage: overrides.dshImage ?? process.env.DSH_SERVER_LOGIN_DSH_IMAGE ?? '',
    controlPlaneImage:
      overrides.controlPlaneImage ?? process.env.DSH_SERVER_LOGIN_CONTROL_PLANE_IMAGE ?? '',
    imagePullSecret:
      overrides.imagePullSecret ?? process.env.DSH_SERVER_LOGIN_IMAGE_PULL_SECRET ?? DEFAULT_IMAGE_PULL_SECRET,
    egressCidrs: overrides.egressCidrs ?? parseCidrs(process.env.DSH_SERVER_LOGIN_EGRESS_CIDRS),
    k8sServiceAccount:
      overrides.k8sServiceAccount ?? process.env.DSH_SERVER_LOGIN_K8S_SERVICE_ACCOUNT ?? DEFAULT_K8S_SERVICE_ACCOUNT,
    podName: overrides.podName ?? process.env.POD_NAME ?? hostname(),
    supabaseUrl: overrides.supabaseUrl ?? requireEnv('DSH_SERVER_LOGIN_SUPABASE_URL'),
    supabaseAnonKey: overrides.supabaseAnonKey ?? requireEnv('DSH_SERVER_LOGIN_SUPABASE_ANON_KEY'),
    sessionSecret: overrides.sessionSecret ?? requireSessionSecret(process.env.SESSION_SECRET),
    mainAppUrl:
      overrides.mainAppUrl ?? process.env.DSH_SERVER_LOGIN_MAIN_APP_URL ?? DEFAULT_MAIN_APP_URL,
  }
}

/**
 * Refuse a configuration that would run tenants without OS-level separation.
 *
 * `soft` isolation runs every tenant DSH under the orchestrator's own uid, and
 * an unguarded loopback port lets a tenant reach another tenant's process.
 * Both are only defensible in a development box, so production mode rejects
 * them at load instead of silently deploying a shared-uid fleet.
 *
 * @param config - the resolved configuration.
 * @throws Error when production is configured with `soft` isolation or without the port guard.
 */
export function assertProductionIsolation(config: ServerConfig): void {
  const production = process.env.NODE_ENV?.trim().toLowerCase() === 'production'
  if (!production) return
  if (config.isolationMode !== 'account') {
    throw new Error(
      `NODE_ENV=production refuses DSH_SERVER_LOGIN_ISOLATION_MODE=${config.isolationMode}: every tenant would share one uid`,
    )
  }
  if (config.portGuard !== true) {
    throw new Error(
      'NODE_ENV=production refuses DSH_SERVER_LOGIN_PORT_GUARD=false: tenants could reach each other\'s loopback ports',
    )
  }
}
