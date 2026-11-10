/**
 * Per-user DSH supervisor: a resident main DSH plus an **on-demand** watchdog.
 *
 * The watchdog is not spawned at launch; it is pulled up once when the main
 * crashes (to repair) or when a post-restart command must be executed. This
 * keeps the steady-state footprint at one process per active user while still
 * providing crash repair + command handoff. The watchdog's agent-level
 * repair/session-resume is harness-internal and deferred to real-harness
 * integration (see docs/blueprint.md §4).
 * @module dsh-server-login/supervisor/orchestrator
 */

import { spawn, execFile, type ChildProcess, type StdioOptions } from 'node:child_process'
import { execFileSync } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import { chmodSync, chownSync, existsSync, mkdirSync, readdirSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import type { ServerConfig } from '../config.js'
import type { User } from '../db/types.js'
import {
  DEFAULT_SANDBOX_DATA_DIR,
  grantUserRootPermissions,
  grantUserSandboxPermissions,
  handoffPath,
  homeRoot,
  userRoot,
  workspaceRoot,
} from '../fs/workspace.js'
import { createPortGuard, type PortGuard } from './firewall.js'
import { findFreePort, scrubEnv, sanitizePath, resolveBinary } from './spawn.js'
import {
  AlreadyRunningError,
  ProvisioningConflict,
  ProvisioningError,
  type Endpoint,
  type Instance,
  type InstanceRole,
  type InstanceStatus,
  type Spawner,
  type TenantState,
  type UserStatus,
} from './spawner.js'

// Re-exported so existing importers (routes) keep resolving from this module.
export { AlreadyRunningError, type Instance, type InstanceRole, type InstanceStatus, type UserStatus }

/** Task given to the one-shot headless watchdog so it doesn't error on a
 * missing task; executes any post-restart command from the handoff path. */
const WATCHDOG_TASK = 'Read DSH_SERVER_LOGIN_HANDOFF_PATH. If it contains a JSON {"command": ...}, run that command. Then exit.'

/** Cgroup directory the transient user scopes live in. */
const SCOPE_CGROUP_ROOT = '/sys/fs/cgroup/system.slice'

/**
 * Stable prefix of every transient scope a tenant role owns.
 * @param userId - tenant the scope belongs to.
 * @param role - main or watchdog.
 * @returns the systemd-safe stem, without the unique launch suffix or `.scope`.
 */
export function tenantScopeStem(userId: string, role: InstanceRole): string {
  const safe = userId.replace(/[^A-Za-z0-9_.-]/g, '-').slice(0, 48)
  return `copymonster-${role}-${safe}`
}

/**
 * Scope units left behind by an earlier launch of the same tenant role.
 *
 * Both the retired unsuffixed name and every uniquely suffixed successor match,
 * so a restarted orchestrator can release a scope it no longer has in memory
 * before `systemd-run` refuses the reused unit name.
 * @param entries - cgroup directory entries.
 * @param stem - prefix from {@link tenantScopeStem}.
 * @returns the matching unit names.
 */
export function staleScopeUnits(entries: readonly string[], stem: string): string[] {
  return entries.filter(entry => entry.endsWith('.scope')
    && (entry === `${stem}.scope` || entry.startsWith(`${stem}-`)))
}

/**
 * Local backend: owns the lifecycle of per-user DSH process pairs via
 * child_process. State is in-memory. Implements {@link Spawner}.
 */
/**
 * Stable reason text for a failed spawn, kept free of paths and personal data.
 * @param error - the thrown failure.
 * @returns the error name plus its first line.
 */
function describeSpawnFailure(error: unknown): string {
  if (error instanceof ProvisioningConflict) return `${error.name}:${error.mismatch}`
  if (error instanceof ProvisioningError) return error.name
  const name = error instanceof Error ? error.name : 'Error'
  const line = error instanceof Error ? error.message.split('\n')[0] ?? '' : String(error)
  return line === '' ? name : `${name}: ${line.slice(0, 200)}`
}

export class LocalSpawner implements Spawner {
  private readonly mains = new Map<string, Instance>()
  private readonly watchdogs = new Map<string, Instance>()
  /** Tenants with a spawn in flight, so a failed spawn never looks running. */
  private readonly starting = new Set<string>()
  /** Last failure per tenant, cleared by a successful launch. */
  private readonly failures = new Map<string, string>()
  private readonly children = new Map<string, ChildProcess>()
  private readonly restartTimers = new Map<string, NodeJS.Timeout>()
  private readonly activeWsSockets = new Map<string, Set<any>>()
  private readonly idleTimers = new Map<string, NodeJS.Timeout>()
  private readonly IDLE_TIMEOUT_MS = 30 * 60 * 1000 // 30 minutes idle timeout

  private readonly portGuard: PortGuard | undefined

  constructor(
    private readonly config: ServerConfig,
    /** Resolve the user's own API key (decrypted); null = user has none. */
    private readonly resolveApiKey: (userId: string) => Promise<string | null>,
    /** Resolve the user's assigned Linux uid (falls back to hash when unset). */
    private readonly resolveUid: (userId: string) => Promise<number>,
    /** Database adapter: usernames for Linux provisioning, plan limits for scopes. */
    private readonly db: { findUserById(id: string): Promise<User | undefined> },
  ) {
    this.portGuard = createPortGuard(config.portGuard)
    // In-memory state does not survive a restart, so scopes started by the
    // previous process are orphans that would collide with the next launch.
    this.reapOrphanScopes()
  }

  /**
   * Ensure the Linux user/group for the tenant's UID exists (idempotent).
   *
   * Resolves the account by name *and* by uid before touching anything: when
   * either exists with a value that does not match the database, the tenant's
   * files and processes belong to another identity, and creating or reusing the
   * account would hand one tenant another tenant's home. That case throws a
   * {@link ProvisioningConflict} instead of continuing.
   */
  private async provisionLinuxUser(userId: string): Promise<void> {
    const uid = await this.resolveUid(userId)
    const user = await this.db.findUserById(userId)
    const username = user?.username ?? `user-${uid}`

    const byName = this.accountId('-u', username)
    const byUid = this.accountName(uid)

    if (byName !== undefined && byName !== uid) {
      throw new ProvisioningConflict(userId, 'uid', byName, uid)
    }
    if (byUid !== undefined && byUid !== username) {
      throw new ProvisioningConflict(userId, 'name', byUid, username)
    }
    if (byName === uid && byUid === username) {
      await this.assertGroup(uid, username)
      return
    }

    // Group first, and only when both its id and its name are free.
    const groupName = this.groupName(uid)
    if (groupName === undefined) {
      try {
        execFileSync('groupadd', ['-g', String(uid), username], { stdio: 'ignore' })
      } catch (error: unknown) {
        const detail = error instanceof Error ? error.message : String(error)
        throw new ProvisioningError(userId, `groupadd failed for gid ${uid}: ${detail}`)
      }
    } else if (groupName !== username && byName === undefined) {
      // The gid belongs to an unrelated group; sharing it would put the tenant
      // in that group.
      throw new ProvisioningConflict(userId, 'gid', groupName, username)
    }

    if (byName === undefined) {
      try {
        execFileSync('useradd', [
          '-u', String(uid),
          '-g', String(uid),
          '-d', userRoot(this.config.dataRoot, userId),
          '-M',
          '-s', '/bin/bash',
          username
        ], { stdio: 'ignore' })
      } catch (error: unknown) {
        // A concurrent spawn may have won the race; accept only a verified match.
        const retryName = this.accountId('-u', username)
        const retryUid = this.accountName(uid)
        if (retryName !== uid || retryUid !== username) {
          const detail = error instanceof Error ? error.message : String(error)
          throw new ProvisioningError(userId, `useradd failed for uid ${uid} (${username}): ${detail}`)
        }
      }
    }

    await this.assertGroup(uid, username)
    const actualUid = this.accountId('-u', username)
    if (actualUid !== uid) {
      throw new ProvisioningConflict(userId, 'uid', actualUid, uid)
    }
  }

  /** Gid an existing group name resolves to, or undefined when absent. */
  private groupName(gid: number): string | undefined {
    try {
      const name = String(execFileSync('getent', ['group', String(gid)], { stdio: 'pipe' })).trim().split(':')[0]
      return name === undefined || name === '' ? undefined : name
    } catch {
      return undefined
    }
  }

  /** Verify the tenant's primary group is its own gid. */
  private async assertGroup(uid: number, username: string): Promise<void> {
    try {
      const line = String(execFileSync('getent', ['group', username], { stdio: 'pipe' })).trim()
      const gid = Number(line.split(':')[2])
      if (gid !== uid) throw new ProvisioningConflict(username, 'gid', String(gid), String(uid))
    } catch (error: unknown) {
      if (error instanceof ProvisioningConflict) throw error
      throw new ProvisioningError(username, `group ${username} is missing for gid ${uid}`)
    }
  }

  /** Uid recorded for a local account name, or undefined when absent. */
  private accountId(idFlag: string, name: string): number | undefined {
    try {
      const value = Number(String(execFileSync('id', [idFlag, name], { stdio: 'pipe' })).trim())
      return Number.isFinite(value) ? value : undefined
    } catch {
      return undefined
    }
  }

  /** Account name owning a local uid, or undefined when the uid is free. */
  private accountName(uid: number): string | undefined {
    try {
      const value = String(execFileSync('getent', ['passwd', String(uid)], { stdio: 'pipe' })).trim()
      const name = value.split(':')[0]
      return name === undefined || name === '' ? undefined : name
    } catch {
      return undefined
    }
  }

  /** Current main + watchdog for a user. */
  async status(userId: string): Promise<UserStatus> {
    return { main: this.mains.get(userId), watchdog: this.watchdogs.get(userId) }
  }

  /**
   * Lifecycle state of a tenant's instance, for `GET /api/dsh/status`.
   *
   * Distinct from {@link endpointFor}: `starting` means a spawn is in flight,
   * `failed` means the last spawn or provisioning attempt was refused, and
   * `stopped` means nothing ran. The proxy needs the difference to decide
   * between "wait", "report an error", and "launch".
   */
  async lifecycle(userId: string): Promise<{ state: TenantState; lastError?: string }> {
    if (this.starting.has(userId)) return { state: 'starting' }
    const failure = this.failures.get(userId)
    if (failure !== undefined) return { state: 'failed', lastError: failure }
    const instance = this.mains.get(userId)
    if (instance === undefined) return { state: 'stopped' }
    return { state: instance.status === 'running' ? 'running' : 'starting' }
  }

  /** Last recorded failure for a tenant, or undefined after a clean launch. */
  lastErrorFor(userId: string): string | undefined {
    return this.failures.get(userId)
  }

  /**
   * Provision the tenant's Linux account without spawning anything.
   *
   * The SSO exchange calls this so a uid conflict fails the login instead of
   * leaving the browser on the launching page.
   * @param userId - tenant whose account must exist.
   * @throws ProvisioningConflict when the host account disagrees with the database.
   * @throws ProvisioningError when `groupadd`/`useradd` fail for another reason.
   */
  async ensureLinuxAccount(userId: string): Promise<void> {
    if (this.config.isolationMode !== 'account') return
    await this.provisionLinuxUser(userId)
  }

  /** Spawn the resident main DSH for a user (watchdog is pulled up on demand). */
  async launch(userId: string, folder: string, patch?: string): Promise<Instance> {
    if (this.mains.has(userId)) throw new AlreadyRunningError(userId)
    // A spawn already in flight owns this tenant; a second caller waits for the
    // same attempt instead of racing it.
    if (this.starting.has(userId)) throw new AlreadyRunningError(userId)
    const inst = await this.spawnInstance(userId, 'main', folder, patch)
    this.scheduleIdleShutdown(userId)
    return inst
  }

  /** Stop the current main (clean) and respawn it with the same folder/patch. */
  async restartMain(userId: string): Promise<Instance | undefined> {
    const current = this.mains.get(userId)
    if (current === undefined) return undefined
    this.killInstance(userId, current)
    return await this.spawnInstance(userId, 'main', current.folder, current.patch)
  }

  /** Spawn a one-shot watchdog for the user's current main (repair / execute). */
  async spawnWatchdog(userId: string): Promise<Instance | undefined> {
    if (!this.config.enablePatch) return undefined // watchdog needs the runtime patch
    if (this.watchdogs.has(userId)) return this.watchdogs.get(userId)
    const main = this.mains.get(userId)
    if (main === undefined) return undefined
    return await this.spawnInstance(userId, 'watchdog', main.folder, main.patch)
  }

  /** Endpoint the proxy forwards to (local → the running main's loopback port). */
  async endpointFor(userId: string): Promise<Endpoint | undefined> {
    const instance = this.mains.get(userId)
    if (instance === undefined || instance.status !== 'running' || instance.port === undefined) return undefined
    return { host: '127.0.0.1', port: instance.port }
  }

  /** Stop both processes for a user (cancelling any pending restart). */
  async stop(userId: string): Promise<void> {
    const timer = this.restartTimers.get(userId)
    if (timer !== undefined) {
      clearTimeout(timer)
      this.restartTimers.delete(userId)
    }
    const main = this.mains.get(userId)
    const watchdog = this.watchdogs.get(userId)
    if (main !== undefined) this.killInstance(userId, main)
    if (watchdog !== undefined) this.killInstance(userId, watchdog)
    this.mains.delete(userId)
    this.watchdogs.delete(userId)
    this.touchActivity(userId)
    this.activeWsSockets.delete(userId)
  }

  touchActivity(userId: string): void {
    const timer = this.idleTimers.get(userId)
    if (timer !== undefined) {
      clearTimeout(timer)
      this.idleTimers.delete(userId)
    }
  }

  registerWebSocket(userId: string, socket: any): void {
    this.touchActivity(userId)
    let set = this.activeWsSockets.get(userId)
    if (!set) {
      set = new Set()
      this.activeWsSockets.set(userId, set)
    }
    set.add(socket)

    const cleanup = () => {
      set?.delete(socket)
      if ((set?.size ?? 0) === 0) {
        this.scheduleIdleShutdown(userId)
      }
    }
    socket.once('close', cleanup)
    socket.once('end', cleanup)
    socket.once('error', cleanup)
  }

  private scheduleIdleShutdown(userId: string): void {
    this.touchActivity(userId)
    const timer = setTimeout(async () => {
      const activeCount = this.activeWsSockets.get(userId)?.size ?? 0
      if (activeCount === 0 && this.mains.has(userId)) {
        await this.stop(userId).catch(() => {})
      }
    }, this.IDLE_TIMEOUT_MS)
    this.idleTimers.set(userId, timer)
  }

  /** Stop every tracked process on shutdown. */
  async teardown(): Promise<void> {
    for (const userId of [...this.mains.keys(), ...this.watchdogs.keys()]) await this.stop(userId)
    this.reapOrphanScopes()
  }

  /**
   * Empty every tenant scope still alive, including ones this process did not
   * spawn.
   *
   * A scope is a sibling of the service, not a child, so systemd's stop does
   * not reach it. A tenant left over from a previous run keeps its proxied
   * connections open, and `app.close()` then waits out the full stop timeout.
   * @returns nothing; failures are ignored so shutdown always proceeds.
   */
  private reapOrphanScopes(): void {
    if (!this.config.resourceScopes) return
    let entries: string[]
    try {
      entries = readdirSync(SCOPE_CGROUP_ROOT)
    } catch {
      return
    }
    for (const entry of entries) {
      if (!entry.startsWith('copymonster-') || !entry.endsWith('.scope')) continue
      for (const root of [SCOPE_CGROUP_ROOT, '/sys/fs/cgroup']) {
        try {
          writeFileSync(join(root, entry, 'cgroup.kill'), '1')
          break
        } catch {}
      }
    }
  }

  /** No-op: local mode has no sidecar — the control plane owns the volume. */
  async ensureFileService(_userId: string): Promise<void> {}

  private handoffPath(userId: string): string {
    return handoffPath(userRoot(this.config.dataRoot, userId))
  }

  /** Materialize the rendered patch so the dsh CLI can `--patch <file>` it.
   * Per role, so a watchdog spawning alongside its main never races the file. */
  private writePatch(userId: string, role: InstanceRole, patch: string): string {
    const dir = join(userRoot(this.config.dataRoot, userId), 'patches')
    mkdirSync(dir, { recursive: true, mode: 0o755 })
    const path = join(dir, `${role}.yml`)
    writeFileSync(path, patch, { mode: 0o644 })
    if (this.config.isolationMode === 'account' && typeof process.getuid === 'function' && process.getuid() === 0) {
      void this.resolveUid(userId).then((uid) => {
        try {
          chownSync(dir, uid, uid)
          chownSync(path, uid, uid)
        } catch {}
      }).catch(() => {})
    }
    return path
  }

  private async baseEnv(userId: string): Promise<Record<string, string>> {
    const root = userRoot(this.config.dataRoot, userId)
    const home = homeRoot(root)
    const workspace = workspaceRoot(root)
    const apiKey = await this.resolveApiKey(userId)
    const scrubbed = scrubEnv(process.env)
    return {
      ...scrubbed,
      PATH: sanitizePath(scrubbed.PATH ?? process.env.PATH),
      // HOME drives the child's directory picker default (homedir()); point it
      // at the user's workspace so their folders show, not DSH's internal home.
      HOME: workspace,
      // DSH's own state (profiles/sessions/credentials) stays in `home`.
      DSH_HOME: home,
      // Public half of the control plane's identity key: the tenant verifies
      // the signed caller identity but cannot mint one.
      ...(this.config.identityPublicKey === ''
        ? {}
        : { DSH_IDENTITY_PUBLIC_KEY: this.config.identityPublicKey }),
      // Each user's own key; omit entirely when unset so the harness reports
      // "no key" instead of a header-hostile value.
      ...(apiKey !== null ? { DEEPSEEK_API_KEY: apiKey } : {}),
    }
  }

  private async spawnInstance(userId: string, role: InstanceRole, folder: string, patch?: string): Promise<Instance> {
    const isMain = role === 'main'
    const port = isMain ? await findFreePort() : undefined
    const instance: Instance = {
      id: randomUUID(),
      userId,
      role,
      folder,
      port,
      status: 'starting',
      patch,
    }
    const map = role === 'main' ? this.mains : this.watchdogs
    // Registered before the spawn so a concurrent caller sees the attempt, but
    // removed again on failure: a rejected spawn must never leave an entry that
    // makes every later launch throw AlreadyRunningError.
    if (isMain) {
      this.starting.add(userId)
      this.failures.delete(userId)
    }

    const [command = 'dsh', ...args] = this.config.dshCommand
    const launchArgs = ['--profile', role === 'main' ? 'web' : 'headless']
    // --patch is a launcher flag and must precede any app/inner args (--host/--port
    // for web, the task string for headless): dsh forwards the first unrecognized
    // token onward, so a trailing --patch reaches the app as an unknown option.
    // Off by default so the child boots even on older dsh versions.
    if (this.config.enablePatch && patch !== undefined) {
      launchArgs.push('--patch', this.writePatch(userId, role, patch))
    }
    if (role === 'main') {
      launchArgs.push('--host', '127.0.0.1', '--port', String(port))
    } else {
      launchArgs.push(WATCHDOG_TASK)
    }

    const env: Record<string, string> = {
      ...(await this.baseEnv(userId)),
      DSH_SERVER_LOGIN_ROLE: role,
      DSH_SERVER_LOGIN_BASE_DOMAIN: this.config.baseDomain,
      DSH_SERVER_LOGIN_HANDOFF_PATH: this.handoffPath(userId), // both roles: main writes, watchdog reads
    }
    if (isMain) {
      env.DSH_SERVER_LOGIN_PORT = String(port)
    }

    try {
      const child = await this.spawnAsUser(userId, role, command, [...args, ...launchArgs], { cwd: folder, env })
      instance.scopeUnit = child.scopeUnit
      this.trackChild(userId, instance, child.child)
      map.set(userId, instance)
      return instance
    } catch (error: unknown) {
      if (isMain) {
        this.starting.delete(userId)
        this.failures.set(userId, describeSpawnFailure(error))
      }
      throw error
    } finally {
      if (isMain) this.starting.delete(userId)
    }
  }

  /** Spawn the child, optionally through the account-level setuid wrapper.
   * @returns the child and, when resource scopes are active, the unit holding it.
   */
  private async spawnAsUser(
    userId: string,
    role: InstanceRole,
    command: string,
    args: string[],
    options: { cwd: string; env: Record<string, string> },
  ): Promise<{ child: ChildProcess; scopeUnit?: string }> {
    const stdio: StdioOptions = ['ignore', 'pipe', 'pipe']
    const env = {
      ...options.env,
      PATH: sanitizePath(options.env.PATH ?? process.env.PATH),
    }
    const resolvedOptions = { ...options, env, stdio }

    // Ensure working directory exists before spawning
    if (resolvedOptions.cwd) {
      mkdirSync(resolvedOptions.cwd, { recursive: true, mode: 0o755 })
    }

    if (this.config.isolationMode !== 'account') {
      const resolvedCommand = resolveBinary(command, env.PATH)
      return { child: spawn(resolvedCommand, args, resolvedOptions) }
    }
    // Ensure the Linux user exists before attempting setpriv
    await this.provisionLinuxUser(userId)
    const uid = await this.resolveUid(userId)
    if (typeof process.getuid === 'function' && process.getuid() === 0) {
      try {
        const root = userRoot(this.config.dataRoot, userId)
        // The recursive grant widens the whole tree, so it runs first and the
        // restrictive modes come after it; the reverse order reopened the
        // owner-only directories on every spawn.
        grantUserRootPermissions(root, uid)
        // The Workspace sandbox sits outside this per-user root, so it needs
        // its own handover: a directory the control plane created as root
        // refuses the tenant's `mkdir` and every Workspace pick fails EACCES.
        grantUserSandboxPermissions(
          process.env.COPYMONSTER_DATA_DIR ?? DEFAULT_SANDBOX_DATA_DIR,
          userId,
          uid,
        )
        // Traversal without listing for the shared parents: a tenant uid must
        // reach its own root, and must not enumerate the other tenants. The
        // per-user root, its home and its workspace stay owner-only.
        chmodSync(this.config.dataRoot, 0o711)
        chmodSync(join(this.config.dataRoot, 'users'), 0o711)
        chmodSync(root, 0o700)
        chmodSync(homeRoot(root), 0o700)
        chmodSync(workspaceRoot(root), 0o700)
      } catch (error) {
        // A permission failure here leaves the tenant unable to read its own
        // root, which surfaces later as an opaque EACCES inside the child.
        const detail = error instanceof Error ? error.message : String(error)
        console.warn(`[provisioning] prepare tenant root failed for ${userId}: ${detail}`)
      }
    }
    const resolvedCommand = resolveBinary(command, env.PATH)
    const prefix = this.config.spawnAsUserCommand.map((part) =>
      part.replaceAll('{UID}', String(uid)).replaceAll('{GID}', String(uid)),
    )
    let [asCommand = 'setpriv', ...asArgs] = prefix
    asCommand = resolveBinary(asCommand, env.PATH)

    // A configured resource limit wraps the whole privilege-drop in a transient
    // systemd scope. The scope runs as the orchestrator's own user: systemd
    // cannot set `SupplementaryGroups` on a scope unit, and inheriting the
    // caller's groups would leave the tenant inside group root, which both
    // denies it /root and hands it group-root access.
    const scope = await this.prepareResourceScope(userId, role)
    if (scope !== undefined) {
      const runner = resolveBinary('systemd-run', env.PATH)
      return {
        child: spawn(runner, [...scope.args, asCommand, ...asArgs, resolvedCommand, ...args], resolvedOptions),
        scopeUnit: scope.unit,
      }
    }

    return { child: spawn(asCommand, [...asArgs, resolvedCommand, ...args], resolvedOptions) }
  }

  /**
   * Release any scope a previous launch left under this tenant role, then build
   * a uniquely named `systemd-run --scope` prefix for the new one.
   *
   * The unit name is derived from the tenant and role, so a restart or a crash
   * recovery that races the previous teardown made `systemd-run` fail with
   * "unit is already loaded". Releasing the stale unit first and appending a
   * launch token keeps the reused name from colliding either way.
   *
   * The plan-derived values stored on the user row win; the global config is
   * the fallback for a tenant whose plan is unknown. Only the limits are set
   * here: the caller composes this prefix with the setpriv prefix, so the
   * scope never changes the child's identity or groups. `--collect` removes
   * the transient unit when the child exits.
   * @param userId - the tenant whose stored plan limits apply.
   * @param role - main or watchdog, so a restart never collides with a live scope.
   * @returns the unit name and argv prefix, or undefined when no limit is configured.
   */
  private async prepareResourceScope(
    userId: string,
    role: InstanceRole,
  ): Promise<{ unit: string; args: string[] } | undefined> {
    if (!this.config.resourceScopes) return undefined
    const user = await this.db.findUserById(userId)
    const memoryMax = user?.memory_max ?? this.config.memoryMax
    const cpuQuota = user?.cpu_quota ?? this.config.cpuQuota
    const tasksMax = user?.tasks_max ?? this.config.tasksMax
    if (memoryMax == null && cpuQuota == null && tasksMax == null) return undefined
    const stem = tenantScopeStem(userId, role)
    await this.releaseStaleScopes(stem)
    const unit = `${stem}-${randomUUID().replaceAll('-', '').slice(0, 12)}.scope`
    const args = ['--scope', '--quiet', '--collect', `--unit=${unit}`]
    if (memoryMax !== undefined) args.push('-p', `MemoryMax=${memoryMax}`)
    if (cpuQuota !== undefined) args.push('-p', `CPUQuota=${cpuQuota}`)
    if (tasksMax !== undefined) args.push('-p', `TasksMax=${tasksMax}`)
    args.push('--')
    return { unit, args }
  }

  /**
   * Kill and stop every leftover scope for a tenant role and wait for the unit
   * to unload, so the next `systemd-run` can claim the name.
   * @param stem - stable prefix from {@link tenantScopeStem}.
   */
  private async releaseStaleScopes(stem: string): Promise<void> {
    let entries: string[]
    try {
      entries = readdirSync(SCOPE_CGROUP_ROOT)
    } catch {
      return
    }
    const stale = staleScopeUnits(entries, stem)
    if (stale.length === 0) return
    await Promise.all(stale.map(unit => this.stopScopeUnit(unit)))
    console.warn(`[supervisor] released stale scope(s) ${stale.join(', ')}`)
  }

  /**
   * Empty one scope synchronously through its cgroup, then let systemd collect
   * the transient unit.
   * @param unit - scope unit name.
   * @returns a promise settled when `systemctl stop` returns.
   */
  private stopScopeUnit(unit: string): Promise<void> {
    for (const root of [SCOPE_CGROUP_ROOT, '/sys/fs/cgroup']) {
      try {
        writeFileSync(join(root, unit, 'cgroup.kill'), '1')
        break
      } catch {}
    }
    return new Promise((resolve) => {
      execFile('systemctl', ['--user', 'stop', unit], { timeout: 10_000 }, () => { resolve() })
    })
  }

  private trackChild(userId: string, instance: Instance, child: ChildProcess): void {
    this.children.set(instance.id, child)
    child.on('spawn', () => {
      instance.status = 'running'
      instance.pid = child.pid ?? undefined
      if (instance.role === 'main' && instance.port !== undefined && this.portGuard !== undefined) {
        try {
          this.portGuard.install(instance.port)
        } catch (error) {
          // Fail closed: without the port guard a co-tenant could reach this
          // DSH's loopback RPC directly. Kill the just-spawned child and mark
          // the instance crashed rather than serve unguarded.
          instance.status = 'crashed'
          instance.lastError = error instanceof Error ? error.message : String(error)
          child.kill('SIGKILL')
        }
      }
    })
    child.stdout?.pipe(process.stdout)
    let stderrTail = ''
    child.stderr?.on('data', (chunk: Buffer) => {
      stderrTail = (stderrTail + chunk.toString()).slice(-2048)
      // Also surface the child's stderr on the orchestrator's own stderr so a
      // boot crash is visible in journald instead of only in lastError.
      process.stderr.write(`[dsh-child ${instance.role}] ${chunk.toString()}`)
    })
    child.on('error', (err) => {
      instance.status = 'crashed'
      instance.lastError = err.message
      this.children.delete(instance.id)
      process.stderr.write(`[dsh-child ${instance.role}] spawn error: ${err.message}\n`)
    })
    child.on('exit', (code) => {
      instance.exitCode = code ?? undefined
      this.children.delete(instance.id)
      // Release the loopback port guard as soon as the main's process is gone
      // (explicit stop, restart, and crash all funnel through this handler).
      if (instance.role === 'main' && instance.port !== undefined) {
        this.portGuard?.remove(instance.port)
      }
      const map = instance.role === 'main' ? this.mains : this.watchdogs
      // Only act if this instance is still the current one (avoid a stale
      // exit handler touching a freshly restarted instance).
      if (map.get(userId)?.id !== instance.id) return
      if (instance.status === 'stopped') {
        map.delete(userId)
        return
      }
      // A one-shot watchdog that finished cleanly is not restarted.
      if (instance.role === 'watchdog' && code === 0) {
        instance.status = 'stopped'
        map.delete(userId)
        return
      }
      instance.status = 'crashed'
      instance.lastError = stderrTail.slice(-500) || undefined
      if (instance.role === 'main') {
        void this.spawnWatchdog(userId)
        this.scheduleRestart(userId, instance)
      } else {
        map.delete(userId)
      }
    })
  }

  private scheduleRestart(userId: string, instance: Instance): void {
    const timer = setTimeout(() => {
      this.restartTimers.delete(userId)
      void this.spawnInstance(userId, instance.role, instance.folder, instance.patch)
    }, this.config.restartBackoffMs)
    timer.unref()
    this.restartTimers.set(userId, timer)
  }

  private killInstance(userId: string, instance: Instance): void {
    instance.status = 'stopped'
    // With resource scopes the tenant lives inside a transient unit, and
    // killing the `systemd-run` wrapper does not end it. `cgroup.kill` empties
    // the delegated subtree synchronously; `systemctl stop` would block here
    // because systemd is already stopping this service.
    if (instance.scopeUnit !== undefined) {
      let killed = false
      for (const dir of [`${SCOPE_CGROUP_ROOT}/${instance.scopeUnit}`, `/sys/fs/cgroup/${instance.scopeUnit}`]) {
        try {
          writeFileSync(join(dir, 'cgroup.kill'), '1')
          killed = true
          break
        } catch {}
      }
      if (!killed) {
        try {
          execFileSync('systemctl', ['stop', '--no-block', instance.scopeUnit], { stdio: 'ignore', timeout: 5_000 })
        } catch {}
      }
    }
    const child = this.children.get(instance.id)
    if (child === undefined) return
    child.kill('SIGTERM')
    const killer = setTimeout(() => {
      if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL')
    }, 5000)
    killer.unref()
  }
}
